package vendor

import (
	"fmt"
	"io"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/telechips"
)

// tcc: Telechips, the SoC behind a number of head units (Hyundai/Kia's among
// them, but not only). A platform-level driver like mediatek: the formats are the
// SoC's, whichever OEM's package carries them, so they are recognised here and not
// in an OEM's driver. Only recognition and reports: there is no recovery path.
type tcc struct{}

func init() { Register(tcc{}) }

func (tcc) ID() string                 { return "telechips" }
func (tcc) Platform() string           { return PlatformTelechips }
func (tcc) OEMIDs() []string           { return nil }
func (tcc) CanIngest(path string) bool { return false }

func (tcc) IngestDonor(string) (*blankflash.Donor, error) { return nil, ErrUnsupported }
func (tcc) HarvestStock(TargetSource) (*blankflash.Target, error) {
	return nil, ErrUnsupported
}
func (tcc) Assemble(*blankflash.Donor, *blankflash.Target, AssembleOptions) (*blankflash.ForgeResult, error) {
	return nil, ErrUnsupported
}

// tccArtifact recognises the SoC's boot stages from their first bytes: the signed
// wrapper of the BL stages (BL3 is a U-Boot), and the older LK bootloader.
func tccArtifact(data []byte) (ArtifactInfo, bool) {
	switch {
	case telechips.IsImage(data):
		info := ArtifactInfo{Label: "Telechips boot stage"}
		if im, err := telechips.Header(data); err == nil {
			info.Detail = strings.TrimSpace(im.Name + " " + im.Version)
		}
		return info, true
	case telechips.IsLKROM(data):
		info := ArtifactInfo{Label: "Telechips LK ROM (BL1+EL3+LK, packaged)"}
		if lk, err := telechips.ParseLKROM(data); err == nil {
			info.Detail = fmt.Sprintf("%s, %d components", strings.TrimSpace(lk.VersionTag), len(lk.Entries))
		}
		return info, true
	}
	return ArtifactInfo{}, false
}

// ArtifactReport implements ArtifactReporter: a boot stage's wrapper, build and
// default environment; an LK ROM's component table.
func (tcc) ArtifactReport(path string, head []byte) []string {
	switch {
	case telechips.IsImage(head):
		data, err := infile.ReadFile(path)
		if err != nil {
			return nil
		}
		im, err := telechips.Parse(data)
		if err != nil {
			return nil
		}
		return im.Report()
	case telechips.IsLKROM(head):
		data, err := infile.ReadFile(path)
		if err != nil {
			return nil
		}
		lk, err := telechips.ParseLKROM(data)
		if err != nil {
			return nil
		}
		return lk.Report()
	}
	return nil
}

// lkromChildName is a carve child's name for one of an LK ROM's 9 table
// entries: a slug of its own found tag (e.g. "bl1c_tcc803x") if it has one,
// otherwise its byte range -- always unique, always meaningful even where no
// tag was found.
func lkromChildName(e telechips.LKROMEntry) string {
	if e.Tag != "" {
		var b strings.Builder
		for _, r := range strings.ToLower(e.Tag) {
			switch {
			case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
				b.WriteRune(r)
			case b.Len() > 0 && b.String()[b.Len()-1] != '_':
				b.WriteByte('_')
			}
			if b.Len() >= 16 {
				break
			}
		}
		if s := strings.Trim(b.String(), "_"); s != "" {
			return s + ".bin"
		}
	}
	return fmt.Sprintf("0x%06x-0x%06x.bin", e.Offset, e.Offset+e.Size)
}

// CarveExpanders implements Carver: an LK ROM's 9 table entries as named
// members, so `ls`/`extract` reach BL1/EL3/LK-proper/etc. directly instead
// of needing their byte ranges looked up by hand each time.
func (tcc) CarveExpanders() []carve.Expander {
	return []carve.Expander{{
		Kind:  "lkrom",
		Match: func(_ *carve.Node, head []byte) bool { return telechips.IsLKROM(head) },
		Expand: func(n *carve.Node) ([]*carve.Node, error) {
			ra, err := n.ReaderAt()
			if err != nil {
				return nil, err
			}
			// The table itself (0xb0 bytes) is tiny, but tags can sit up to
			// lkromTagScanWindow into an entry the table hasn't been read
			// yet to locate -- so ParseLKROM needs the whole image, not
			// just a head buffer. n.Size is already known from the
			// container (the tar/carve layer), so one read covers it.
			head := make([]byte, n.Size)
			if _, err := ra.ReadAt(head, 0); err != nil && err != io.EOF {
				return nil, err
			}
			lk, err := telechips.ParseLKROM(head)
			if err != nil {
				return nil, err
			}
			var out []*carve.Node
			for _, e := range lk.Sorted() {
				if int64(e.Offset)+int64(e.Size) > n.Size {
					continue
				}
				out = append(out, carve.FromReaderAt(lkromChildName(e), io.NewSectionReader(ra, int64(e.Offset), int64(e.Size)), int64(e.Size)))
			}
			return out, nil
		},
	}}
}
