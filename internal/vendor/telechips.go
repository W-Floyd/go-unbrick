package vendor

import (
	"bytes"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
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
	case bytes.HasPrefix(data, []byte("ANDROID@")) && len(data) >= 0x20:
		return ArtifactInfo{Label: "Telechips LK bootloader", Detail: strings.Join(strings.Fields(string(bytes.Trim(data[0x18:0x20], "\x00"))), " ")}, true
	}
	return ArtifactInfo{}, false
}

// ArtifactReport implements ArtifactReporter: a boot stage's wrapper, build and
// default environment.
func (tcc) ArtifactReport(path string, head []byte) []string {
	if !telechips.IsImage(head) {
		return nil
	}
	data, err := infile.ReadFile(path)
	if err != nil {
		return nil
	}
	im, err := telechips.Parse(data)
	if err != nil {
		return nil
	}
	return im.Report()
}
