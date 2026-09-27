package vendor

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
)

// motorola: Qualcomm/qboot blankflash — a SINGLE_N_LONELY singleimage.bin plus
// the qboot flasher. Delegates to the blankflash codec, which is this format.
type motorola struct{}

func init() { Register(motorola{}) }

func (motorola) ID() string       { return "motorola" }
func (motorola) Platform() string { return PlatformQualcomm }
func (motorola) OEMIDs() []string { return []string{"02E8"} }

// EDLCommands: Motorola's ABL reaches EDL through `oem blankflash`, which its
// own `oem help` advertises (observed on fogona, U1TF34.100-35-14). `oem edl` is
// kept as a second try for older MBM builds that predate it.
func (motorola) EDLCommands() [][]string {
	return [][]string{{"oem", "blankflash"}, {"oem", "edl"}}
}

func (motorola) CanIngest(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		found := false
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isContainerHead(p) {
				found = true
			}
			return nil
		})
		return found
	}
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		zr, err := zip.OpenReader(path)
		if err != nil {
			return false
		}
		defer zr.Close()
		for _, f := range zr.File {
			if strings.HasSuffix(f.Name, "/") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			head := make([]byte, len(blankflash.Magic))
			n, _ := io.ReadFull(rc, head)
			rc.Close()
			if blankflash.IsContainer(head[:n]) {
				return true
			}
		}
		return false
	}
	return isContainerHead(path) || MatchesVendorCatalog("motorola", path)
}

func isContainerHead(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, len(blankflash.Magic))
	n, _ := io.ReadFull(f, head)
	return blankflash.IsContainer(head[:n])
}

func (motorola) IngestDonor(path string) (*blankflash.Donor, error) {
	return blankflash.Ingest(path)
}

// stockMembers are the members of a Motorola retail firmware zip that carry the
// target's boot chain and partition table. The rest of the package (super
// chunks, radio, logo...) is not part of a blankflash.
var stockMembers = []string{"bootloader.img", "gpt.bin"}

// flashfileHeader is the part of a retail package's flashfile.xml that identifies
// the channel the package is built for, rather than the images it flashes.
type flashfileHeader struct {
	CIDValue struct {
		Value string `xml:"value,attr"`
	} `xml:"header>cid_value"`
	SubsidyLock struct {
		Name string `xml:"name,attr"`
	} `xml:"header>subsidy_lock_config"`
}

// carrierFromFlashfile reads the CID and subsidy-lock config a retail package
// declares. Both are absent from service and donor packages, so a miss is normal
// and silent: an unparseable or headerless flashfile just yields no channel data.
func carrierFromFlashfile(b []byte) (cid, subsidyLock string) {
	if len(b) == 0 {
		return "", ""
	}
	var h flashfileHeader
	if err := xml.Unmarshal(b, &h); err != nil {
		return "", ""
	}
	return strings.TrimSpace(h.CIDValue.Value), strings.TrimSpace(h.SubsidyLock.Name)
}

// zipMembers reads the named top-level members of a zip in one pass. Members are
// matched on base name, so a crafted path in the archive cannot escape anywhere:
// nothing is written to disk.
func zipMembers(path string, names []string) (map[string][]byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := make(map[string][]byte, len(names))
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if !want[base] || out[base] != nil {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		out[base] = b
	}
	return out, nil
}

func (motorola) CanIngestStock(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".zip") {
		return false
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return false
	}
	defer zr.Close()

	// A Motorola stock package requires both bootloader.img and gpt.bin
	var blFile *zip.File
	hasGPT := false
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if base == "bootloader.img" {
			blFile = f
		}
		if base == "gpt.bin" {
			hasGPT = true
		}
	}
	if blFile == nil || !hasGPT {
		return false
	}

	// Content check on bootloader.img
	if rc, err := blFile.Open(); err == nil {
		head := make([]byte, len(blankflash.Magic))
		n, _ := io.ReadFull(rc, head)
		rc.Close()
		if blankflash.IsContainer(head[:n]) {
			return true
		}
	}

	// Fallback when bootloader.img has no container magic (e.g. test stubs)
	return true
}

func (motorola) HarvestStockPackage(path string) (*blankflash.Target, error) {
	m, err := zipMembers(path, append(stockMembers, "flashfile.xml"))
	if err != nil {
		return nil, err
	}
	for _, n := range stockMembers {
		if m[n] == nil {
			return nil, fmt.Errorf("%s: not a Motorola stock package (no %s)", path, n)
		}
	}
	t, err := blankflash.FromBootloaderImg(m["bootloader.img"], m["gpt.bin"])
	if err != nil {
		return nil, err
	}
	t.Source = path
	t.CID, t.SubsidyLock = carrierFromFlashfile(m["flashfile.xml"])
	return t, nil
}

// reSuperChunk matches the sparse chunks a Motorola package splits super into.
var reSuperChunk = regexp.MustCompile(`^super\.img_sparsechunk\.(\d+)$`)

// ExplodeStock writes every partition image in a Motorola retail zip to dir:
// the package's own members, plus the boot-chain images unpacked out of
// bootloader.img (named by their flash label, e.g. xbl.img). super is joined
// from its chunks only when asked.
func (m motorola) ExplodeStock(path, dir string, opts ExplodeOptions) ([]string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	var written []string
	chunks := map[int]*zip.File{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(f.Name)
		if sc := reSuperChunk.FindStringSubmatch(base); sc != nil {
			n, _ := strconv.Atoi(sc[1])
			chunks[n] = f
			continue
		}
		if err := copyZipMember(f, filepath.Join(dir, base)); err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		written = append(written, base)
	}

	if opts.Super && len(chunks) > 0 {
		name, err := joinSuper(chunks, filepath.Join(dir, "super.img"))
		if err != nil {
			return nil, err
		}
		written = append(written, name)
	}

	// The boot chain lives inside bootloader.img, so it is not a member of its
	// own; unpack it so every flashable partition is present as a file. A
	// bootloader we cannot parse is not fatal -- the package's own members are
	// already written and remain useful.
	if blPath := filepath.Join(dir, "bootloader.img"); fileExists(blPath) {
		names, err := m.explodeBootloader(blPath, dir)
		if err != nil {
			return written, fmt.Errorf("bootloader.img not unpacked (%w); package members were still written", err)
		}
		written = append(written, names...)
	}
	sort.Strings(written)
	return written, nil
}

// explodeBootloader writes each boot-chain partition as <label>.img.
func (m motorola) explodeBootloader(blPath, dir string) ([]string, error) {
	img, err := os.ReadFile(blPath)
	if err != nil {
		return nil, err
	}
	t, err := blankflash.FromBootloaderImg(img, nil)
	if err != nil {
		return nil, err
	}
	var out []string
	labels := make([]string, 0, len(t.FlashMap))
	for l := range t.FlashMap {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, label := range labels {
		data, ok := t.Parts[t.FlashMap[label]]
		if !ok {
			continue
		}
		name := label + ".img"
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, nil
}

func joinSuper(chunks map[int]*zip.File, dest string) (string, error) {
	out, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	defer out.Close()
	for i := 0; i < len(chunks); i++ {
		f, ok := chunks[i]
		if !ok {
			return "", fmt.Errorf("super chunk %d missing; refusing to write a short image", i)
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		if err != nil {
			return "", err
		}
	}
	return filepath.Base(dest), nil
}

func copyZipMember(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// CodenameFromStock reads the device name Motorola stamps into the GPT.
func (motorola) CodenameFromStock(t *blankflash.Target) string {
	return CodenameFromGPT(t.GPT)
}

// HarvestDonorStock recovers the donor device's own signed boot chain and GPT
// from a blankflash package. The singleimage is the same SINGLE_N_LONELY
// container as a bootloader.img, carrying its own recipe, so the stock harvest
// path reads it directly.
func (motorola) HarvestDonorStock(path string) (*blankflash.Target, error) {
	img, err := singleimageOf(path)
	if err != nil {
		return nil, err
	}
	recs, err := blankflash.Parse(img)
	if err != nil {
		return nil, err
	}
	gpt := blankflash.Index(recs)["gpt.bin"]
	if gpt == nil {
		return nil, fmt.Errorf("no gpt.bin in the donor package")
	}
	t, err := blankflash.FromBootloaderImg(img, gpt)
	if err != nil {
		return nil, err
	}
	if len(t.Parts) == 0 {
		return nil, fmt.Errorf("donor carries a loader but no boot chain")
	}
	t.Source = path
	return t, nil
}

// singleimageOf returns the container bytes of a donor, given the package zip,
// a directory, or the singleimage itself.
func singleimageOf(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		var found string
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && found == "" && isContainerHead(p) {
				found = p
			}
			return nil
		})
		if found == "" {
			return nil, fmt.Errorf("no SINGLE_N_LONELY container under %s", path)
		}
		return os.ReadFile(found)
	}
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		zr, err := zip.OpenReader(path)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err == nil && blankflash.IsContainer(b) {
				return b, nil
			}
		}
		return nil, fmt.Errorf("no SINGLE_N_LONELY container in %s", path)
	}
	return os.ReadFile(path)
}

func (motorola) HarvestStock(src TargetSource) (*blankflash.Target, error) {
	var gpt []byte
	if src.GPT != "" {
		var err error
		if gpt, err = os.ReadFile(src.GPT); err != nil {
			return nil, err
		}
	}
	slot := src.Slot
	if slot == "" {
		slot = "a"
	}
	if src.Parts != "" {
		return blankflash.FromDumps(src.Parts, slot, gpt)
	}
	if src.Bootloader == "" {
		return nil, fmt.Errorf("need --target-bootloader or --target-parts")
	}
	img, err := os.ReadFile(src.Bootloader)
	if err != nil {
		return nil, err
	}
	return blankflash.FromBootloaderImg(img, gpt)
}

func (motorola) Assemble(d *blankflash.Donor, t *blankflash.Target, opts AssembleOptions) (*blankflash.ForgeResult, error) {
	return blankflash.Forge(d, t, opts.Slot, opts.Storage, opts.Provision)
}

// reMBM matches the build signature Motorola stamps into every boot partition,
// e.g. "MBM-3.0-fogona-2902df5ac-250831" -- product, git hash, and YYMMDD.
var reMBM = regexp.MustCompile(`MBM-[0-9.]+-([a-z0-9_]+)-([0-9a-f]{6,})-(\d{6})`)

// StockBuildID names a stock build "<YYMMDD>-<githash>", date first so that
// lexical order is chronological. Every signed partition carries the same
// stamp, so any one of them identifies the build; xbl/abl are checked first
// only to avoid scanning the largest images.
func (motorola) StockBuildID(t *blankflash.Target) string {
	order := append([]string{"xbl.elf", "abl.elf"}, sortedNames(t.Parts)...)
	seen := map[string]bool{}
	for _, fn := range order {
		if seen[fn] {
			continue
		}
		seen[fn] = true
		m := reMBM.FindSubmatch(t.Parts[fn])
		if m == nil {
			continue
		}
		return string(m[3]) + "-" + string(m[2])
	}
	return ""
}

func sortedNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// prodField is the space-padded product tag Motorola stamps into each LUN image
// of a gpt.bin, e.g. "PROD:fogona". It is the package's own name for the device
// and matches the catalog codename, where the MBM build signature does not
// (devon's reads "devon_g").
const prodField = "PROD:"

// CodenameFromGPT reads the device codename out of a Motorola gpt.bin. The file
// is itself a SINGLE_N_LONELY container whose gpt_mainN.bin records each carry a
// signed trailer beginning with the PROD field. Returns "" if absent.
func CodenameFromGPT(gpt []byte) string {
	if !blankflash.IsContainer(gpt) {
		return ""
	}
	recs, err := blankflash.Parse(gpt)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(recs))
	byName := map[string][]byte{}
	for _, r := range recs {
		if strings.HasPrefix(r.Name, "gpt_main") {
			names = append(names, r.Name)
			byName[r.Name] = r.Data
		}
	}
	sort.Strings(names)
	for _, n := range names {
		if cn := prodOf(byName[n]); cn != "" {
			return cn
		}
	}
	return ""
}

// prodOf extracts the codename from one LUN image's PROD field. The field is a
// fixed 16-byte space-padded cell, so the value ends at the first space or NUL.
func prodOf(lun []byte) string {
	i := bytes.Index(lun, []byte(prodField))
	if i < 0 {
		return ""
	}
	v := lun[i+len(prodField):]
	if len(v) > 16 {
		v = v[:16]
	}
	if j := bytes.IndexAny(v, " \x00"); j >= 0 {
		v = v[:j]
	}
	cn := strings.ToLower(string(v))
	for _, r := range cn {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return ""
		}
	}
	return cn
}
