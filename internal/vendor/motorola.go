package vendor

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go-unbrick/internal/blankflash"
)

// motorola: Qualcomm/qboot blankflash — a SINGLE_N_LONELY singleimage.bin plus
// the qboot flasher. Delegates to the blankflash codec, which is this format.
type motorola struct{}

func init() { Register(motorola{}) }

func (motorola) ID() string       { return "motorola" }
func (motorola) Platform() string { return PlatformQualcomm }
func (motorola) OEMIDs() []string { return []string{"02E8"} }

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
	return isContainerHead(path)
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
