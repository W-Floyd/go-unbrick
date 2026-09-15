package vendor

import (
	"archive/zip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go-unbrick/internal/blankflash"
)

// samsung: Qualcomm-SoC Samsung devices share the secboot identity core (so
// `inspect` and identity matching already work), but the recovery format is
// entirely different — a .pit partition table with Odin (.tar.md5) or EDL
// Firehose rawprogram/patch XML, and no SINGLE_N_LONELY / qboot. Detection is
// implemented; the packaging steps are stubs until a Samsung loader + a second
// unit are available to build and validate against.
type samsung struct{}

func init() { Register(samsung{}) }

func (samsung) ID() string       { return "samsung" }
func (samsung) Platform() string { return PlatformQualcomm }
func (samsung) OEMIDs() []string { return []string{"0020"} }

func (samsung) CanIngest(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		found := false
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isSamsungName(d.Name()) {
				found = true
			}
			return nil
		})
		return found
	}
	if isSamsungName(filepath.Base(path)) {
		return true
	}
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		if zr, err := zip.OpenReader(path); err == nil {
			defer zr.Close()
			for _, f := range zr.File {
				if isSamsungName(filepath.Base(f.Name)) {
					return true
				}
			}
		}
	}
	return false
}

// isSamsungName recognizes Samsung recovery markers: a .pit table, an Odin
// tar.md5, or a Samsung-signed Firehose programmer.
func isSamsungName(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".pit") ||
		strings.HasSuffix(l, ".tar.md5") ||
		(strings.HasPrefix(l, "prog") && strings.Contains(l, "firehose"))
}

func (samsung) IngestDonor(string) (*blankflash.Donor, error) {
	return nil, fmt.Errorf("samsung donor ingest (.pit/Odin, not SINGLE_N_LONELY): %w", ErrUnsupported)
}

func (samsung) HarvestStock(TargetSource) (*blankflash.Target, error) {
	return nil, fmt.Errorf("samsung stock harvest (.pit-based): %w", ErrUnsupported)
}

func (samsung) Assemble(*blankflash.Donor, *blankflash.Target, AssembleOptions) (*blankflash.ForgeResult, error) {
	return nil, fmt.Errorf("samsung recovery packaging (Odin/Firehose XML): %w", ErrUnsupported)
}
