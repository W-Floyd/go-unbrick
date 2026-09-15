package vendor

import (
	"archive/zip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"blankflash-forge/internal/bfforge"
)

// mediatek: a different recovery platform entirely — BROM/Preloader + a Download
// Agent driven by SP Flash Tool over a scatter file, not Qualcomm EDL/Firehose.
// There is no SINGLE_N_LONELY singleimage and no Qualcomm secboot cert chain, so
// none of the Qualcomm core applies. Detection is implemented (so these packages
// report cleanly instead of "unrecognized"); the rest awaits a real MTK build.
//
// Platform-level for now (OEM-agnostic): MTK auth binds differently than
// Qualcomm's OEM_ID, so a future motorola-mtk / other OEM support would refine
// this rather than add a parallel container driver.
type mediatek struct{}

func init() { Register(mediatek{}) }

func (mediatek) ID() string       { return "mediatek" }
func (mediatek) Platform() string { return PlatformMediaTek }
func (mediatek) OEMIDs() []string { return nil } // MTK does not use Qualcomm OEM_ID

func (mediatek) CanIngest(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		found := false
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isMTKName(d.Name()) {
				found = true
			}
			return nil
		})
		return found
	}
	if isMTKName(filepath.Base(path)) {
		return true
	}
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		if zr, err := zip.OpenReader(path); err == nil {
			defer zr.Close()
			for _, f := range zr.File {
				if isMTKName(filepath.Base(f.Name)) {
					return true
				}
			}
		}
	}
	return false
}

// isMTKName recognizes SP Flash Tool / Download Agent markers.
func isMTKName(name string) bool {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "scatter") && strings.HasSuffix(l, ".txt"):
		return true
	case strings.Contains(l, "mtk_allinone_da"):
		return true
	case strings.Contains(l, "sp_download_tool"):
		return true
	case l == "preloader.bin" || strings.HasPrefix(l, "preloader_"):
		return true
	}
	return false
}

func (mediatek) IngestDonor(string) (*bfforge.Donor, error) {
	return nil, fmt.Errorf("mediatek donor ingest (SP Flash Tool scatter + DA, not Firehose): %w", ErrUnsupported)
}

func (mediatek) HarvestStock(TargetSource) (*bfforge.Target, error) {
	return nil, fmt.Errorf("mediatek stock harvest (scatter-based): %w", ErrUnsupported)
}

func (mediatek) Assemble(*bfforge.Donor, *bfforge.Target, AssembleOptions) (*bfforge.ForgeResult, error) {
	return nil, fmt.Errorf("mediatek recovery packaging (SP Flash Tool): %w", ErrUnsupported)
}
