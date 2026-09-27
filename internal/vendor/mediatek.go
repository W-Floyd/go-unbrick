package vendor

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
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

// isMTKContent checks for MediaTek scatter file headers, preloader binary magics, or DA markers.
func isMTKContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// 1. Scatter text format check
	if len(data) > 32 {
		limit := len(data)
		if limit > 2048 {
			limit = 2048
		}
		sample := string(data[:limit])
		if strings.Contains(sample, "MTK_PLATFORM_CFG") ||
			(strings.Contains(sample, "platform: MT") && strings.Contains(sample, "partition_index:")) {
			return true
		}
	}
	// 2. Preloader binary header check (EMMC_BOOT, BRLYT, MMM\x01, FILE_INFO)
	limit := len(data)
	if limit > 512 {
		limit = 512
	}
	head := data[:limit]
	if bytes.HasPrefix(head, []byte("EMMC_BOOT")) ||
		bytes.HasPrefix(head, []byte("BRLYT")) ||
		bytes.Contains(head, []byte("MMM\x01")) ||
		bytes.Contains(head, []byte("FILE_INFO")) {
		return true
	}
	// 3. Download Agent binary marker check
	daLimit := len(data)
	if daLimit > 4096 {
		daLimit = 4096
	}
	daSample := data[:daLimit]
	if bytes.Contains(daSample, []byte("MTK_AllInOne_DA")) ||
		bytes.Contains(daSample, []byte("MTK_DOWNLOAD_AGENT")) {
		return true
	}
	return false
}

func (mediatek) CanIngest(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}

	// 1. Content inspection on standalone files
	if !fi.IsDir() && !strings.HasSuffix(strings.ToLower(path), ".zip") {
		if data, err := os.ReadFile(path); err == nil {
			if isMTKContent(data) {
				return true
			}
		}
	}

	// 2. Content inspection on Zip archives
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		if zr, err := zip.OpenReader(path); err == nil {
			defer zr.Close()
			for _, f := range zr.File {
				if f.FileInfo().IsDir() {
					continue
				}
				if rc, err := f.Open(); err == nil {
					buf := make([]byte, 4096)
					n, _ := io.ReadFull(rc, buf)
					rc.Close()
					if isMTKContent(buf[:n]) {
						return true
					}
				}
			}
			// Fallback inside zip: filename check
			for _, f := range zr.File {
				if isMTKName(filepath.Base(f.Name)) {
					return true
				}
			}
		}
	}

	// 3. Content inspection on directories
	if fi.IsDir() {
		found := false
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && !found {
				if data, err := os.ReadFile(p); err == nil && isMTKContent(data) {
					found = true
				}
			}
			return nil
		})
		if found {
			return true
		}
		// Fallback inside directory: filename check
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isMTKName(d.Name()) {
				found = true
			}
			return nil
		})
		if found {
			return true
		}
	}

	// 4. Last resort only: filename check on path
	return isMTKName(filepath.Base(path))
}

// isMTKName recognizes SP Flash Tool / Download Agent markers as a last resort fallback.
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

func (mediatek) IngestDonor(string) (*blankflash.Donor, error) {
	return nil, fmt.Errorf("mediatek donor ingest (SP Flash Tool scatter + DA, not Firehose): %w", ErrUnsupported)
}

func (mediatek) HarvestStock(TargetSource) (*blankflash.Target, error) {
	return nil, fmt.Errorf("mediatek stock harvest (scatter-based): %w", ErrUnsupported)
}

func (mediatek) Assemble(*blankflash.Donor, *blankflash.Target, AssembleOptions) (*blankflash.ForgeResult, error) {
	return nil, fmt.Errorf("mediatek recovery packaging (SP Flash Tool): %w", ErrUnsupported)
}
