package vendor

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/payload"
)

// google: Google Pixel / Tensor firmware driver.
// Handles official Google Pixel OTA packages (.zip with payload.bin and metadata),
// extracting Google Tensor firmware (ABL, BL31, GSA, TZSW, DRAM) and core Android boot partitions.
type google struct{}

func init() { Register(google{}) }

func (google) ID() string       { return "google" }
func (google) Platform() string { return "tensor" }
func (google) OEMIDs() []string { return []string{"0000"} }

func (g google) CanIngest(path string) bool {
	// 1. Content inspection
	if g.CanIngestStock(path) {
		return true
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		if metaBytes, err := os.ReadFile(filepath.Join(path, "META-INF/com/android/metadata")); err == nil {
			if strings.Contains(string(metaBytes), "post-build=google/") {
				return true
			}
		}
	}
	// 2. Last resort only: filename check driven by catalog YAML
	return MatchesVendorCatalog("google", path)
}

func (google) CanIngestStock(path string) bool {
	// 1. Content check on zip files
	if zr, err := zip.OpenReader(path); err == nil {
		defer zr.Close()
		for _, f := range zr.File {
			if f.Name == "META-INF/com/android/metadata" {
				if rc, err := f.Open(); err == nil {
					buf := make([]byte, 4096)
					n, _ := io.ReadFull(rc, buf)
					rc.Close()
					if strings.Contains(string(buf[:n]), "post-build=google/") {
						return true
					}
				}
			}
		}
	}

	// 2. Content check on directories
	if metaBytes, err := os.ReadFile(filepath.Join(path, "META-INF/com/android/metadata")); err == nil {
		if strings.Contains(string(metaBytes), "post-build=google/") {
			return true
		}
	}

	// 3. Last resort only: filename matching if unreadable, driven by catalog YAML
	return MatchesVendorCatalog("google", path)
}

func (g google) HarvestStockPackage(path string) (*blankflash.Target, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var metadataBytes []byte
	for _, f := range zr.File {
		if f.Name == "META-INF/com/android/metadata" {
			rc, err := f.Open()
			if err == nil {
				metadataBytes, _ = io.ReadAll(rc)
				rc.Close()
			}
			break
		}
	}

	p, closer, err := payload.OpenZip(path)
	if err != nil {
		return nil, fmt.Errorf("opening payload from %s: %w", path, err)
	}
	defer closer.Close()

	ctx := context.Background()
	parts := make(map[string][]byte)

	for _, name := range p.Partitions() {
		if !payload.IsBootloaderPartition(name) {
			continue
		}
		data, err := p.ExtractPartitionToBytes(ctx, name)
		if err != nil {
			continue
		}
		clean := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(name, "_a"), "_b"))
		parts[clean+".img"] = data
		parts[name+".img"] = data
	}

	if len(metadataBytes) > 0 {
		parts["ota_metadata"] = metadataBytes
	}

	return &blankflash.Target{
		Parts:   parts,
		Storage: "ufs",
		Source:  path,
	}, nil
}

func (google) CodenameFromStock(t *blankflash.Target) string {
	meta, ok := t.Parts["ota_metadata"]
	if !ok {
		return ""
	}
	for _, line := range strings.Split(string(meta), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pre-device=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "pre-device="))
		}
	}
	return ""
}

func (google) StockBuildID(t *blankflash.Target) string {
	meta, ok := t.Parts["ota_metadata"]
	if !ok {
		return ""
	}
	for _, line := range strings.Split(string(meta), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "post-build=") {
			// Format: google/<device>/<device>:<version>/<build_id>/<incremental>:user/release-keys
			val := strings.TrimPrefix(line, "post-build=")
			parts := strings.Split(val, ":")
			if len(parts) >= 2 {
				sub := strings.Split(parts[1], "/")
				if len(sub) >= 2 {
					return sub[1] // e.g. BD1A.250702.001 or CD1A.260618.001.A7
				}
			}
			return val
		}
	}
	return ""
}

func (google) IngestDonor(path string) (*blankflash.Donor, error) {
	return nil, ErrUnsupported
}

func (google) HarvestStock(src TargetSource) (*blankflash.Target, error) {
	if src.Bootloader != "" {
		return google{}.HarvestStockPackage(src.Bootloader)
	}
	if src.Parts != "" {
		return blankflash.FromDumps(src.Parts, src.Slot, nil)
	}
	return nil, fmt.Errorf("google driver requires stock OTA zip package via --target-bootloader")
}

func (google) Assemble(d *blankflash.Donor, t *blankflash.Target, opts AssembleOptions) (*blankflash.ForgeResult, error) {
	return nil, ErrUnsupported
}
