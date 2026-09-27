package vendor

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
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

var pitMagic = []byte{0x76, 0x98, 0x34, 0x12}

// isSamsungContent checks for PIT binary magic (0x12349876) or Samsung Qualcomm secboot signatures.
func isSamsungContent(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// 1. PIT file binary magic: 0x12349876 in little endian
	if bytes.HasPrefix(data, pitMagic) {
		return true
	}
	// 2. Qualcomm signed ELF for Samsung (OEMID 0020 or Samsung cert CN)
	if id, err := secboot.FromELF(data); err == nil {
		if id.OEMID == "0020" || strings.Contains(strings.ToLower(id.RootCN), "samsung") || strings.Contains(strings.ToLower(id.LeafCN), "samsung") {
			return true
		}
	}
	return false
}

// isSamsungTar inspects an Odin tarball (.tar / .tar.md5) for Samsung content.
func isSamsungTar(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		buf := make([]byte, 4)
		n, _ := io.ReadFull(tr, buf)
		if n == 4 && bytes.Equal(buf, pitMagic) {
			return true
		}
		base := strings.ToLower(filepath.Base(hdr.Name))
		if strings.HasSuffix(base, ".pit") || base == "sboot.bin" || base == "sboot.bin.lz4" || base == "param.bin" || base == "param.bin.lz4" {
			return true
		}
	}
	return false
}

func (samsung) CanIngest(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}

	// 1. Content inspection on standalone files
	if !fi.IsDir() && !strings.HasSuffix(strings.ToLower(path), ".zip") {
		if data, err := os.ReadFile(path); err == nil {
			if isSamsungContent(data) {
				return true
			}
		}
		if isSamsungTar(path) {
			return true
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
					if isSamsungContent(buf[:n]) {
						return true
					}
				}
			}
			// Fallback inside zip: filename check
			for _, f := range zr.File {
				if isSamsungName(filepath.Base(f.Name)) {
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
				if data, err := os.ReadFile(p); err == nil && isSamsungContent(data) {
					found = true
				}
				if !found && isSamsungTar(p) {
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
			if err == nil && !d.IsDir() && isSamsungName(d.Name()) {
				found = true
			}
			return nil
		})
		if found {
			return true
		}
	}

	// 4. Last resort only: filename check on path
	return isSamsungName(filepath.Base(path))
}

// isSamsungName recognizes Samsung recovery markers as a last resort fallback.
func isSamsungName(name string) bool {
	if MatchesVendorCatalog("samsung", name) {
		return true
	}
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
