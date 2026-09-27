package vendor

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/payload"
	"github.com/W-Floyd/go-unbrick/internal/qfil"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
)

// qualcomm: standard Qualcomm Firehose EDL recovery driver (QFIL / rawprogram0.xml).
// Unlike Motorola's singleimage.bin container, standard Qualcomm recovery packages
// consist of the signed Firehose loader (prog_firehose_*.elf), partition XMLs
// (rawprogram0.xml and patch0.xml), gpt_main0.bin, and the target's partition images.
type qualcomm struct{}

func init() { Register(qualcomm{}) }

func (qualcomm) ID() string       { return "qualcomm" }
func (qualcomm) Platform() string { return PlatformQualcomm }
func (qualcomm) OEMIDs() []string { return []string{"0000"} }

// EDLCommands: the reference Qualcomm routes, for a device whose OEM the catalog
// does not name. `reboot edl` is last because a current AOSP fastboot rejects
// that target itself, so it never reaches the bootloader.
func (qualcomm) EDLCommands() [][]string {
	return [][]string{{"oem", "edl"}, {"reboot-edl"}, {"reboot", "emergency"}, {"reboot", "edl"}}
}

func (qualcomm) CanIngest(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}

	// 1. Content inspection on standalone files
	if !fi.IsDir() && !strings.HasSuffix(strings.ToLower(path), ".zip") {
		if data, err := os.ReadFile(path); err == nil {
			if isFirehoseContent(data) || isRawProgramContent(data) || isPatchContent(data) {
				return true
			}
			if id, err := secboot.FromELF(data); err == nil && (id.OEMID == "0000" || id.OEMID == "0001") {
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
					buf := make([]byte, 65536)
					n, _ := io.ReadFull(rc, buf)
					rc.Close()
					sample := buf[:n]
					if isFirehoseContent(sample) || isRawProgramContent(sample) {
						return true
					}
					if f.UncompressedSize64 > 0 && f.UncompressedSize64 < 32*1024*1024 {
						if rc, err := f.Open(); err == nil {
							data, _ := io.ReadAll(rc)
							rc.Close()
							if isFirehoseContent(data) || isRawProgramContent(data) {
								return true
							}
						}
					}
				}
			}
			// Fallback inside zip: filename check
			for _, f := range zr.File {
				if isQualcommDonorName(filepath.Base(f.Name)) {
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
				if data, err := os.ReadFile(p); err == nil {
					if isFirehoseContent(data) || isRawProgramContent(data) {
						found = true
					}
				}
			}
			return nil
		})
		if found {
			return true
		}
		// Fallback inside directory: filename check
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isQualcommDonorName(d.Name()) {
				found = true
			}
			return nil
		})
		if found {
			return true
		}
	}

	// 4. Last resort only: filename check on path
	return isQualcommDonorName(filepath.Base(path))
}

// isFirehoseContent inspects binary bytes to determine if it is a Qualcomm Firehose programmer.
func isFirehoseContent(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	// Check for signed Qualcomm ELF with Firehose markers or programmer SW_ID
	if id, err := secboot.FromELF(data); err == nil {
		lower := bytes.ToLower(data)
		if bytes.Contains(lower, []byte("firehose")) ||
			bytes.Contains(lower, []byte("fh_cmd")) ||
			bytes.Contains(data, []byte("<data>")) ||
			bytes.Contains(data, []byte("configure")) ||
			id.SWID == 0x0d || id.SWID == 0x1b || id.SWID == 0x12 {
			return true
		}
	}
	// Check for unsigned ELF or binary containing Firehose markers
	lower := bytes.ToLower(data)
	if (secboot.IsELF(data) || len(data) > 64) && (bytes.Contains(lower, []byte("firehose")) || bytes.Contains(lower, []byte("fh_cmd"))) {
		return true
	}
	return false
}

// isRawProgramContent inspects data to check if it is a Qualcomm rawprogram XML.
func isRawProgramContent(data []byte) bool {
	if !bytes.Contains(data, []byte("<data>")) && !bytes.Contains(data, []byte("<program")) {
		return false
	}
	entries, err := qfil.ParseRawProgram(data)
	return err == nil && len(entries) > 0
}

// isPatchContent inspects data to check if it is a Qualcomm patch XML.
func isPatchContent(data []byte) bool {
	if !bytes.Contains(data, []byte("<patches>")) && !bytes.Contains(data, []byte("<patch")) {
		return false
	}
	entries, err := qfil.ParsePatch(data)
	return err == nil && len(entries) > 0
}

// isQualcommDonorName identifies Firehose programmers and standard Qualcomm flash files as a last resort.
func isQualcommDonorName(name string) bool {
	l := strings.ToLower(name)
	if strings.Contains(l, "firehose") && (strings.HasSuffix(l, ".elf") || strings.HasSuffix(l, ".mbn") || strings.HasSuffix(l, ".bin")) {
		return true
	}
	if strings.HasPrefix(l, "prog_") && (strings.HasSuffix(l, ".elf") || strings.HasSuffix(l, ".mbn")) {
		return true
	}
	if strings.Contains(l, "_fhprg") && strings.HasSuffix(l, ".bin") {
		return true
	}
	return false
}

func inferStorage(name string, data []byte) string {
	if len(data) > 0 {
		lower := bytes.ToLower(data)
		if bytes.Contains(lower, []byte("ufs")) && !bytes.Contains(lower, []byte("emmc")) {
			return "ufs"
		}
		if bytes.Contains(lower, []byte("emmc")) && !bytes.Contains(lower, []byte("ufs")) {
			return "emmc"
		}
	}
	return inferStorageFromName(name)
}

func inferStorageFromName(name string) string {
	l := strings.ToLower(name)
	if strings.Contains(l, "ufs") {
		return "ufs"
	}
	if strings.Contains(l, "emmc") {
		return "emmc"
	}
	return ""
}

func (qualcomm) IngestDonor(path string) (*blankflash.Donor, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Standalone Firehose programmer file
	if !fi.IsDir() && !strings.HasSuffix(strings.ToLower(path), ".zip") {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(path)
		return &blankflash.Donor{
			Programmer: data,
			Storage:    inferStorage(base, data),
			Source:     path,
		}, nil
	}

	// Directory of files
	if fi.IsDir() {
		var progData []byte
		var progName string
		recipes := map[string][]byte{}

		// Pass 1: content inspection
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			fn := filepath.Base(p)
			if isRawProgramContent(data) {
				recipes[fn] = data
			}
			if isFirehoseContent(data) && progData == nil {
				progData = data
				progName = fn
			}
			return nil
		})

		// Pass 2: fallback to filename matching only if content inspection didn't find programmer
		if progData == nil {
			filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				fn := filepath.Base(p)
				if isQualcommDonorName(fn) && progData == nil {
					if data, err := os.ReadFile(p); err == nil {
						progData = data
						progName = fn
					}
				}
				if strings.HasPrefix(fn, "rawprogram") && strings.HasSuffix(fn, ".xml") {
					if b, err := os.ReadFile(p); err == nil && recipes[fn] == nil {
						recipes[fn] = b
					}
				}
				return nil
			})
		}

		if progData == nil {
			return nil, fmt.Errorf("no Firehose programmer found in %s", path)
		}
		return &blankflash.Donor{
			Programmer: progData,
			Recipes:    recipes,
			Storage:    inferStorage(progName, progData),
			Source:     path,
		}, nil
	}

	// Zip file
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var progData []byte
	var progName string
	recipes := map[string][]byte{}

	// Pass 1: content inspection
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		fn := filepath.Base(f.Name)
		if isRawProgramContent(data) {
			recipes[fn] = data
		}
		if isFirehoseContent(data) && progData == nil {
			progData = data
			progName = fn
		}
	}

	// Pass 2: fallback to filename matching
	if progData == nil {
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			fn := filepath.Base(f.Name)
			if isQualcommDonorName(fn) && progData == nil {
				if rc, err := f.Open(); err == nil {
					data, _ := io.ReadAll(rc)
					rc.Close()
					progData = data
					progName = fn
				}
			}
			if strings.HasPrefix(fn, "rawprogram") && strings.HasSuffix(fn, ".xml") && recipes[fn] == nil {
				if rc, err := f.Open(); err == nil {
					b, _ := io.ReadAll(rc)
					rc.Close()
					recipes[fn] = b
				}
			}
		}
	}

	if progData == nil {
		return nil, fmt.Errorf("no Firehose programmer found in zip %s", path)
	}

	return &blankflash.Donor{
		Programmer: progData,
		Recipes:    recipes,
		Storage:    inferStorage(progName, progData),
		Source:     path,
	}, nil
}

func (qualcomm) HarvestStock(src TargetSource) (*blankflash.Target, error) {
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
		target, err := blankflash.FromDumps(src.Parts, slot, gpt)
		if err != nil {
			return nil, err
		}
		// If rawprogram0.xml is in the dumps dir, refine FlashMap / FlashOrder
		rpPath := filepath.Join(src.Parts, "rawprogram0.xml")
		if rpData, err := os.ReadFile(rpPath); err == nil {
			if entries, err := qfil.ParseRawProgram(rpData); err == nil {
				order := make([]string, 0, len(entries))
				fmap := make(map[string]string, len(entries))
				for _, e := range entries {
					if e.Label == "PrimaryGPT" || e.Filename == "" {
						continue
					}
					cleanLabel := strings.TrimSuffix(strings.TrimSuffix(e.Label, "_a"), "_b")
					order = append(order, cleanLabel)
					fmap[cleanLabel] = e.Filename
				}
				target.FlashOrder = order
				target.FlashMap = fmap
			}
		}
		return target, nil
	}

	if src.Bootloader == "" {
		return nil, fmt.Errorf("need --target-parts or --target-bootloader")
	}

	// If bootloader is a directory or zip holding partition images
	fi, err := os.Stat(src.Bootloader)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return blankflash.FromDumps(src.Bootloader, slot, gpt)
	}

	// Content check 1: Standalone file
	if !fi.IsDir() && !strings.HasSuffix(strings.ToLower(src.Bootloader), ".zip") {
		data, err := os.ReadFile(src.Bootloader)
		if err != nil {
			return nil, err
		}
		// Check for Android OTA payload magic "CrAU"
		if len(data) >= payload.HeaderLen && string(data[:4]) == payload.HeaderMagic {
			p, err := payload.NewFromReaderAt(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				return nil, fmt.Errorf("parsing payload: %w", err)
			}
			return harvestQualcommPayload(p, gpt)
		}
		// Check for Motorola blankflash container magic
		if blankflash.IsContainer(data) {
			return blankflash.FromBootloaderImg(data, gpt)
		}
	}

	// Content check 2: Zip archive (checks for CrAU payload inside)
	if strings.HasSuffix(strings.ToLower(src.Bootloader), ".zip") {
		if p, closer, err := payload.OpenZip(src.Bootloader); err == nil {
			defer closer.Close()
			return harvestQualcommPayload(p, gpt)
		}
	}

	// Fallback check 3: payload.bin filename check
	base := strings.ToLower(filepath.Base(src.Bootloader))
	if base == "payload.bin" {
		f, err := os.Open(src.Bootloader)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		p, err := payload.NewFromReaderAt(f, fi.Size())
		if err != nil {
			return nil, fmt.Errorf("parsing payload.bin: %w", err)
		}
		return harvestQualcommPayload(p, gpt)
	}

	return nil, fmt.Errorf("unrecognized bootloader image format in %s", src.Bootloader)
}

func harvestQualcommPayload(p *payload.Payload, gpt []byte) (*blankflash.Target, error) {
	files := make(map[string][]byte)
	ctx := context.Background()
	for _, name := range p.Partitions() {
		if !payload.IsBootloaderPartition(name) {
			continue
		}
		data, err := p.ExtractPartitionToBytes(ctx, name)
		if err != nil {
			continue
		}
		clean := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(name, "_a"), "_b"))
		files[clean] = data
		files[name] = data
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no bootloader partitions found in payload.bin")
	}
	return &blankflash.Target{
		GPT:    gpt,
		Parts:  files,
		Source: "payload.bin",
	}, nil
}

func (qualcomm) Assemble(d *blankflash.Donor, t *blankflash.Target, opts AssembleOptions) (*blankflash.ForgeResult, error) {
	return qfil.Assemble(d, t, qfil.AssembleOptions{
		Slot:      opts.Slot,
		Storage:   opts.Storage,
		Provision: opts.Provision,
	})
}
