package vendor

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/payload"
	"go-unbrick/internal/qfil"
	"go-unbrick/internal/secboot"
)

// xiaomi: Xiaomi / Redmi / POCO Qualcomm Firehose EDL recovery driver.
// Handles Fastboot archives (.tgz / images/ directory), Recovery packages (.zip with
// firmware-update/ and alias resolution), modern Android OTA packages (payload.bin),
// and raw partition dumps, assembling standard QFIL Firehose recovery bundles.
type xiaomi struct{}

func init() { Register(xiaomi{}) }

func (xiaomi) ID() string       { return "xiaomi" }
func (xiaomi) Platform() string { return PlatformQualcomm }
func (xiaomi) OEMIDs() []string { return []string{"0072", "0000", "0001", "0003"} }

// Xiaomi partition filename aliases mapped from recovery packages / firmware-update/.
var xiaomiAliases = map[string]string{
	"qupv3fw.elf":     "qupfw",
	"uefi_sec.mbn":    "uefisecapp",
	"km4.mbn":         "keymaster",
	"km3.mbn":         "keymaster",
	"NON-HLOS.bin":    "modem",
	"BTFM.bin":        "bluetooth",
	"dspso.bin":       "dsp",
	"featenabler.mbn": "featenabler",
}

func (xiaomi) CanIngest(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}

	// 1. Content inspection on standalone ELF files
	if !fi.IsDir() {
		if data, err := os.ReadFile(path); err == nil {
			if id, err := secboot.FromELF(data); err == nil {
				if id.OEMID == "0072" {
					return true
				}
			}
		}
	}

	// 2. Content inspection on Zip archives
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		if zr, err := zip.OpenReader(path); err == nil {
			defer zr.Close()
			for _, f := range zr.File {
				// Check OTA metadata content
				if f.Name == "META-INF/com/android/metadata" {
					if rc, err := f.Open(); err == nil {
						buf := make([]byte, 4096)
						n, _ := io.ReadFull(rc, buf)
						rc.Close()
						content := strings.ToLower(string(buf[:n]))
						if strings.Contains(content, "post-build=xiaomi/") ||
							strings.Contains(content, "post-build=redmi/") ||
							strings.Contains(content, "post-build=poco/") {
							return true
						}
					}
				}
				// Check updater-script content
				if strings.HasSuffix(f.Name, "updater-script") {
					if rc, err := f.Open(); err == nil {
						buf := make([]byte, 4096)
						n, _ := io.ReadFull(rc, buf)
						rc.Close()
						content := strings.ToLower(string(buf[:n]))
						if strings.Contains(content, "xiaomi") || strings.Contains(content, "miui") {
							return true
						}
					}
				}
				// Check for signed Firehose loader with OEMID 0072
				if strings.Contains(strings.ToLower(f.Name), "firehose") && (strings.HasSuffix(f.Name, ".elf") || strings.HasSuffix(f.Name, ".mbn")) {
					if rc, err := f.Open(); err == nil {
						data, _ := io.ReadAll(rc)
						rc.Close()
						if id, err := secboot.FromELF(data); err == nil && id.OEMID == "0072" {
							return true
						}
					}
				}
				// Check for firmware-update directory structure
				if strings.Contains(f.Name, "firmware-update/") {
					return true
				}
			}
		}
	}

	// 3. Content inspection on Tar / TGZ archives
	if strings.HasSuffix(strings.ToLower(path), ".tgz") || strings.HasSuffix(strings.ToLower(path), ".tar.gz") || strings.HasSuffix(strings.ToLower(path), ".tar") {
		if isXiaomiTar(path) {
			return true
		}
	}

	// 4. Content inspection on directories
	if fi.IsDir() {
		if isXiaomiDirectory(path) {
			return true
		}
	}

	// 5. Last resort only: filename and format extension fallback driven by catalog YAML
	if MatchesVendorCatalog("xiaomi", path) {
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(base, ".tgz") || strings.HasSuffix(base, ".tar.gz") || base == "payload.bin"
}

func isXiaomiTar(tarPath string) bool {
	f, err := os.Open(tarPath)
	if err != nil {
		return false
	}
	defer f.Close()

	var tr *tar.Reader
	if strings.HasSuffix(strings.ToLower(tarPath), ".tar") {
		tr = tar.NewReader(f)
	} else {
		gzr, err := gzip.NewReader(f)
		if err != nil {
			return false
		}
		defer gzr.Close()
		tr = tar.NewReader(gzr)
	}

	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		name := strings.ToLower(hdr.Name)
		if strings.Contains(name, "flash_all.sh") || strings.Contains(name, "rawprogram") {
			buf := make([]byte, 4096)
			n, _ := tr.Read(buf)
			content := strings.ToLower(string(buf[:n]))
			if strings.Contains(content, "fastboot") || strings.Contains(content, "program") || strings.Contains(content, "anti_ver") {
				return true
			}
		}
	}
	return false
}

func isXiaomiDirectory(dir string) bool {
	if b, err := os.ReadFile(filepath.Join(dir, "flash_all.sh")); err == nil {
		if strings.Contains(string(b), "fastboot") || strings.Contains(string(b), "anti_ver") {
			return true
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "images/rawprogram0.xml")); err == nil {
		if strings.Contains(string(b), "<program") {
			return true
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "rawprogram0.xml")); err == nil {
		if strings.Contains(string(b), "<program") {
			return true
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "firmware-update")); err == nil && fi.IsDir() {
		return true
	}
	return false
}

func (x xiaomi) IngestDonor(path string) (*blankflash.Donor, error) {
	// If it's an archive or directory, find programmer and rawprogram recipes
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	base := strings.ToLower(filepath.Base(path))

	// Standalone programmer file
	if !fi.IsDir() && (strings.HasSuffix(base, ".elf") || strings.HasSuffix(base, ".mbn") || strings.HasSuffix(base, ".bin")) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return &blankflash.Donor{
			Programmer: data,
			Storage:    inferStorageFromName(base),
			Source:     path,
		}, nil
	}

	// Tar archive (.tgz / .tar.gz / .tar)
	if strings.HasSuffix(base, ".tgz") || strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tar") {
		return x.ingestDonorTar(path)
	}

	// Standard directory or zip delegation to qualcomm donor parsing
	return qualcomm{}.IngestDonor(path)
}

func (xiaomi) ingestDonorTar(tarPath string) (*blankflash.Donor, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tr *tar.Reader
	if strings.HasSuffix(strings.ToLower(tarPath), ".tar") {
		tr = tar.NewReader(f)
	} else {
		gzr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("opening gzip stream: %w", err)
		}
		defer gzr.Close()
		tr = tar.NewReader(gzr)
	}

	var progData []byte
	var progName string
	recipes := map[string][]byte{}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			continue
		}
		fn := filepath.Base(hdr.Name)

		// 1. Content inspection
		if isRawProgramContent(b) {
			recipes[fn] = b
		}
		if isFirehoseContent(b) && progData == nil {
			progData = b
			progName = fn
		}

		// 2. Fallback to filename matching if not identified by content
		if progData == nil && isQualcommDonorName(fn) {
			progData = b
			progName = fn
		}
		if strings.HasPrefix(fn, "rawprogram") && strings.HasSuffix(fn, ".xml") && recipes[fn] == nil {
			recipes[fn] = b
		}
	}

	if progData == nil {
		return nil, fmt.Errorf("no Firehose programmer found in archive %s", tarPath)
	}

	return &blankflash.Donor{
		Programmer: progData,
		Recipes:    recipes,
		Storage:    inferStorage(progName, progData),
		Source:     tarPath,
	}, nil
}

func (x xiaomi) HarvestStock(src TargetSource) (*blankflash.Target, error) {
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

	// 1. From Parts directory
	if src.Parts != "" {
		return x.harvestFromDirectory(src.Parts, slot, gpt)
	}

	// 2. From Bootloader archive or file
	if src.Bootloader == "" {
		return nil, fmt.Errorf("need --target-parts or --target-bootloader")
	}

	fi, err := os.Stat(src.Bootloader)
	if err != nil {
		return nil, err
	}

	if fi.IsDir() {
		return x.harvestFromDirectory(src.Bootloader, slot, gpt)
	}

	// 1. Content check on standalone file: check for CrAU payload magic
	if !fi.IsDir() && !strings.HasSuffix(strings.ToLower(src.Bootloader), ".zip") &&
		!strings.HasSuffix(strings.ToLower(src.Bootloader), ".tgz") &&
		!strings.HasSuffix(strings.ToLower(src.Bootloader), ".tar.gz") &&
		!strings.HasSuffix(strings.ToLower(src.Bootloader), ".tar") {
		f, err := os.Open(src.Bootloader)
		if err == nil {
			var magic [4]byte
			n, _ := io.ReadFull(f, magic[:])
			if n == 4 && string(magic[:]) == payload.HeaderMagic {
				p, err := payload.NewFromReaderAt(f, fi.Size())
				if err != nil {
					f.Close()
					return nil, fmt.Errorf("parsing payload: %w", err)
				}
				target, err := x.harvestFromPayload(p, slot, gpt)
				f.Close()
				return target, err
			}
			f.Close()
		}
	}

	base := strings.ToLower(filepath.Base(src.Bootloader))

	// If it's a standalone payload.bin (filename fallback)
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
		return x.harvestFromPayload(p, slot, gpt)
	}

	// If it's a .zip archive (could be recovery zip or OTA payload zip)
	if strings.HasSuffix(base, ".zip") {
		return x.harvestFromZip(src.Bootloader, slot, gpt)
	}

	// If it's a Fastboot tarball (.tgz / .tar.gz / .tar)
	if strings.HasSuffix(base, ".tgz") || strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tar") {
		return x.harvestFromTar(src.Bootloader, slot, gpt)
	}

	// Fallback to qualcomm driver
	return qualcomm{}.HarvestStock(src)
}

func (x xiaomi) harvestFromDirectory(dir string, slot string, gpt []byte) (*blankflash.Target, error) {
	// If directory contains "images" subfolder, prefer images/
	imagesDir := filepath.Join(dir, "images")
	if fi, err := os.Stat(imagesDir); err == nil && fi.IsDir() {
		dir = imagesDir
	}

	// 1. Content check for payload by scanning directory files for CrAU magic
	dirEntries, _ := os.ReadDir(dir)
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		p := filepath.Join(dir, de.Name())
		if f, err := os.Open(p); err == nil {
			var magic [4]byte
			n, _ := io.ReadFull(f, magic[:])
			if n == 4 && string(magic[:]) == payload.HeaderMagic {
				if fi, err := f.Stat(); err == nil {
					pld, err := payload.NewFromReaderAt(f, fi.Size())
					if err == nil {
						target, err := x.harvestFromPayload(pld, slot, gpt)
						f.Close()
						if err == nil {
							return target, nil
						}
					}
				}
			}
			f.Close()
		}
	}

	// 2. Last resort check for payload.bin filename
	payloadPath := filepath.Join(dir, "payload.bin")
	if fi, err := os.Stat(payloadPath); err == nil && !fi.IsDir() {
		f, err := os.Open(payloadPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		p, err := payload.NewFromReaderAt(f, fi.Size())
		if err != nil {
			return nil, fmt.Errorf("parsing payload.bin: %w", err)
		}
		return x.harvestFromPayload(p, slot, gpt)
	}

	// If directory contains firmware-update/, resolve aliases
	fwDir := filepath.Join(dir, "firmware-update")
	targetDir := dir
	if fi, err := os.Stat(fwDir); err == nil && fi.IsDir() {
		targetDir = fwDir
	}

	// Check for rawprogram0.xml
	rpPath := filepath.Join(targetDir, "rawprogram0.xml")
	var rawProgEntries []qfil.ProgramEntry
	if rpData, err := os.ReadFile(rpPath); err == nil {
		rawProgEntries, _ = qfil.ParseRawProgram(rpData)
	}

	// Build Target from files in targetDir
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return nil, err
	}

	files := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fn := e.Name()
		data, err := os.ReadFile(filepath.Join(targetDir, fn))
		if err != nil {
			continue
		}

		// Direct name match or alias translation
		canon := canonicalPartitionName(fn)
		files[canon] = data
		files[fn] = data
	}

	// Auto-detect GPT if present in directory
	if gpt == nil {
		if b, ok := files["gpt_main0.bin"]; ok {
			gpt = b
		} else if b, ok := files["gpt_both0.bin"]; ok {
			gpt = b
		}
	}

	target := &blankflash.Target{
		GPT:    gpt,
		Parts:  files,
		Source: dir,
	}

	if len(rawProgEntries) > 0 {
		order := make([]string, 0, len(rawProgEntries))
		fmap := make(map[string]string, len(rawProgEntries))
		for _, e := range rawProgEntries {
			if e.Label == "PrimaryGPT" || e.Filename == "" {
				continue
			}
			clean := strings.TrimSuffix(strings.TrimSuffix(e.Label, "_a"), "_b")
			order = append(order, clean)
			fmap[clean] = e.Filename
		}
		target.FlashOrder = order
		target.FlashMap = fmap
	}

	return target, nil
}

func (x xiaomi) harvestFromPayload(p *payload.Payload, slot string, gpt []byte) (*blankflash.Target, error) {
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

func (x xiaomi) harvestFromZip(zipPath string, slot string, gpt []byte) (*blankflash.Target, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	// Check if this zip has a payload.bin
	for _, f := range zr.File {
		if f.Name == "payload.bin" {
			p, closer, err := payload.OpenZip(zipPath)
			if err != nil {
				return nil, err
			}
			defer closer.Close()
			return x.harvestFromPayload(p, slot, gpt)
		}
	}

	// Otherwise, scan zip entries for firmware-update/ or images/
	files := make(map[string][]byte)
	var rawProgData []byte

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		fn := filepath.Base(f.Name)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		if fn == "rawprogram0.xml" {
			rawProgData = b
		}

		canon := canonicalPartitionName(fn)
		files[canon] = b
		files[fn] = b
	}

	if gpt == nil {
		if b, ok := files["gpt_main0.bin"]; ok {
			gpt = b
		}
	}

	target := &blankflash.Target{
		GPT:    gpt,
		Parts:  files,
		Source: zipPath,
	}

	if len(rawProgData) > 0 {
		if entries, err := qfil.ParseRawProgram(rawProgData); err == nil {
			order := make([]string, 0, len(entries))
			fmap := make(map[string]string, len(entries))
			for _, e := range entries {
				if e.Label == "PrimaryGPT" || e.Filename == "" {
					continue
				}
				clean := strings.TrimSuffix(strings.TrimSuffix(e.Label, "_a"), "_b")
				order = append(order, clean)
				fmap[clean] = e.Filename
			}
			target.FlashOrder = order
			target.FlashMap = fmap
		}
	}

	return target, nil
}

func (x xiaomi) harvestFromTar(tarPath string, slot string, gpt []byte) (*blankflash.Target, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tr *tar.Reader
	if strings.HasSuffix(strings.ToLower(tarPath), ".tar") {
		tr = tar.NewReader(f)
	} else {
		gzr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gzr.Close()
		tr = tar.NewReader(gzr)
	}

	files := make(map[string][]byte)
	var rawProgData []byte

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		fn := filepath.Base(hdr.Name)
		b, err := io.ReadAll(tr)
		if err != nil {
			continue
		}

		if fn == "rawprogram0.xml" {
			rawProgData = b
		}

		canon := canonicalPartitionName(fn)
		files[canon] = b
		files[fn] = b
	}

	if gpt == nil {
		if b, ok := files["gpt_main0.bin"]; ok {
			gpt = b
		}
	}

	target := &blankflash.Target{
		GPT:    gpt,
		Parts:  files,
		Source: tarPath,
	}

	if len(rawProgData) > 0 {
		if entries, err := qfil.ParseRawProgram(rawProgData); err == nil {
			order := make([]string, 0, len(entries))
			fmap := make(map[string]string, len(entries))
			for _, e := range entries {
				if e.Label == "PrimaryGPT" || e.Filename == "" {
					continue
				}
				clean := strings.TrimSuffix(strings.TrimSuffix(e.Label, "_a"), "_b")
				order = append(order, clean)
				fmap[clean] = e.Filename
			}
			target.FlashOrder = order
			target.FlashMap = fmap
		}
	}

	return target, nil
}

// canonicalPartitionName translates filenames (including extensions and Xiaomi aliases)
// into clean partition identifiers.
func canonicalPartitionName(filename string) string {
	base := filepath.Base(filename)
	if mapped, ok := xiaomiAliases[base]; ok {
		return mapped
	}
	// Strip known firmware image extensions
	lower := strings.ToLower(base)
	for _, ext := range []string{".img", ".bin", ".elf", ".mbn"} {
		if strings.HasSuffix(lower, ext) {
			return strings.TrimSuffix(lower, ext)
		}
	}
	return lower
}

func (xiaomi) Assemble(d *blankflash.Donor, t *blankflash.Target, opts AssembleOptions) (*blankflash.ForgeResult, error) {
	return qfil.Assemble(d, t, qfil.AssembleOptions{
		Slot:      opts.Slot,
		Storage:   opts.Storage,
		Provision: opts.Provision,
	})
}
