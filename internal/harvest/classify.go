package harvest

import (
	"bytes"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go-unbrick/internal/blankflash"
)

var loaderExts = map[string]bool{".elf": true, ".mbn": true, ".bin": true, ".melf": true, ".hex": true}

var archiveExts = map[string]bool{".zip": true, ".rar": true, ".7z": true, ".tar": true,
	".gz": true, ".tgz": true, ".bz2": true, ".xz": true}

var (
	elfMagic = []byte("\x7fELF")
	// Qualcomm SBL/MBN header codeword pair (the 80-byte header).
	mbnMagic = []byte("\xd1\xdc\x4b\x84\x34\x10\xd7\x73")
)

// A signed loader lands around 5.5 bits/byte; anything near 8.0 is encrypted or
// compressed — these repos carry a lot of it under loader filenames.
const opaqueEntropy = 7.9

// looksLikeLoader: extension alone is unreliable (repos ship loaders with no
// extension and READMEs named .bin), so an extensionless file needs ELF magic.
func looksLikeLoader(path string, size, minSize, maxSize int64) bool {
	if size < minSize || size > maxSize {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if loaderExts[ext] {
		return true
	}
	if ext != "" {
		return false
	}
	head, err := readHead(path, 4)
	return err == nil && bytes.Equal(head, elfMagic)
}

func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	m, err := io.ReadFull(f, b)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return b[:m], nil
}

// repairMagic undoes sellers neutering a loader by flipping one magic byte
// (\x7fELE for \x7fELF, d1dc4b87 for the MBN codeword): everything after it
// still validates, so the file is a working loader one byte away. Returns the
// offset and corrected byte.
func repairMagic(head []byte) (int, byte, bool) {
	if len(head) < 8 {
		return 0, 0, false
	}
	if bytes.Equal(head[:3], []byte("\x7fEL")) && head[3] != 'F' &&
		(head[4] == 1 || head[4] == 2) && (head[5] == 1 || head[5] == 2) && head[6] == 1 {
		return 3, 'F', true
	}
	if bytes.Equal(head[:3], []byte("\xd1\xdcK")) && head[3] != 0x84 && bytes.Equal(head[4:8], mbnMagic[4:]) {
		return 3, 0x84, true
	}
	return 0, 0, false
}

// classifyImage is ELF32, ELF64, MBN, OPAQUE (encrypted/compressed) or UNKNOWN.
// Classifying by "not ELF" once produced a manifest of mislabelled MBNs: in
// thantoeaungat/firehose 110 of 113 such files were opaque blobs.
func classifyImage(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	body := make([]byte, 1<<20)
	n, _ := io.ReadFull(f, body)
	body = body[:n]
	head := append([]byte(nil), body[:min(8, n)]...)
	if off, b, ok := repairMagic(head); ok {
		head[off] = b
	}
	switch {
	case bytes.HasPrefix(head, elfMagic) && len(head) > 4:
		if head[4] == 2 {
			return "ELF64"
		}
		return "ELF32"
	case bytes.Equal(head, mbnMagic):
		return "MBN"
	case entropy(body) > opaqueEntropy:
		return "OPAQUE"
	}
	return "UNKNOWN"
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// loaderName: a loader's filename, unlike a boot-chain image's, names the
// programmer. Counting these keeps a firmware tree (hundreds of boot images,
// zero loaders) from looking like a rich source.
var loaderName = regexp.MustCompile(`(?i)(firehose|programmer|prog_emmc|prog_ufs|[mn]prg|enprg|fhprg|fhloader|blankflash|singleimage)`)

// firehoseMarkers is protocol vocabulary a programmer embeds as plaintext and a
// boot-chain image (xbl/abl/tz/aop/gpt) does not.
var firehoseMarkers = [][]byte{[]byte("MaxPayloadSizeToTarget"), []byte("NUM_DISK_SECTORS"),
	[]byte("rawmode"), []byte("<configure"), []byte("<program "), []byte("firehose"), []byte("Firehose")}

// isFirehoseLoader: loader-named files pass by name; a device-named loader
// (ZUK.mbn) passes by carrying the Firehose XML vocabulary.
func isFirehoseLoader(path string) bool {
	if loaderName.MatchString(filepath.Base(path)) {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, m := range firehoseMarkers {
		if bytes.Contains(data, m) {
			return true
		}
	}
	return false
}

// singleimageLoader: only the programmer record of a SINGLE_N_LONELY container
// is a loader; the rest is the signed boot chain.
var singleimageLoader = regexp.MustCompile(`(?i)^(prog|programmer).*\.(elf|mbn)$`)

// expandSingleimages carves the programmer out of each Motorola singleimage.bin
// under root into a <name>.programmer.elf sidecar the scan picks up. Idempotent.
func expandSingleimages(root string) int {
	written := 0
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".programmer.elf") {
			return nil
		}
		head, err := readHead(p, len(blankflash.Magic))
		if err != nil || !bytes.Equal(head, blankflash.Magic) {
			return nil
		}
		sidecar := p + ".programmer.elf"
		if _, err := os.Stat(sidecar); err == nil {
			return nil
		}
		blob, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		recs, err := blankflash.Parse(blob)
		if err != nil {
			return nil
		}
		for _, r := range recs {
			if singleimageLoader.MatchString(r.Name) {
				if os.WriteFile(sidecar, r.Data, 0o644) == nil {
					written++
				}
				break
			}
		}
		return nil
	})
	return written
}
