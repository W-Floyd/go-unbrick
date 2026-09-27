// Package modem reads files out of a Motorola/Qualcomm modem image. The chain a
// stock package ships is radio.img → NON-HLOS.bin → ext4, i.e.:
//
//	radio.img     SINGLE_N_LONELY container (modem=NON-HLOS.bin, fsg=fsg.mbn)
//	NON-HLOS.bin  Android sparse image
//	(decoded)     ext4 filesystem — the modem's /image directory (mcfg_hw.mbn, …)
//
// Resolve accepts an image at any layer and peels down to the ext4 bytes (or
// FAT, the layout Qualcomm reference builds ship); List and Extract then read it
// in pure Go (no mount, no privilege).
package modem

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	ext4 "github.com/dsoprea/go-ext4"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/bootelf"
	"go-unbrick/internal/sparse"
)

// ErrNotFound is returned (wrapped) by Extract when no file matches.
var ErrNotFound = errors.New("not found")

// JoinSplit joins the PIL split image named by mdt (a path or suffix, as for
// Extract) with the .bNN files beside it into one ELF. missing lists segments
// with no .bNN, zero-filled in the result.
func JoinSplit(img []byte, mdt string) (joined []byte, missing []int, err error) {
	raw, err := Resolve(img) // once, not per segment
	if err != nil {
		return nil, nil, err
	}
	head, err := Extract(raw, mdt)
	if err != nil {
		return nil, nil, err
	}
	stem := strings.TrimSuffix(mdt, path.Ext(mdt))
	return bootelf.JoinSplit(head, func(i int) []byte {
		b, _ := Extract(raw, fmt.Sprintf("%s.b%02d", stem, i))
		return b
	})
}

// ext4 superblock magic 0xEF53, at byte 0x38 of the superblock (which is at 1024).
const ext4MagicOff = 1024 + 0x38

func isExt4(b []byte) bool {
	return len(b) > ext4MagicOff+2 && binary.LittleEndian.Uint16(b[ext4MagicOff:ext4MagicOff+2]) == 0xEF53
}

// Resolve peels a modem image down to its ext4 bytes, accepting a SINGLE_N_LONELY
// radio.img, a (sparse or raw) NON-HLOS.bin, or the ext4 image itself.
func Resolve(img []byte) ([]byte, error) {
	if bytes.HasPrefix(img, blankflash.Magic) {
		recs, err := blankflash.Parse(img)
		if err != nil {
			return nil, err
		}
		var modem []byte
		for _, r := range recs {
			if r.Name == "NON-HLOS.bin" || r.Name == "modem" {
				modem = r.Data
				break
			}
		}
		if modem == nil {
			return nil, fmt.Errorf("modem: no NON-HLOS.bin in SINGLE_N_LONELY container")
		}
		img = modem
	}
	raw, err := sparse.Decode(img)
	if err != nil {
		return nil, err
	}
	if !isExt4(raw) && !isFAT(raw) {
		return nil, fmt.Errorf("modem: resolved image is neither ext4 nor FAT (unsupported modem filesystem)")
	}
	return raw, nil
}

// Entry is one regular file in the modem filesystem.
type Entry struct {
	Path string
	Size uint64
}

// ext4 superblock s_feature_incompat is a u32 LE at offset 0x60; INCOMPAT_FLEX_BG
// is bit 0x200.
const (
	ext4FeatIncompatOff = 1024 + 0x60
	ext4FlexBG          = 0x200
)

// ensureFlexBg works around go-ext4's refusal to read a filesystem without the
// flex_bg incompat flag. The reader never actually depends on flex_bg — it locates
// each block group's inode table from that group's descriptor, which is correct
// with or without the flag; flex_bg only changes where those tables physically
// sit. Some Motorola partitions (dspso, a small single-group image) are built
// without it. Set the flag on a copy so the reader accepts them; nothing reads it
// back. Only a non-flex_bg image is copied, and those are the small ones.
func ensureFlexBg(raw []byte) []byte {
	if len(raw) < ext4FeatIncompatOff+4 {
		return raw
	}
	feat := binary.LittleEndian.Uint32(raw[ext4FeatIncompatOff:])
	if feat&ext4FlexBG != 0 {
		return raw
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	binary.LittleEndian.PutUint32(out[ext4FeatIncompatOff:], feat|ext4FlexBG)
	return out
}

func openExt4(raw []byte) (*ext4.BlockGroupDescriptorList, *bytes.Reader, error) {
	raw = ensureFlexBg(raw)
	r := bytes.NewReader(raw)
	if _, err := r.Seek(ext4.Superblock0Offset, io.SeekStart); err != nil {
		return nil, nil, err
	}
	sb, err := ext4.NewSuperblockWithReader(r)
	if err != nil {
		return nil, nil, err
	}
	bgdl, err := ext4.NewBlockGroupDescriptorListWithReadSeeker(r, sb)
	if err != nil {
		return nil, nil, err
	}
	return bgdl, r, nil
}

// List returns every regular file in the modem image, sorted by path.
func List(img []byte) ([]Entry, error) {
	raw, err := Resolve(img)
	if err != nil {
		return nil, err
	}
	if isFAT(raw) {
		return fatList(raw)
	}
	bgdl, r, err := openExt4(raw)
	if err != nil {
		return nil, err
	}
	root, err := bgdl.GetWithAbsoluteInode(ext4.InodeRootDirectory)
	if err != nil {
		return nil, err
	}
	dw, err := ext4.NewDirectoryWalk(r, root, ext4.InodeRootDirectory)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for {
		full, de, err := dw.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if !de.IsRegular() {
			continue
		}
		size := uint64(0)
		if bgd, err := bgdl.GetWithAbsoluteInode(int(de.Data().Inode)); err == nil {
			if in, err := ext4.NewInodeWithReadSeeker(bgd, r, int(de.Data().Inode)); err == nil {
				size = in.Size()
			}
		}
		out = append(out, Entry{Path: full, Size: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Extract returns the bytes of one file. name matches a full modem path exactly,
// or (for convenience) any file whose path ends in "/"+name; an ambiguous suffix
// is an error so a caller never silently gets the wrong file.
func Extract(img []byte, name string) ([]byte, error) {
	raw, err := Resolve(img)
	if err != nil {
		return nil, err
	}
	if isFAT(raw) {
		return fatExtract(raw, name)
	}
	bgdl, r, err := openExt4(raw)
	if err != nil {
		return nil, err
	}
	root, err := bgdl.GetWithAbsoluteInode(ext4.InodeRootDirectory)
	if err != nil {
		return nil, err
	}
	dw, err := ext4.NewDirectoryWalk(r, root, ext4.InodeRootDirectory)
	if err != nil {
		return nil, err
	}
	var match string
	var inode int
	for {
		full, de, err := dw.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if !de.IsRegular() {
			continue
		}
		if full == name || strings.HasSuffix(full, "/"+name) {
			if match != "" {
				return nil, fmt.Errorf("modem: %q is ambiguous (%s and %s); use a full path", name, match, full)
			}
			match, inode = full, int(de.Data().Inode)
		}
	}
	if match == "" {
		return nil, fmt.Errorf("modem: %q: %w", name, ErrNotFound)
	}
	bgd, err := bgdl.GetWithAbsoluteInode(inode)
	if err != nil {
		return nil, err
	}
	in, err := ext4.NewInodeWithReadSeeker(bgd, r, inode)
	if err != nil {
		return nil, err
	}
	en := ext4.NewExtentNavigatorWithReadSeeker(r, in)
	return io.ReadAll(ext4.NewInodeReader(en))
}

// mpssRe finds the modem's QC_IMAGE_VERSION_STRING (baseband/MPSS build), the
// authoritative firmware version stamped into the modem images.
var mpssRe = regexp.MustCompile(`QC_IMAGE_VERSION_STRING=(MPSS\.[!-~]+)`)

// Baseband returns the MPSS baseband version stamped in the modem image, or ""
// if none is present. It resolves the image to its ext4 bytes and scans them —
// the modem firmware ELFs inside carry the version string in the clear.
func Baseband(img []byte) string {
	raw, err := Resolve(img)
	if err != nil {
		return ""
	}
	if m := mpssRe.FindSubmatch(raw); m != nil {
		return string(m[1])
	}
	return ""
}
