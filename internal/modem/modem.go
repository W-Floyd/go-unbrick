// Package modem reads files out of a Motorola/Qualcomm modem image. The chain a
// stock package ships is radio.img → NON-HLOS.bin → ext4, i.e.:
//
//	radio.img     SINGLE_N_LONELY container (modem=NON-HLOS.bin, fsg=fsg.mbn)
//	NON-HLOS.bin  Android sparse image
//	(decoded)     ext4 filesystem — the modem's /image directory (mcfg_hw.mbn, …)
//
// Resolve accepts an image at any layer and peels down to the ext4 bytes; List
// and Extract then read it in pure Go (no mount, no privilege).
package modem

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	ext4 "github.com/dsoprea/go-ext4"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/sparse"
)

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
	if !isExt4(raw) {
		return nil, fmt.Errorf("modem: resolved image is not ext4 (unsupported modem filesystem)")
	}
	return raw, nil
}

// Entry is one regular file in the modem filesystem.
type Entry struct {
	Path string
	Size uint64
}

func openExt4(raw []byte) (*ext4.BlockGroupDescriptorList, *bytes.Reader, error) {
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
		return nil, fmt.Errorf("modem: %q not found", name)
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
