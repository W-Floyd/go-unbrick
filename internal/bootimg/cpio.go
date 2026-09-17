package bootimg

import (
	"fmt"
	"strconv"
	"strings"
)

// CpioEntry is one file/dir/symlink from a newc-format cpio (an Android ramdisk).
type CpioEntry struct {
	Name   string
	Mode   uint32
	Size   uint32
	Data   []byte // regular-file contents; symlink target for a link
	IsDir  bool
	IsLink bool
	LinkTo string // symlink target
	IsReg  bool
}

// The "new ASCII" (newc) cpio header: magic "070701" then 13 eight-hex fields,
// name follows, name and data each padded to a 4-byte boundary. The archive ends
// with an entry named "TRAILER!!!".
const (
	cpioMagicNewc = "070701"
	cpioHdrLen    = 110 // 6 magic + 13*8
	sIFMT         = 0o170000
	sIFDIR        = 0o040000
	sIFLNK        = 0o120000
	sIFREG        = 0o100000
)

// ParseCpio walks a decompressed newc cpio, returning its entries in archive
// order. It stops at the TRAILER!!! sentinel and ignores anything after it (an
// Android ramdisk can concatenate several archives; ParseCpioConcat handles that).
func ParseCpio(b []byte) ([]CpioEntry, error) {
	entries, _, err := parseCpioOnce(b)
	return entries, err
}

// ParseCpioConcat parses one or more cpio archives laid end to end — Android
// concatenates a ramdisk's fragments this way — merging their entries in order.
func ParseCpioConcat(b []byte) ([]CpioEntry, error) {
	var all []CpioEntry
	for len(b) >= cpioHdrLen && string(b[:6]) == cpioMagicNewc {
		entries, consumed, err := parseCpioOnce(b)
		if err != nil {
			return all, err
		}
		all = append(all, entries...)
		// Advance past this archive, skipping the zero padding cpio puts between
		// concatenated members.
		b = b[consumed:]
		for len(b) > 0 && b[0] == 0 {
			b = b[1:]
		}
	}
	return all, nil
}

func parseCpioOnce(b []byte) ([]CpioEntry, int, error) {
	var out []CpioEntry
	off := 0
	for {
		if off+cpioHdrLen > len(b) {
			return out, off, fmt.Errorf("cpio truncated at header (offset %d)", off)
		}
		if string(b[off:off+6]) != cpioMagicNewc {
			return out, off, fmt.Errorf("bad cpio magic at offset %d: %q", off, b[off:off+6])
		}
		f := func(i int) uint32 { return hex8(b, off+6+i*8) }
		mode := f(1)
		nameSize := f(11)
		dataSize := f(6)

		nameOff := off + cpioHdrLen
		if nameOff+int(nameSize) > len(b) {
			return out, off, fmt.Errorf("cpio name runs past end at offset %d", off)
		}
		name := strings.TrimRight(string(b[nameOff:nameOff+int(nameSize)]), "\x00")
		dataOff := align4(nameOff + int(nameSize))
		if dataOff+int(dataSize) > len(b) {
			return out, off, fmt.Errorf("cpio data runs past end for %q", name)
		}
		data := b[dataOff : dataOff+int(dataSize)]
		next := align4(dataOff + int(dataSize))

		if name == "TRAILER!!!" {
			return out, next, nil
		}

		e := CpioEntry{Name: name, Mode: mode, Size: dataSize}
		switch mode & sIFMT {
		case sIFDIR:
			e.IsDir = true
		case sIFLNK:
			e.IsLink = true
			e.LinkTo = string(data)
		case sIFREG:
			e.IsReg = true
			e.Data = append([]byte(nil), data...)
		default:
			// device nodes, fifos: keep the record, drop the (empty) body.
		}
		out = append(out, e)
		off = next
	}
}

// Find returns the first entry whose path ends in the given base name (e.g.
// "fastbootd"), or a full-path match. Ramdisk paths have no leading slash.
func Find(entries []CpioEntry, name string) (CpioEntry, bool) {
	name = strings.TrimPrefix(name, "/")
	for _, e := range entries {
		if e.Name == name || pathBase(e.Name) == name {
			return e, true
		}
	}
	return CpioEntry{}, false
}

func hex8(b []byte, off int) uint32 {
	if off+8 > len(b) {
		return 0
	}
	n, err := strconv.ParseUint(string(b[off:off+8]), 16, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func align4(n int) int {
	if r := n % 4; r != 0 {
		return n + (4 - r)
	}
	return n
}

func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
