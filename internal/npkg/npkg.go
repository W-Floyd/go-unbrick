// Package npkg reads Hyundai Mobis's "PRNM" navigation data package: a small
// header naming one or more sections, each a contiguous byte range of the file,
// back to back with no gap, covering it exactly to EOF. Confirmed against six
// real samples (both the single-section and two-section shapes) from a kia-ev6
// sw_backup.tar: the header's own declared offsets and sizes land exactly on the
// file's true length in every case, not just inferred from field positions.
//
//	0x00  "PRNM"
//	0x04  u32 version (1000 on every sample seen)
//	0x08  u32 section count N
//	0x0C  [20]byte build timestamp, NUL-padded ASCII "YYYY/MM/DD HH:MM:SS"
//	0x20  N × { u32 tag, u32 offset, u32 size } -- offset is absolute in the
//	      file; tag is a per-role identifier (the same value across every
//	      sample's first section, a different shared value across every
//	      sample's second section), not a per-file content hash
//
// Each section's own bytes start with their own magic ("RLNM" seen on a
// single-section file, "RINM" on a two-section file) and a further structured
// body that is not decoded here -- see the package doc for what is confirmed
// and what remains unknown.
package npkg

import (
	"encoding/binary"
	"fmt"
)

const (
	magic         = "PRNM"
	fixedHdrSize  = 0x20 // magic + version + count + timestamp
	sectionStride = 12   // tag, offset, size
)

// Section is one contiguous byte range the header names.
type Section struct {
	Tag          uint32 // a per-role identifier, not a content hash (see package doc)
	Offset, Size uint32 // absolute in the file
}

// Package is a parsed PRNM header.
type Package struct {
	Version   uint32
	Timestamp string // "YYYY/MM/DD HH:MM:SS", as stored
	Sections  []Section
	HeaderEnd uint32 // byte offset the first section starts at
}

// Is reports whether head begins a PRNM package (head must cover at least the
// fixed part of the header: 0x20 bytes).
func Is(head []byte) bool {
	return len(head) >= fixedHdrSize && string(head[:4]) == magic
}

// Parse reads a PRNM header. It does not require the sections' own bytes to be
// present; size need only cover the header itself. ok is false if the magic
// doesn't match, the header is truncated, or the sections don't exactly tile
// [HeaderEnd, size) with no gap or overlap -- the one structural invariant
// confirmed across every real sample, and worth checking rather than trusting
// a file that merely starts with the right magic.
func Parse(head []byte, size int64) (*Package, error) {
	if !Is(head) {
		return nil, fmt.Errorf("npkg: not a PRNM package")
	}
	version := binary.LittleEndian.Uint32(head[4:8])
	count := binary.LittleEndian.Uint32(head[8:12])
	hdrEnd := fixedHdrSize + count*sectionStride
	if uint64(hdrEnd) > uint64(len(head)) {
		return nil, fmt.Errorf("npkg: header truncated (%d section(s) need %d bytes, have %d)", count, hdrEnd, len(head))
	}
	ts := string(head[0x0C:0x20])
	if i := indexByte(ts, 0); i >= 0 {
		ts = ts[:i]
	}
	p := &Package{Version: version, Timestamp: ts, HeaderEnd: hdrEnd}
	off := fixedHdrSize
	for i := uint32(0); i < count; i++ {
		s := Section{
			Tag:    binary.LittleEndian.Uint32(head[off : off+4]),
			Offset: binary.LittleEndian.Uint32(head[off+4 : off+8]),
			Size:   binary.LittleEndian.Uint32(head[off+8 : off+12]),
		}
		p.Sections = append(p.Sections, s)
		off += sectionStride
	}
	if err := p.validate(size); err != nil {
		return nil, err
	}
	return p, nil
}

// validate checks the one invariant confirmed across every real sample: the
// sections, in header order, exactly tile [HeaderEnd, size) -- no gap, no
// overlap, nothing left over.
func (p *Package) validate(size int64) error {
	want := int64(p.HeaderEnd)
	for i, s := range p.Sections {
		if int64(s.Offset) != want {
			return fmt.Errorf("npkg: section %d offset %d, want %d (sections must be contiguous from the header end)", i, s.Offset, want)
		}
		want += int64(s.Size)
	}
	if size > 0 && want != size {
		return fmt.Errorf("npkg: sections cover %d bytes, file is %d", want, size)
	}
	return nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// Summary is a one-line description: version, build date, section count.
func (p *Package) Summary() string {
	n := "section"
	if len(p.Sections) != 1 {
		n += "s"
	}
	return fmt.Sprintf("PRNM v%d, built %s, %d %s", p.Version, p.Timestamp, len(p.Sections), n)
}

// Report is Summary plus one line per section: its byte range and tag. The tag
// is shown as-is because its meaning isn't decoded yet (see the package doc) --
// it is confirmed to be a per-role identifier, not a content hash (the same
// value recurs across every sample's section in the same role), but which role
// is which remains unknown.
func (p *Package) Report() []string {
	out := []string{p.Summary()}
	for i, s := range p.Sections {
		out = append(out, fmt.Sprintf("  section %d: 0x%08x-0x%08x (%d bytes), tag 0x%08x", i, s.Offset, s.Offset+s.Size, s.Size, s.Tag))
	}
	return out
}
