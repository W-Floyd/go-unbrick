package telechips

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Layout of the older "ANDROID@TCSBLBS_" bootloader image (lk.rom), confirmed
// byte-for-byte against a real decrypted Telechips TCC803x image, not
// inferred from strings alone -- see the kia-ev6 repo's 64BIT.md ("Resolved:
// the EL3 blob's real base" onward) for the reverse-engineering trail that
// found this.
//
//	0x00   "ANDROID@TCSBLBS_"
//	0x18   version tag, e.g. "V7  803X"
//	0x20   9 (offset uint64, size uint64) pairs, little-endian -- NOT
//	       necessarily in file order (a later table slot can name an earlier
//	       byte range than one before it), but together they tile every byte
//	       from 0x200 to EOF with no gaps and no overlaps: sorted by offset,
//	       entry[i].Offset+entry[i].Size == entry[i+1].Offset, and the last
//	       entry ends exactly at EOF. The first 0x200 bytes (this header plus
//	       the table itself) aren't named by any entry.
//
// Known components, by what's actually been found in each range on real
// images (not guaranteed present on every variant -- this is one shipped
// chip's firmware, not a spec): a small block, BL1 (ARM32, tagged
// "BL1C@..." near its own start), a header/signature block, an AArch64 EL3
// secure monitor, "LK proper" (ARM32), a few more small blocks, and a
// trailing image with its own distinct header (a `b` instruction then a
// "Ver:..." tag) -- large enough on known samples to be a second, separately
// linked payload (OP-TEE core has been found inside it), not padding.
// LKROMVersion is this LKROM codec's current behavior version, for
// pkg/analysis/cache: raise it whenever parsing changes in a way that could
// change what is reported for bytes already seen. Scoped to this file, not
// the whole telechips package, which also parses the boot-stage wrapper
// (telechips.go) and other things cache.Versions tracks separately.
const LKROMVersion = 1

const (
	lkromMagic      = "ANDROID@"
	lkromTableOff   = 0x20
	lkromEntryCount = 9
	lkromEntrySize  = 16 // one (uint64 offset, uint64 size) pair
	lkromHeaderSize = 0x200
)

// LKROMEntry is one of the 9 (offset, size) pairs the table at file 0x20
// names, in the order they appear in the table (not sorted by offset -- see
// LKROM.Sorted for that).
type LKROMEntry struct {
	Offset, Size uint64
	TableIndex   int // 0-8: this entry's slot in the on-disk table
	Tag          string // a short printable-ASCII run found at this entry's own start, if any (e.g. "BL1C@TCC803X", "Ver:LB__") -- empty if none
}

// LKROM is a parsed "ANDROID@TCSBLBS_" image: the version tag and the 9
// table entries.
type LKROM struct {
	VersionTag string
	Entries    []LKROMEntry // table order; use Sorted() for byte order
}

// IsLKROM reports whether head begins an "ANDROID@..." LK ROM image (head
// must cover at least the fixed header and table: 0x20+9*16 = 0xb0 bytes).
func IsLKROM(head []byte) bool {
	return len(head) >= lkromTableOff+lkromEntryCount*lkromEntrySize && bytes.HasPrefix(head, []byte(lkromMagic))
}

// ParseLKROM reads the whole header+table, and tags each entry from its own
// first bytes within data (data must cover the real file, not just a head
// buffer, for the tags to be found -- the table alone needs only 0xb0 bytes,
// but Size at trailing-image length means Entries past the header need the
// file itself to peek at).
func ParseLKROM(data []byte) (*LKROM, error) {
	if !IsLKROM(data) {
		return nil, errors.New("telechips: not an LK ROM image")
	}
	le := binary.LittleEndian
	lk := &LKROM{VersionTag: cstr(data[0x18:lkromTableOff])}
	for i := 0; i < lkromEntryCount; i++ {
		off := lkromTableOff + i*lkromEntrySize
		e := LKROMEntry{
			Offset:     le.Uint64(data[off:]),
			Size:       le.Uint64(data[off+8:]),
			TableIndex: i,
		}
		if int(e.Offset) < len(data) {
			end := int(e.Offset) + lkromTagScanWindow
			if end > len(data) {
				end = len(data)
			}
			e.Tag = findTag(data[e.Offset:end])
		}
		lk.Entries = append(lk.Entries, e)
	}
	return lk, nil
}

// lkromTagScanWindow is how far into each entry findTag looks: a region's own
// identifying tag isn't always its first bytes -- BL1's "BL1C@..." tag sits
// after a real ARM32 exception vector table, not at its region's start.
const lkromTagScanWindow = 256

// findTag is the first run of printable ASCII (len >= minTagLen, embedded
// single NULs allowed so a NUL-padded fixed-width tag like
// "BL1C@TCC803X\0\0\0\0" still reads as one run) found anywhere in b, trimmed
// of trailing NULs. A run has to START with a genuinely printable byte, not
// a NUL -- otherwise a stretch of zero-padding with one incidental printable
// byte nearby reads as a false tag (seen in practice: an all-but-one-byte-
// NUL region scoring a "tag" of mostly garbage).
const minTagLen = 4

func findTag(b []byte) string {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 || b[i] < 0x20 || b[i] >= 0x7f {
			continue
		}
		// A continuous printable run, then OPTIONALLY trailing NUL padding --
		// never printable-NUL-printable interleaved. Binary code/data
		// regions routinely have isolated zero bytes between otherwise
		// unrelated printable-looking bytes; letting a single NUL "bridge"
		// back into more printable content (an earlier version of this
		// function did, to handle NUL-padded tags) matched that kind of
		// noise as a false tag just as often as it matched a real one.
		n := i
		for n < len(b) && b[n] >= 0x20 && b[n] < 0x7f {
			n++
		}
		if n-i >= minTagLen {
			return string(b[i:n])
		}
		for n < len(b) && b[n] == 0 {
			n++
		}
		i = n - 1 // the loop's i++ advances past the padding
	}
	return ""
}

// printableHead is the longest run of printable ASCII (or embedded single
// NULs, so a NUL-padded fixed-width tag like "BL1C@TCC803X\0\0\0\0" still
// reads as one tag) starting at b[0], trimmed of trailing NULs. Kept for
// VersionTag, which genuinely is at a fixed offset from the start of data.
func printableHead(b []byte) string {
	n := 0
	for n < len(b) && (b[n] == 0 || b[n] >= 0x20 && b[n] < 0x7f) {
		n++
	}
	return string(bytes.TrimRight(b[:n], "\x00"))
}

// Sorted is the 9 entries ordered by Offset -- the byte-range order, which
// is how the table tiles the file even though its own on-disk order can
// differ (see the package doc comment).
func (lk *LKROM) Sorted() []LKROMEntry {
	out := append([]LKROMEntry(nil), lk.Entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// Contiguous reports whether the sorted entries tile the file with no gaps
// or overlaps from the first entry's offset to the last entry's end -- the
// invariant found on every real image seen so far. False is worth surfacing
// to whoever's reading a report, not silently working around: it means
// either this image differs from what's documented, or the table was read
// wrong.
func (lk *LKROM) Contiguous() bool {
	s := lk.Sorted()
	for i := 1; i < len(s); i++ {
		if s[i-1].Offset+s[i-1].Size != s[i].Offset {
			return false
		}
	}
	return true
}

// Report is what recon says about a whole LK ROM image, as lines.
func (lk *LKROM) Report() []string {
	out := []string{fmt.Sprintf("LK ROM: version tag %q, %d table entries", lk.VersionTag, len(lk.Entries))}
	if !lk.Contiguous() {
		out = append(out, "WARNING: table entries don't tile the file contiguously -- this image may differ from what's documented")
	}
	for _, e := range lk.Sorted() {
		line := fmt.Sprintf("  0x%06x-0x%06x (%d bytes, table slot %d)", e.Offset, e.Offset+e.Size, e.Size, e.TableIndex)
		if e.Tag != "" {
			line += fmt.Sprintf("  tag %q", e.Tag)
		}
		out = append(out, line)
	}
	return out
}
