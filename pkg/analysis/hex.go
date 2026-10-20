package analysis

import (
	"time"
	"unicode/utf8"

	"github.com/sergi/go-diff/diffmatchpatch"
)

// HexHunk is one stretch where two byte strings differ: [OffA, OffA+len(A)) of
// the one stands where [OffB, OffB+len(B)) of the other does. Either may be
// empty (a pure insertion or deletion).
type HexHunk struct {
	OffA, OffB int
	A, B       []byte
}

// Len is the bytes the hunk spans on its longer side.
func (h HexHunk) Len() int { return max(len(h.A), len(h.B)) }

// hexMerge is the run of equal bytes below which two hunks are shown as one.
const hexMerge = 8

// HexDiff finds where a and b differ, as a minimal edit script does: hunks in
// order, and the bytes they span in all. Two strings of equal size larger than
// exactMax are compared position by position, since a script is too dear; two of
// unequal size larger than that are not diffed (ok false).
func HexDiff(a, b []byte) (hunks []HexHunk, total int, ok bool) {
	if len(a) == len(b) && len(a) > exactMax {
		for i := 0; i < len(a); {
			if a[i] == b[i] {
				i++
				continue
			}
			j := i
			for j < len(a) && (a[j] != b[j] || gapDiffers(a, b, j)) {
				j++
			}
			hunks = append(hunks, HexHunk{i, i, a[i:j], b[i:j]})
			i = j
		}
		return hunks, sumLen(hunks), true
	}
	if len(a) > exactMax || len(b) > exactMax {
		return nil, 0, false
	}
	dmp := diffmatchpatch.New()
	dmp.DiffTimeout = time.Second
	ia, ib := 0, 0
	var cur *HexHunk
	// A short run of equal bytes between two changes joins them into one hunk (the
	// next change extends it across the run); after the last one it is left out.
	for _, d := range dmp.DiffMain(asRunes(a), asRunes(b), false) {
		n := utf8.RuneCountInString(d.Text)
		switch d.Type {
		case diffmatchpatch.DiffEqual:
			if cur != nil && n >= hexMerge {
				hunks = append(hunks, *cur)
				cur = nil
			}
			ia, ib = ia+n, ib+n
		default:
			if cur == nil {
				cur = &HexHunk{OffA: ia, OffB: ib}
			}
			if d.Type == diffmatchpatch.DiffDelete {
				ia += n
			} else {
				ib += n
			}
			cur.A = a[cur.OffA:ia]
			cur.B = b[cur.OffB:ib]
		}
	}
	if cur != nil {
		hunks = append(hunks, *cur)
	}
	return hunks, sumLen(hunks), true
}

// gapDiffers says whether the bytes just after j, up to hexMerge of them, hold
// another difference, so two close changes make one hunk.
func gapDiffers(a, b []byte, j int) bool {
	for k := j; k < len(a) && k < j+hexMerge; k++ {
		if a[k] != b[k] {
			return true
		}
	}
	return false
}

func sumLen(hs []HexHunk) int {
	n := 0
	for _, h := range hs {
		n += h.Len()
	}
	return n
}

// HexDiffOutsideStrings is HexDiff without the hunks that lie wholly in printable
// strings on both sides (see Residue): those are the strings diff's, and what is
// left is what changed in the binary around the text.
func HexDiffOutsideStrings(a, b []byte, min int) (hunks []HexHunk, total int, ok bool) {
	all, _, ok := HexDiff(a, b)
	if !ok {
		return nil, 0, false
	}
	ma, mb := stringMask(a, min), stringMask(b, min)
	inside := func(m []uint64, off, n int) bool {
		for i := off; i < off+n; i++ {
			if m[i/64]&(1<<(i%64)) == 0 {
				return false
			}
		}
		return true
	}
	for _, h := range all {
		if inside(ma, h.OffA, len(h.A)) && inside(mb, h.OffB, len(h.B)) {
			continue
		}
		hunks = append(hunks, h)
	}
	return hunks, sumLen(hunks), true
}
