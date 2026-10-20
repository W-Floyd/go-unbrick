package analysis

import (
	"time"
	"unicode/utf8"

	"github.com/sergi/go-diff/diffmatchpatch"
)

// exactMax is the size up to which two similar files are measured byte for byte
// rather than in chunks. A chunk with any changed byte counts as unique whole,
// which for a small file is most of it; and byte for byte is affordable there.
const exactMax = 64 << 10

// cellMap accumulates, along a file of size bytes, how much of each of Buckets
// stretches is shared.
type cellMap struct {
	size          int
	shared, total []float64
	bytes         int64 // shared bytes in all
}

func newCellMap(size int) *cellMap {
	return &cellMap{size: size, shared: make([]float64, Buckets), total: make([]float64, Buckets)}
}

// add records that bytes [start, start+n) are, or are not, shared. A range may
// straddle cells; its bytes are apportioned.
func (c *cellMap) add(start, n int, isShared bool) {
	if isShared {
		c.bytes += int64(n)
	}
	for pos := start; pos < start+n; {
		cell := min(pos*Buckets/c.size, Buckets-1)
		end := min((cell+1)*c.size/Buckets+1, start+n)
		if end <= pos {
			end = pos + 1
		}
		w := float64(end - pos)
		c.total[cell] += w
		if isShared {
			c.shared[cell] += w
		}
		pos = end
	}
}

// result is the fraction shared in each cell, and the shared bytes.
func (c *cellMap) result() ([]float64, int64) {
	m := make([]float64, Buckets)
	for i := range m {
		if c.total[i] > 0 {
			m[i] = c.shared[i] / c.total[i]
		}
	}
	return m, c.bytes
}

// asRunes makes every byte one character, so a diff of the strings is a diff of
// the bytes whatever they are.
func asRunes(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// exactOverlap is Compare's measure taken byte for byte: the stretches a and b
// have in common, in order, as a minimal edit script finds them. ok is false if
// there is no size to measure.
func exactOverlap(a, b []byte) (ma, mb []float64, sharedA, sharedB int64, ok bool) {
	if len(a) == 0 || len(b) == 0 {
		return nil, nil, 0, 0, false
	}
	dmp := diffmatchpatch.New()
	dmp.DiffTimeout = time.Second // beyond it the diff is rougher, still a diff
	diffs := dmp.DiffMain(asRunes(a), asRunes(b), false)
	ca, cb := newCellMap(len(a)), newCellMap(len(b))
	ia, ib := 0, 0
	for _, d := range diffs {
		n := utf8.RuneCountInString(d.Text)
		switch d.Type {
		case diffmatchpatch.DiffEqual:
			ca.add(ia, n, true)
			cb.add(ib, n, true)
			ia, ib = ia+n, ib+n
		case diffmatchpatch.DiffDelete:
			ca.add(ia, n, false)
			ia += n
		case diffmatchpatch.DiffInsert:
			cb.add(ib, n, false)
			ib += n
		}
	}
	ma, sharedA = ca.result()
	mb, sharedB = cb.result()
	return ma, mb, sharedA, sharedB, true
}
