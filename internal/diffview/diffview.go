// Package diffview analyses two byte strings for a person to read: a line diff
// for text, how much of two binaries is shared and how much is unique to each,
// and a diff of the printable strings inside binaries. It does no I/O and no
// drawing, so what the interactive diff shows can be tested.
package diffview

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sergi/go-diff/diffmatchpatch"
)

// IsText reports whether data reads as text: valid UTF-8 (a character cut off
// at the end excepted), no NUL, and almost no control characters.
func IsText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	head := data
	if len(head) > 64<<10 {
		head = head[:64<<10]
		// Do not call a character cut by the sample invalid.
		for i := 0; i < utf8.UTFMax && len(head) > 0 && !utf8.Valid(head); i++ {
			head = head[:len(head)-1]
		}
	}
	if !utf8.Valid(head) {
		return false
	}
	ctl := 0
	for _, b := range head {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' && b != '\f' {
			ctl++
		}
	}
	return ctl*50 < len(head) // under 2%
}

// Line is one line of a unified diff: ' ' unchanged, '-' only in a, '+' only in
// b, '@' a hunk header. A and B are the 1-based line numbers it has on each
// side, 0 where it has none.
type Line struct {
	Op   byte
	A, B int
	Text string
	Hi   [][2]int // byte ranges of Text that differ from its counterpart, when words are marked (MarkWords)
}

// Stats counts what a line diff found.
type Stats struct{ Added, Removed, Same int }

// MaxTextLines bounds a text diff; past it the diff is cut and says so.
const MaxTextLines = 20000

// TextDiff is a line diff of a and b with context unchanged lines around each
// change, as hunks. truncated is set when the output hit MaxTextLines.
func TextDiff(a, b []byte, context int) (lines []Line, st Stats, truncated bool) {
	all := lineDiff(string(a), string(b))
	for _, l := range all {
		switch l.Op {
		case '+':
			st.Added++
		case '-':
			st.Removed++
		default:
			st.Same++
		}
	}
	if st.Added+st.Removed == 0 {
		return nil, st, false
	}
	keep := make([]bool, len(all))
	for i, l := range all {
		if l.Op == ' ' {
			continue
		}
		for j := max(0, i-context); j <= min(len(all)-1, i+context); j++ {
			keep[j] = true
		}
	}
	inHunk := false
	for i, l := range all {
		if !keep[i] {
			inHunk = false
			continue
		}
		if !inHunk {
			inHunk = true
			// Count the lines each side shows in this hunk for its header.
			na, nb := 0, 0
			for j := i; j < len(all) && keep[j]; j++ {
				if all[j].Op != '+' {
					na++
				}
				if all[j].Op != '-' {
					nb++
				}
			}
			sa, sb := firstNum(all, i, true), firstNum(all, i, false)
			lines = append(lines, Line{Op: '@', Text: fmt.Sprintf("@@ -%d,%d +%d,%d @@", sa, na, sb, nb)})
		}
		lines = append(lines, l)
		if len(lines) >= MaxTextLines {
			return lines, st, true
		}
	}
	return lines, st, false
}

// firstNum is the line number on one side at or after index i.
func firstNum(all []Line, i int, a bool) int {
	for ; i < len(all); i++ {
		if a && all[i].A > 0 {
			return all[i].A
		}
		if !a && all[i].B > 0 {
			return all[i].B
		}
	}
	return 0
}

// lineDiff diffs by whole lines and numbers them.
func lineDiff(a, b string) []Line {
	dmp := diffmatchpatch.New()
	dmp.DiffTimeout = 5 * time.Second
	ca, cb, table := dmp.DiffLinesToChars(a, b)
	diffs := dmp.DiffCharsToLines(dmp.DiffMain(ca, cb, false), table)
	var out []Line
	na, nb := 0, 0
	for _, d := range diffs {
		text := d.Text
		for text != "" {
			var one string
			if i := strings.IndexByte(text, '\n'); i >= 0 {
				one, text = text[:i], text[i+1:]
			} else {
				one, text = text, ""
			}
			switch d.Type {
			case diffmatchpatch.DiffEqual:
				na++
				nb++
				out = append(out, Line{Op: ' ', A: na, B: nb, Text: one})
			case diffmatchpatch.DiffDelete:
				na++
				out = append(out, Line{Op: '-', A: na, Text: one})
			case diffmatchpatch.DiffInsert:
				nb++
				out = append(out, Line{Op: '+', B: nb, Text: one})
			}
		}
	}
	return out
}

// Strings extracts the printable runs of at least min characters from data:
// ASCII, and UTF-16LE (a character then a zero byte), in file order. At most
// MaxStrings are kept.
func Strings(data []byte, min int) []string {
	var out []string
	scanRuns(data, min, func(r run) bool {
		if r.utf16 {
			var sb strings.Builder
			for i := r.start; i < r.end; i += 2 {
				sb.WriteByte(data[i])
			}
			out = append(out, sb.String())
		} else {
			out = append(out, string(data[r.start:r.end]))
		}
		return len(out) < MaxStrings
	})
	return out
}

// run is a stretch of data that is a printable string: [start, end) bytes, and
// whether it is UTF-16LE (a character then a zero byte, so two bytes a character).
type run struct {
	start, end int
	utf16      bool
}

func printable(c byte) bool { return c >= 0x20 && c < 0x7f || c == '\t' }

// scanRuns calls f for each string of at least min characters in data — the
// ASCII ones in order, then the UTF-16LE ones — until f returns false. One
// scanner, so what Strings lists and what Residue leaves out are the same bytes.
func scanRuns(data []byte, min int, f func(run) bool) {
	for i := 0; i < len(data); {
		if !printable(data[i]) {
			i++
			continue
		}
		j := i
		for j < len(data) && printable(data[j]) {
			j++
		}
		// A UTF-16LE string alternates a character with a zero byte; reading it
		// as ASCII yields one-character runs, so it is looked for separately.
		if j-i >= min && !f(run{i, j, false}) {
			return
		}
		i = j
	}
	for i := 0; i+1 < len(data); {
		if !(printable(data[i]) && data[i+1] == 0) {
			i++
			continue
		}
		j := i
		for j+1 < len(data) && printable(data[j]) && data[j+1] == 0 {
			j += 2
		}
		if (j-i)/2 >= min && !f(run{i, j, true}) {
			return
		}
		i = j
	}
}

// Residue is data with every printable string cut out, each with the NUL that
// ends it (two for UTF-16): what a binary is apart from its text. The
// terminator goes with the string because adding or removing a string adds or
// removes it, and a binary that only gained a string should not look as though
// something else changed.
func Residue(data []byte, min int) []byte {
	covered := stringMask(data, min)
	out := make([]byte, 0, len(data))
	for i, c := range data {
		if covered[i/64]&(1<<(i%64)) == 0 {
			out = append(out, c)
		}
	}
	return out
}

// stringMask is a bit per byte of data: set for those in a string or its
// terminator, as Residue cuts them.
func stringMask(data []byte, min int) []uint64 {
	covered := make([]uint64, (len(data)+63)/64)
	cover := func(from, to int) {
		for i := from; i < to; i++ {
			covered[i/64] |= 1 << (i % 64)
		}
	}
	scanRuns(data, min, func(r run) bool {
		end := r.end
		switch {
		case !r.utf16 && end < len(data) && data[end] == 0:
			end++
		case r.utf16 && end+1 < len(data) && data[end] == 0 && data[end+1] == 0:
			end += 2
		}
		cover(r.start, end)
		return true
	})
	return covered
}

// StringsVerdict says whether two binaries differ only in their printable
// strings: whether, with every string cut out of both, what is left is identical.
type StringsVerdict struct {
	// Only is set when a and b differ and the bytes outside strings are the same.
	Only bool
	// ResidueA and ResidueB are the bytes outside strings on each side.
	ResidueA, ResidueB int64
	// ResidueDiffering is, when the two residues are the same size, how many of
	// their bytes differ (0 when Only); -1 when the sizes differ.
	ResidueDiffering int64
	// StringBytesA and StringBytesB are the bytes inside strings.
	StringBytesA, StringBytesB int64
}

// StringsOnly checks whether a and b differ only in strings of at least min
// characters (ASCII or UTF-16LE). A string that changes length shifts nothing
// that is not a string, so it counts; a change to a byte outside a string, or
// inside a run too short to be one, does not.
func StringsOnly(a, b []byte, min int) StringsVerdict {
	ra, rb := Residue(a, min), Residue(b, min)
	v := StringsVerdict{
		ResidueA: int64(len(ra)), ResidueB: int64(len(rb)), ResidueDiffering: -1,
		StringBytesA: int64(len(a) - len(ra)), StringBytesB: int64(len(b) - len(rb)),
	}
	if len(ra) == len(rb) {
		v.ResidueDiffering = 0
		for i := range ra {
			if ra[i] != rb[i] {
				v.ResidueDiffering++
			}
		}
	}
	v.Only = v.ResidueDiffering == 0 && !bytes.Equal(a, b)
	return v
}

// MaxStrings bounds the strings taken from one file.
const MaxStrings = 100000

// StringDiff is a line diff of the printable strings in a and b, one string per
// line, so what text a binary gained or lost shows without the bytes between.
func StringDiff(a, b []byte, min, context int) (lines []Line, st Stats, truncated bool) {
	sa := strings.Join(Strings(a, min), "\n") + "\n"
	sb := strings.Join(Strings(b, min), "\n") + "\n"
	return TextDiff([]byte(sa), []byte(sb), context)
}

// Overlap is how much of two byte strings is the same content and how much is
// unique to each, found by cutting both into content-defined chunks (so an
// insertion shifts nothing after it) and matching chunks across.
type Overlap struct {
	SizeA, SizeB     int64 // bytes analysed
	SharedA, SharedB int64 // bytes of each in a chunk the other also has
	// Chunk is the average size of the chunks it was measured in (see chunkerFor):
	// a changed byte makes its whole chunk unique, so this is the resolution. 0
	// when it was measured byte for byte (see exactMax).
	Chunk int
	// Prefix and Suffix are the bytes the two begin and end with identically.
	Prefix, Suffix int64
	// Differing is, for equal sizes, the bytes that differ at the same offset
	// (-1 when sizes differ), and FirstDiff the first such offset (-1 if none).
	Differing, FirstDiff int64
	// MapA and MapB are Buckets cells along each file: the fraction of that
	// stretch which is shared.
	MapA, MapB []float64
}

// Buckets is the resolution of an Overlap's maps.
const Buckets = 64

// UniqueA and UniqueB are the bytes found in only one of the two.
func (o Overlap) UniqueA() int64 { return o.SizeA - o.SharedA }
func (o Overlap) UniqueB() int64 { return o.SizeB - o.SharedB }

// A chunk is the unit of "shared": one that holds any changed byte is counted
// as unique whole. So its size has to be small against the file, or a few
// scattered changes in a small file make all of it look unique; but not so
// small that a large file is cut into millions of pieces. The average is about
// 1/256 of the file, a power of two from chunkAvgMin to chunkAvgMax.
const (
	chunkAvgMin = 64
	chunkAvgMax = 4 << 10
)

type chunker struct {
	avg, min, max int
	mask          uint64
}

// chunkerFor is the chunking for comparing data of about this size.
func chunkerFor(size int) chunker {
	avg := chunkAvgMin
	for avg < chunkAvgMax && avg*256 < size {
		avg *= 2
	}
	return chunker{avg: avg, min: max(avg/4, 16), max: avg * 4, mask: uint64(avg - 1)}
}

var gear = func() (t [256]uint64) {
	x := uint64(0x9E3779B97F4A7C15)
	for i := range t {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		t[i] = x
	}
	return
}()

type chunk struct {
	off, n int
	key    chunkKey
}

type chunkKey struct {
	sum uint64
	n   int
}

func chunks(data []byte, c chunker) []chunk {
	var out []chunk
	for start := 0; start < len(data); {
		end := min(start+c.max, len(data))
		cut := end
		var h uint64
		for i := start; i < end; i++ {
			h = h<<1 + gear[data[i]]
			if i-start+1 >= c.min && h&c.mask == 0 {
				cut = i + 1
				break
			}
		}
		f := fnv.New64a()
		f.Write(data[start:cut])
		out = append(out, chunk{start, cut - start, chunkKey{f.Sum64(), cut - start}})
		start = cut
	}
	return out
}

// Compare measures a against b.
func Compare(a, b []byte) Overlap {
	o := Overlap{SizeA: int64(len(a)), SizeB: int64(len(b)), Differing: -1, FirstDiff: -1}
	for o.Prefix < int64(len(a)) && o.Prefix < int64(len(b)) && a[o.Prefix] == b[o.Prefix] {
		o.Prefix++
	}
	for o.Suffix < int64(len(a))-o.Prefix && o.Suffix < int64(len(b))-o.Prefix && a[int64(len(a))-1-o.Suffix] == b[int64(len(b))-1-o.Suffix] {
		o.Suffix++
	}
	if len(a) == len(b) {
		o.Differing = 0
		for i := range a {
			if a[i] != b[i] {
				if o.FirstDiff < 0 {
					o.FirstDiff = int64(i)
				}
				o.Differing++
			}
		}
	}
	c := chunkerFor(max(len(a), len(b))) // the same cutting on both sides, or nothing matches
	o.Chunk = c.avg
	ca, cb := chunks(a, c), chunks(b, c)
	inA, inB := map[chunkKey]bool{}, map[chunkKey]bool{}
	for _, c := range ca {
		inA[c.key] = true
	}
	for _, c := range cb {
		inB[c.key] = true
	}
	o.MapA, o.SharedA = shareMap(ca, inB, len(a))
	o.MapB, o.SharedB = shareMap(cb, inA, len(b))
	// Small and alike: measure it exactly. The chunks said it is alike (if they
	// found little in common, an exact diff would only be slow and unfavourable
	// to read), and they cannot say how alike, to better than their own size.
	if max(len(a), len(b)) <= exactMax && 5*o.SharedA >= int64(len(a)) && 5*o.SharedB >= int64(len(b)) {
		if ma, mb, sa, sb, ok := exactOverlap(a, b); ok {
			o.MapA, o.MapB, o.SharedA, o.SharedB, o.Chunk = ma, mb, sa, sb, 0
		}
	}
	return o
}

// shareMap counts the bytes of cs present in other, and spreads them over
// Buckets cells along a file of the given size.
func shareMap(cs []chunk, other map[chunkKey]bool, size int) ([]float64, int64) {
	if size == 0 {
		return make([]float64, Buckets), 0
	}
	cm := newCellMap(size)
	for _, c := range cs {
		cm.add(c.off, c.n, other[c.key])
	}
	return cm.result()
}
