// Package imgdiff compares two Qualcomm signed images in terms that mean
// something.
//
// A raw byte diff is useless here. Every build re-signs, so the hash-table
// segment always differs; payloads are pointer-linked, so inserting one entry
// relocates everything after it; and images embed high-entropy key material that
// changes wholesale. Counting differing bytes therefore reports large numbers
// for images that are semantically identical. This package separates those
// effects: it splits an image by ELF segment, classifies each differing run by
// entropy, and compares embedded name tables as sets rather than byte-wise.
package imgdiff

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"sort"

	"go-unbrick/internal/devcfg"
	"go-unbrick/internal/secboot"
)

// entropyOpaque is the bits/byte above which a run is treated as key material
// or a hash table rather than data with readable structure. Compressed and
// encrypted bytes sit at ~8.0; structured firmware data measures well below.
const entropyOpaque = 7.5

// runGap joins differing bytes into one run when they are closer than this.
const runGap = 32

// Verdict summarizes how two images relate.
type Verdict string

const (
	Identical    Verdict = "identical"
	ResignOnly   Verdict = "re-signed only"  // payload identical, signature differs
	Changed      Verdict = "payload changed" // at least one payload segment differs
	Incomparable Verdict = "incomparable"    // different segment layout
)

// Run is a contiguous differing region within a segment.
type Run struct {
	Start, Len int
	Entropy    float64
	Opaque     bool // high entropy: key material or hashes, expected to differ
}

// SegmentDiff is the comparison of one program-header segment.
type SegmentDiff struct {
	Index        int
	Paddr        uint64
	Size         int
	Hash         bool // the Qualcomm hash-table segment
	Differing    int
	Runs         []Run
	NamesA       []string // NUL-separated name table, if the segment holds one
	NamesB       []string
	NamesEqual   bool // same set of names, possibly reordered
	NamesOrdered bool // same names in the same order
	// DevCfg is set when the segment is a Qualcomm device-configuration payload,
	// which can be compared by property rather than by byte.
	DevCfg *devcfg.Diff
}

// Opaque reports whether every differing run is high-entropy. Such bytes carry
// no readable structure -- compressed code, key material or a hash table -- so
// a byte count over them says nothing about how much really changed. It does
// NOT mean the change is insignificant: abl's payload is a compressed UEFI
// volume and reads as opaque while containing the entire bootloader.
func (s SegmentDiff) Opaque() bool {
	if len(s.Runs) == 0 {
		return false
	}
	for _, r := range s.Runs {
		if !r.Opaque {
			return false
		}
	}
	return true
}

// Result is the whole comparison.
type Result struct {
	Verdict  Verdict
	Segments []SegmentDiff
	// SizeA/SizeB are the whole-image sizes, for context only.
	SizeA, SizeB int
	// RawDiffering is the naive byte-difference count, kept so a caller can show
	// how misleading it is next to the verdict.
	RawDiffering int
	// OutsideDiffering counts bytes that differ but lie in no program header.
	// Vendors stamp build identity there, so ignoring it would report two builds
	// as indistinguishable.
	OutsideDiffering int
	// Stamps are the differing texts found outside the segments, e.g. the two
	// images' build signatures.
	StampA, StampB string
	// DevCfg is a device-configuration comparison made independently of segment
	// layout. It is how two images whose layouts do not correspond -- different
	// devices, or builds far enough apart that segments moved -- can still be
	// compared by content.
	DevCfg *devcfg.Diff
	Note   string
}

// findDevCfg locates and parses a device-configuration payload anywhere in an
// image, independently of how its segments line up with another image's.
func findDevCfg(img []byte) *devcfg.Config {
	segs, err := secboot.Segments(img)
	if err != nil {
		return nil
	}
	for _, s := range segs {
		seg := img[s.Offset : s.Offset+s.Filesz]
		if c, ok := devcfg.Parse(seg, s.Paddr); ok {
			return c
		}
	}
	return nil
}

// compareDevCfg attaches a layout-independent configuration comparison.
func compareDevCfg(res *Result, a, b []byte) {
	ca, cb := findDevCfg(a), findDevCfg(b)
	if ca == nil || cb == nil {
		return
	}
	d := devcfg.Compare(ca, cb)
	res.DevCfg = &d
}

// Compare diffs two signed images.
func Compare(a, b []byte) (*Result, error) {
	segsA, err := secboot.Segments(a)
	if err != nil {
		return nil, fmt.Errorf("first image: %w", err)
	}
	segsB, err := secboot.Segments(b)
	if err != nil {
		return nil, fmt.Errorf("second image: %w", err)
	}
	res := &Result{SizeA: len(a), SizeB: len(b), RawDiffering: countDiff(a, b)}
	if len(segsA) != len(segsB) {
		res.Verdict = Incomparable
		res.Note = fmt.Sprintf("segment counts differ (%d vs %d); these are not two builds of one image",
			len(segsA), len(segsB))
		compareDevCfg(res, a, b)
		return res, nil
	}

	payloadChanged, signatureChanged := false, false
	for i := range segsA {
		sa, sb := segsA[i], segsB[i]
		if sa.Filesz != sb.Filesz || sa.Paddr != sb.Paddr {
			res.Verdict = Incomparable
			res.Note = fmt.Sprintf("segment %d has a different size or load address; layouts do not correspond", i)
			compareDevCfg(res, a, b)
			return res, nil
		}
		da := a[sa.Offset : sa.Offset+sa.Filesz]
		db := b[sb.Offset : sb.Offset+sb.Filesz]
		sd := SegmentDiff{Index: i, Paddr: sa.Paddr, Size: len(da), Hash: sa.Hash}
		sd.Differing = countDiff(da, db)
		if sd.Differing == 0 {
			res.Segments = append(res.Segments, sd)
			continue
		}
		sd.Runs = runs(da, db)
		sd.NamesA, sd.NamesB = nameTable(da), nameTable(db)
		sd.NamesEqual, sd.NamesOrdered = compareNames(sd.NamesA, sd.NamesB)
		if ca, ok := devcfg.Parse(da, sa.Paddr); ok {
			if cb, ok := devcfg.Parse(db, sb.Paddr); ok {
				d := devcfg.Compare(ca, cb)
				sd.DevCfg = &d
			}
		}
		res.Segments = append(res.Segments, sd)
		if sa.Hash {
			signatureChanged = true
		} else {
			payloadChanged = true
		}
	}

	res.OutsideDiffering, res.StampA, res.StampB = outside(a, b, segsA)

	switch {
	case payloadChanged:
		res.Verdict = Changed
		// A decoded configuration whose readable content matches is worth
		// saying, but it is not a claim of equivalence: the payload also holds
		// regions this package cannot read.
		for _, s := range res.Segments {
			if s.DevCfg != nil && s.Differing > 0 && s.DevCfg.Equivalent() {
				res.Note = fmt.Sprintf(
					"device config: identical name sets, and the %d decoded values agree; "+
						"the rest is layout and undecoded regions",
					s.DevCfg.ComparedValues)
			}
		}
	case signatureChanged || res.OutsideDiffering > 0:
		res.Verdict = ResignOnly
		res.Note = "payload segments are byte-identical; only the signature and build stamp differ"
	default:
		res.Verdict = Identical
	}
	return res, nil
}

// outside compares the bytes covered by no program header. A signed image keeps
// its build signature there, so those bytes are the difference between two
// builds whose payload is otherwise identical.
func outside(a, b []byte, segs []secboot.Segment) (n int, stampA, stampB string) {
	covered := make([]bool, min(len(a), len(b)))
	for _, s := range segs {
		for i := s.Offset; i < s.Offset+s.Filesz && int(i) < len(covered); i++ {
			covered[i] = true
		}
	}
	lo, hi := -1, -1
	for i := range covered {
		if covered[i] || a[i] == b[i] {
			continue
		}
		n++
		if lo < 0 {
			lo = i
		}
		hi = i
	}
	if lo < 0 {
		return 0, "", ""
	}
	return n, printableAround(a, lo, hi), printableAround(b, lo, hi)
}

// printableAround widens a differing range to the printable text surrounding it,
// so a differing build stamp is reported whole rather than as stray bytes.
func printableAround(b []byte, lo, hi int) string {
	isText := func(c byte) bool { return c >= 0x20 && c < 0x7f }
	for lo > 0 && isText(b[lo-1]) {
		lo--
	}
	for hi+1 < len(b) && isText(b[hi+1]) {
		hi++
	}
	return string(bytes.TrimSpace(b[lo : hi+1]))
}

func countDiff(a, b []byte) int {
	n := min(len(a), len(b))
	d := abs(len(a) - len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			d++
		}
	}
	return d
}

// runs groups differing bytes into contiguous regions and measures each.
func runs(a, b []byte) []Run {
	n := min(len(a), len(b))
	var out []Run
	start, prev := -1, -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		seg := a[start : end+1]
		e := entropy(seg)
		out = append(out, Run{Start: start, Len: end - start + 1, Entropy: e, Opaque: e > entropyOpaque})
	}
	for i := 0; i < n; i++ {
		if a[i] == b[i] {
			continue
		}
		if start < 0 {
			start, prev = i, i
			continue
		}
		if i-prev > runGap {
			flush(prev)
			start = i
		}
		prev = i
	}
	flush(prev)
	sort.Slice(out, func(i, j int) bool { return out[i].Len > out[j].Len })
	return out
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var f [256]int
	for _, c := range b {
		f[c]++
	}
	h := 0.0
	for _, c := range f {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(len(b))
		h -= p * math.Log2(p)
	}
	return h
}

var reName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]{3,}$`)

// nameTable extracts the NUL-separated identifier table these images embed --
// property names in devcfg, for instance. Reordering such a table shifts every
// byte after it, so comparing the names as a set says far more than the byte
// count does.
func nameTable(b []byte) []string {
	var out []string
	for _, f := range bytes.Split(b, []byte{0}) {
		if reName.Match(f) {
			out = append(out, string(f))
		}
	}
	return out
}

// compareNames reports whether two tables hold the same names, and whether they
// hold them in the same order.
func compareNames(a, b []string) (equal, ordered bool) {
	if len(a) == 0 && len(b) == 0 {
		return false, false
	}
	sa, sb := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	if len(sa) != len(sb) {
		return false, false
	}
	for i := range sa {
		if sa[i] != sb[i] {
			return false, false
		}
	}
	ordered = true
	if len(a) == len(b) {
		for i := range a {
			if a[i] != b[i] {
				ordered = false
				break
			}
		}
	} else {
		ordered = false
	}
	return true, ordered
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
