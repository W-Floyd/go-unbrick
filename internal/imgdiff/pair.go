package imgdiff

import "go-unbrick/internal/secboot"

// Segments are paired by load address, not by position in the program-header
// table. A rebuild can insert, drop, resize or reorder segments -- keymaster
// keeps only 3 of its 8 addresses between two fogona builds -- but a segment
// that still exists still loads where it loaded. Pairing on index instead makes
// one inserted segment shift everything after it and turns a readable diff into
// "layouts do not correspond".
//
// Addresses are not unique: tz carries 28 segments over 27 distinct addresses.
// Segments sharing an address are therefore paired in the order they appear.

// pair is one aligned segment. Either side may be absent, when a segment was
// added or removed rather than changed.
type pair struct {
	a, b *secboot.Segment
}

// pairByPaddr aligns two segment lists on load address, preserving order within
// an address and leaving unmatched segments on whichever side holds them.
//
// The hash segment is paired first and separately. An image has exactly one, and
// a rebuild can move it -- keymaster's goes from 0x56000 to 0x53000 -- so
// pairing it on address would report the signature as one segment removed and
// another added, when it is the same segment re-signed.
func pairByPaddr(as, bs []secboot.Segment) []pair {
	usedB := make([]bool, len(bs))
	var out []pair

	ha, hb := hashIndex(as), hashIndex(bs)
	if ha >= 0 && hb >= 0 {
		usedB[hb] = true
		out = append(out, pair{a: &as[ha], b: &bs[hb]})
	}

	byAddr := map[uint64][]int{}
	for i := range bs {
		if i == hb {
			continue
		}
		byAddr[bs[i].Paddr] = append(byAddr[bs[i].Paddr], i)
	}

	for i := range as {
		if i == ha {
			continue
		}
		sa := as[i]
		q := byAddr[sa.Paddr]
		matched := -1
		for _, j := range q {
			if !usedB[j] {
				matched = j
				break
			}
		}
		if matched < 0 {
			out = append(out, pair{a: &as[i]})
			continue
		}
		usedB[matched] = true
		out = append(out, pair{a: &as[i], b: &bs[matched]})
	}
	for j := range bs {
		if !usedB[j] {
			out = append(out, pair{b: &bs[j]})
		}
	}
	return out
}

// hashIndex finds the Qualcomm hash-table segment, or -1.
func hashIndex(ss []secboot.Segment) int {
	for i := range ss {
		if ss[i].Hash {
			return i
		}
	}
	return -1
}

// aligned reports how many pairs have both sides, which decides whether the two
// images correspond closely enough to compare at all.
func aligned(ps []pair) int {
	n := 0
	for _, p := range ps {
		if p.a != nil && p.b != nil {
			n++
		}
	}
	return n
}
