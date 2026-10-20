package analysis

import (
	"unicode"

	"github.com/sergi/go-diff/diffmatchpatch"
)

// MarkWords sets Hi on the lines of a diff: where a removed line is followed by an
// added one (the nth of a run of removals with the nth of the additions after
// it), the words that differ between the two. Other lines are as they were.
func MarkWords(lines []Line) []Line {
	out := append([]Line(nil), lines...)
	for i := 0; i < len(out); {
		if out[i].Op != '-' {
			i++
			continue
		}
		j := i
		for j < len(out) && out[j].Op == '-' {
			j++
		}
		k := j
		for k < len(out) && out[k].Op == '+' {
			k++
		}
		for n := 0; n < j-i && n < k-j; n++ {
			out[i+n].Hi, out[j+n].Hi = wordDiff(out[i+n].Text, out[j+n].Text)
		}
		i = k
	}
	return out
}

// tokens cuts s into runs of letters and digits, of space, and single other
// characters, as byte offsets.
func tokens(s string) []string {
	var out []string
	start, class := 0, -1
	for i, r := range s {
		c := 2
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_':
			c = 0
		case unicode.IsSpace(r):
			c = 1
		}
		if c != class || c == 2 {
			if i > start {
				out = append(out, s[start:i])
			}
			start, class = i, c
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// wordDiff gives the byte ranges of a and of b that are not shared tokens.
func wordDiff(a, b string) (ha, hb [][2]int) {
	ta, tb := tokens(a), tokens(b)
	ids := map[string]rune{}
	enc := func(ts []string) string {
		r := make([]rune, len(ts))
		for i, t := range ts {
			id, ok := ids[t]
			if !ok {
				id = rune(len(ids) + 1)
				ids[t] = id
			}
			r[i] = id
		}
		return string(r)
	}
	ea, eb := enc(ta), enc(tb)
	ia, ib, pa, pb := 0, 0, 0, 0
	add := func(h *[][2]int, from, to int) {
		if to <= from {
			return
		}
		if n := len(*h); n > 0 && (*h)[n-1][1] == from {
			(*h)[n-1][1] = to
			return
		}
		*h = append(*h, [2]int{from, to})
	}
	for _, d := range diffmatchpatch.New().DiffMain(ea, eb, false) {
		for range d.Text {
			switch d.Type {
			case diffmatchpatch.DiffEqual:
				pa += len(ta[ia])
				pb += len(tb[ib])
				ia++
				ib++
			case diffmatchpatch.DiffDelete:
				add(&ha, pa, pa+len(ta[ia]))
				pa += len(ta[ia])
				ia++
			case diffmatchpatch.DiffInsert:
				add(&hb, pb, pb+len(tb[ib]))
				pb += len(tb[ib])
				ib++
			}
		}
	}
	return ha, hb
}
