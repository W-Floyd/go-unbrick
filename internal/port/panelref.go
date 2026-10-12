package port

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// seqCallRe matches the kernel's DSI write helpers with a literal byte list:
// mipi_dsi_dcs_write_seq_multi(&dsi_ctx, 0xf0, 0x99, ...), and the generic and
// non-multi forms.
var seqCallRe = regexp.MustCompile(`(?s)mipi_dsi_(?:dcs|generic)_write_seq(?:_multi)?\(\s*[&\w>\-]+\s*,\s*(.*?)\)\s*;`)

// ReferenceSequences reads every literal command a driver source sends.
func ReferenceSequences(src string) [][]byte {
	src = lineComment.ReplaceAllString(blockComment.ReplaceAllString(src, ""), "")
	var out [][]byte
	for _, m := range seqCallRe.FindAllStringSubmatch(src, -1) {
		var seq []byte
		ok := true
		for _, f := range strings.Split(m[1], ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(f), 0, 8)
			if err != nil {
				ok = false
				break
			}
			seq = append(seq, byte(v))
		}
		if ok && len(seq) > 0 {
			out = append(out, seq)
		}
	}
	return out
}

var (
	clockRe  = regexp.MustCompile(`\.clock\s*=\s*(\d+)`)
	vfrontRe = regexp.MustCompile(`\.vsync_start\s*=\s*\d+\s*\+\s*(\d+)`)
)

// PanelSection is the report's account of the drafted panel drivers, and, when
// a hand-written driver is given, how its command bytes and modes line up.
func PanelSection(ds []PanelDriver, reference string) string {
	if len(ds) == 0 {
		return ""
	}
	var seqs [][]byte
	var clocks, vfronts []string
	if reference != "" {
		seqs = ReferenceSequences(reference)
		for _, m := range clockRe.FindAllStringSubmatch(reference, -1) {
			clocks = append(clocks, m[1])
		}
		for _, m := range vfrontRe.FindAllStringSubmatch(reference, -1) {
			vfronts = append(vfronts, m[1])
		}
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## Panel drivers\n")
	w("One draft per panel the board references, from its stock node: modes, reset timing, init and off sequences, lanes, format and mode flags. Each is a starting point for a driver, not a compiled one.\n")
	w("| panel | modes | lanes, format | init / off commands | reset (level, ms) |")
	w("|---|---|---|---|---|")
	for _, d := range ds {
		var modes []string
		for _, m := range d.Modes {
			modes = append(modes, fmt.Sprintf("%dx%d@%d (clock %d kHz)", m.HDisplay, m.VDisplay, m.Hz, m.Clock))
		}
		w("| %s | %s | %d, %s | %d / %d | %s |", d.Name, strings.Join(modes, "; "), d.Lanes, strings.TrimPrefix(d.Format, "MIPI_DSI_FMT_"), len(d.On), len(d.Off), resetText(d.Reset))
	}
	if reference != "" {
		w("\nAgainst the reference driver. A panel counts as the reference's when one of its mode clocks appears there; the others only share short commands by chance.\n")
		w("| panel | init+off commands, same bytes | same, ignoring trailing zero padding | mode clocks | vertical front porches |")
		w("|---|---|---|---|---|")
		for _, d := range ds {
			var ck, vf []string
			mine := false
			for _, m := range d.Modes {
				c := markIn(strconv.Itoa(m.Clock), clocks)
				mine = mine || strings.HasSuffix(c, "✓")
				ck = append(ck, c)
				vf = append(vf, markIn(strconv.Itoa(m.VFront), vfronts))
			}
			if !mine {
				w("| %s | not in the reference | — | — | — |", d.Name)
				continue
			}
			total, exact, loose := 0, 0, 0
			for _, c := range append(append([]DSICmd{}, d.On...), d.Off...) {
				total++
				var e, l bool
				for _, s := range seqs {
					e = e || bytes.Equal(s, c.Payload)
					l = l || bytes.Equal(trimZeros(s), trimZeros(c.Payload))
				}
				if e {
					exact++
				}
				if l {
					loose++
				}
			}
			w("| %s | %d of %d | %d of %d | %s | %s |", d.Name, exact, total, loose, total, strings.Join(ck, ", "), strings.Join(vf, ", "))
		}
	}
	for _, d := range ds {
		for _, n := range d.Notes {
			w("\n- %s: %s", d.Name, n)
		}
	}
	return b.String()
}

// trimZeros drops trailing zero bytes but keeps the command byte: the stock
// stream pads a command to a fixed length that a driver need not send.
func trimZeros(b []byte) []byte {
	for len(b) > 1 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

func markIn(v string, in []string) string {
	for _, s := range in {
		if s == v {
			return v + " ✓"
		}
	}
	return v + " ✗"
}
