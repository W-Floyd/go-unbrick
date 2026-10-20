package main

import (
	"math/rand"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

func TestFitWrapsWithAHangingIndent(t *testing.T) {
	text := strings.Repeat("alpha beta gamma delta ", 12) + "end"
	out := plain(fit("    12      + ", text, 50, true, lipgloss.NewStyle()))
	rows := strings.Split(out, "\n")
	if len(rows) < 3 {
		t.Fatalf("a %d-character line did not wrap at 50 columns: %q", len(text), out)
	}
	var rejoined []string
	for i, r := range rows {
		if w := ansi.StringWidth(r); w > 50 {
			t.Errorf("row %d is %d wide: %q", i, w, r)
		}
		if i == 0 {
			if !strings.HasPrefix(r, "    12      + ") {
				t.Errorf("first row lost its gutter: %q", r)
			}
			rejoined = append(rejoined, strings.TrimPrefix(r, "    12      + "))
			continue
		}
		// A continuation sits under the text, marked, not flush left.
		if !strings.HasPrefix(r, strings.Repeat(" ", 12)+"↳ ") {
			t.Errorf("continuation row %d is not indented under the text: %q", i, r)
		}
		rejoined = append(rejoined, strings.TrimPrefix(r, strings.Repeat(" ", 12)+"↳ "))
	}
	// Nothing is lost: the words come back in order.
	if got, want := strings.Fields(strings.Join(rejoined, " ")), strings.Fields(text); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("wrapping changed the text:\n got %q\nwant %q", got, want)
	}

	// A word longer than the line is broken, not lost or left to overflow.
	long := strings.Repeat("x", 200)
	for i, r := range strings.Split(plain(fit("   1 ", long, 40, true, lipgloss.NewStyle())), "\n") {
		if ansi.StringWidth(r) > 40 {
			t.Errorf("long word row %d overflows: %d", i, ansi.StringWidth(r))
		}
	}

	// With wrapping off the line is one row, cut off and marked.
	cut := plain(fit("    12      + ", text, 50, false, lipgloss.NewStyle()))
	if strings.Contains(cut, "\n") || ansi.StringWidth(cut) != 50 || !strings.HasSuffix(cut, "…") {
		t.Errorf("unwrapped: %q (%d wide)", cut, ansi.StringWidth(cut))
	}

	// A short line is left alone.
	if got := plain(fit("  3 ", "short", 50, true, lipgloss.NewStyle())); got != "  3 short" {
		t.Errorf("short line: %q", got)
	}
}

func TestRenderLinesWrapsWideChars(t *testing.T) {
	// Wide characters count two columns: no row may be wider than asked.
	ls := []analysis.Line{{Op: '+', B: 1, Text: strings.Repeat("日本語のテキスト", 10)}}
	for i, r := range strings.Split(strings.TrimRight(plain(renderLines(ls, 40, true)), "\n"), "\n") {
		if w := ansi.StringWidth(r); w > 40 {
			t.Errorf("row %d is %d wide", i, w)
		}
	}
}

func TestInteractiveWrapsLongLinesAndTogglesWithW(t *testing.T) {
	long := strings.Repeat("the quick brown fox jumps over the lazy dog ", 8) // ~350 columns
	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{"wide.txt": []byte("short\n" + long + "one\nend\n")})
	writeTree(t, b, map[string][]byte{"wide.txt": []byte("short\n" + long + "TWO\nend\n")})
	m := newDiffTUI("t", compared(t, a, b))
	open(m, 100, 30)
	drive(m, m.refresh())

	rows := func() []string { return strings.Split(plain(m.View().Content), "\n") }
	check := func(label string) {
		for i, r := range rows() {
			if w := ansi.StringWidth(r); w > 100 {
				t.Errorf("%s: row %d is %d wide in a 100-wide window", label, i, w)
			}
		}
	}
	pane := func() string { return plain(m.rendered[m.rk(m.lines[0])]) }

	// Wrapped (the default): the whole of the long line is there, over rows.
	check("wrapped")
	got := pane()
	if !strings.Contains(got, "↳") {
		t.Errorf("a ~350 column line in a ~58 column pane did not wrap:\n%s", got)
	}
	if n := strings.Count(strings.Join(strings.Fields(got), " "), "lazy dog"); n < 8 {
		t.Errorf("wrapping lost text: %d of 8 repetitions", n)
	}
	if !strings.Contains(got, "TWO") {
		t.Errorf("the changed word is not shown:\n%s", got)
	}

	// w switches to cut-off lines: no ↳, ends marked with …, and the cut text is gone.
	key(m, "w")
	if m.wrap {
		t.Fatal("w did not turn wrapping off")
	}
	check("cut off")
	got = pane()
	if strings.Contains(got, "↳") || !strings.Contains(got, "…") {
		t.Errorf("unwrapped pane:\n%s", got)
	}
	if strings.Count(strings.Join(strings.Fields(got), " "), "lazy dog") >= 8 {
		t.Error("the whole long line is shown with wrapping off")
	}

	// And back: both renderings are cached separately, so toggling is instant and
	// returns the wrapped text.
	key(m, "w")
	if !m.wrap || !strings.Contains(pane(), "↳") {
		t.Error("w did not turn wrapping back on")
	}
	check("wrapped again")
}

// The verdict: do only the strings differ?
func TestInteractiveSaysWhetherOnlyStringsDiffer(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	body := noStrings(r, 30<<10)
	mk := func(version string, tweak func([]byte)) []byte {
		out := append([]byte(nil), body...)
		if tweak != nil {
			tweak(out)
		}
		return append(append(out, 0x01), append([]byte("version="+version), 0)...)
	}
	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{
		"only.bin":   mk("1.0.0", nil),
		"grew.bin":   mk("1.0.0", nil),
		"both.bin":   mk("1.0.0", nil),
		"nonstr.bin": mk("1.0.0", nil),
	})
	writeTree(t, b, map[string][]byte{
		"only.bin":   mk("1.0.1", nil),                                                              // same length
		"grew.bin":   mk("1.0.0-rc1-with-a-much-longer-suffix", nil),                                // longer
		"both.bin":   mk("1.0.1", func(b []byte) { b[500] ^= 0xff }),                                // string and a byte
		"nonstr.bin": mk("1.0.0", func(b []byte) { b[700] ^= 0xff; b[9000] ^= 0x7e; b[9001] ^= 1 }), // bytes only
	})
	m := newDiffTUI("t", compared(t, a, b))
	open(m, 140, 40)
	show := func(name string) string {
		t.Helper()
		for i, it := range m.lines {
			if it.path == name {
				_, cmd := m.move(i)
				if cmd == nil {
					cmd = m.refresh()
				}
				drive(m, cmd)
				return plain(m.rendered[m.rk(m.lines[m.cur])])
			}
		}
		t.Fatalf("no line for %s", name)
		return ""
	}
	for name, want := range map[string]string{
		"only.bin":   "Only strings differ",
		"grew.bin":   "Only strings differ",
		"both.bin":   "Not only strings",
		"nonstr.bin": "Not only strings",
	} {
		for _, mode := range []int{modeAuto, modeStrings, modeOverlap} { // in every view
			m.mode = mode
			if got := show(name); !strings.Contains(got, want) {
				t.Errorf("%s, view %s: want %q in:\n%s", name, modeNames[mode], want, got)
			}
		}
	}
	m.mode = modeAuto
	if got := show("both.bin"); !strings.Contains(got, "1 byte of the") || !strings.Contains(got, "differs too") {
		t.Errorf("no count of the non-string bytes that differ:\n%s", got)
	}
	// Text files get no such verdict: a line diff says it all.
	a2, b2 := t.TempDir(), t.TempDir()
	writeTree(t, a2, map[string][]byte{"t.txt": []byte("one\n")})
	writeTree(t, b2, map[string][]byte{"t.txt": []byte("two\n")})
	m2 := newDiffTUI("t", compared(t, a2, b2))
	open(m2, 140, 40)
	drive(m2, m2.refresh())
	if got := plain(m2.rendered[m2.rk(m2.lines[0])]); strings.Contains(got, "strings") && strings.Contains(got, "Only strings") {
		t.Errorf("a text file got the strings verdict:\n%s", got)
	}
}
