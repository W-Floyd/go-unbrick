package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/diffview"
)

func TestHexShownUnaskedOnlyWhenFewBytesDiffer(t *testing.T) {
	a := bytes.Repeat([]byte{0, 1, 2, 3}, 500)
	few := append([]byte(nil), a...)
	few[40], few[41] = 0xde, 0xad
	out := plain(renderHex(a, few, hexAuto, 100, false))
	for _, want := range []string{"2 bytes differ in 1 place", "@@ A 0x28 +2", "de ad", "- 00000020", "+ 00000020"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	many := append([]byte(nil), a...)
	for i := 0; i < 1000; i += 2 {
		many[i] ^= 0xff
	}
	if got := renderHex(a, many, hexAuto, 100, false); got != "" {
		t.Errorf("unasked, %d differing bytes were shown", 500)
	}
	if got := plain(renderHex(a, many, hexBytes, 100, true)); !strings.Contains(got, "differ in") {
		t.Errorf("the hex view shows nothing:\n%s", got)
	}
	if got := plain(renderHex(a, a, hexBytes, 100, true)); !strings.Contains(got, "no bytes differ") {
		t.Errorf("identical: %q", got)
	}
}

func TestWordDiffMarksChangedWordsAndToggles(t *testing.T) {
	m := containers(t) // top.txt: "one" becomes "two"
	goTo(t, m, "top.txt")
	raw := func() string { return m.rendered[m.rk(m.lines[m.cur])] }
	if got := raw(); !strings.Contains(got, "\x1b[7mone\x1b[27m") || !strings.Contains(got, "\x1b[7mtwo\x1b[27m") {
		t.Errorf("changed words are not marked:\n%q", got)
	}
	key(m, "d")
	if m.words {
		t.Fatal("d did not switch word diff off")
	}
	if got := raw(); got == "" || strings.Contains(got, "\x1b[7m") {
		t.Errorf("words marked with word diff off:\n%q", got)
	}
	key(m, "d")
	if !m.words {
		t.Error("d did not switch it back on")
	}
}

func TestWordDiffMarkingIgnoresUnchangedWordsAndLines(t *testing.T) {
	a, b := []byte("let total = price * 3;\nsame\n"), []byte("let total = cost * 3;\nsame\n")
	ls, _, _ := diffview.TextDiff(a, b, 1)
	out := renderLines(diffview.MarkWords(ls), 100, true)
	if !strings.Contains(out, "\x1b[7mprice\x1b[27m") || !strings.Contains(out, "\x1b[7mcost\x1b[27m") {
		t.Errorf("changed words are not marked:\n%q", out)
	}
	if strings.Contains(out, "\x1b[7mlet") || strings.Contains(out, "\x1b[7msame") {
		t.Error("something unchanged is marked")
	}
}
