package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr runs f with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	f()
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

// Off a terminal the shared bar draws nothing, so progress must come out as
// plain lines a log can keep: one per stage, and the detail inside a stage.
func TestPortProgressPrintsLinesOffATerminal(t *testing.T) {
	if stderrIsTTY {
		t.Skip("stderr is a terminal; the bar draws instead")
	}
	out := captureStderr(t, func() {
		p := newPortProgress()
		if p.bar != nil {
			t.Error("no bar off a terminal")
		}
		p.say("reading %s", "the boot images")
		p.detail("unpacked %d of %d chunks", 11, 44)
		p.say("writing the bundle")
		p.done()
		p.done() // finishing twice (a deferred call after an explicit one) is harmless
	})
	for _, want := range []string{"port: [", "reading the boot images", "unpacked 11 of 44 chunks", "writing the bundle"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "\n") != 3 {
		t.Errorf("want 3 lines:\n%s", out)
	}
}

func TestPortProgressIsSafeWithoutABar(t *testing.T) {
	p := &portProgress{} // a nil bar, as off a terminal
	p.done()
	p.n = 3
	p.done()
	if p.n != 0 {
		t.Errorf("done resets the step count, got %d", p.n)
	}
}
