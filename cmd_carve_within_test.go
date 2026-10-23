package main

import (
	"strings"
	"testing"
)

// A real archive member can be named "." or ".." (see browseEntry.literalNote
// and within's own comment: "an archive can say '../../x'"). within clamps
// such a name to stay inside dir instead of following it out or refusing it
// outright, and looksUnsafe is what decides whether that's worth a warning.
func TestWithinClampsADangerousName(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"PRM6/../../map/list.json",
		"..",
		"a/../../b",
		"../../../../etc/passwd",
	} {
		if !looksUnsafe(name) {
			t.Errorf("%q: looksUnsafe said no", name)
		}
		dst, err := within(dir, name)
		if err != nil {
			t.Errorf("%q: within refused it: %v", name, err)
			continue
		}
		if !strings.HasPrefix(dst, dir) {
			t.Errorf("%q clamped to %q, which lands outside %s", name, dst, dir)
		}
	}
}

// An ordinary relative name is never flagged, and lands exactly where its
// path says.
func TestWithinOrdinaryName(t *testing.T) {
	dir := t.TempDir()
	if looksUnsafe("a/b.txt") {
		t.Error("an ordinary relative name was flagged unsafe")
	}
	dst, err := within(dir, "a/b.txt")
	if err != nil {
		t.Fatalf("within refused an ordinary name: %v", err)
	}
	if want := dir + "/a/b.txt"; dst != want {
		t.Errorf("got %q, want %q", dst, want)
	}
}
