package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

// A real archive member can be named "." or ".." (an HKMC navi map package
// is: see literalNote's comment) - rendered one path segment per line the
// same way, it would otherwise be indistinguishable from the synthetic "go
// up" row, which shares the same name.
func TestLiteralDotEntryIsNoted(t *testing.T) {
	for _, name := range []string{"..", "."} {
		e := browseEntry{name: name, dir: true}
		line := e.line()
		if !strings.Contains(line, "literal") {
			t.Errorf("%q: line %q has no literal note", name, line)
		}
	}
	if line := parentEntry.line(); strings.Contains(line, "literal") {
		t.Errorf("the synthetic parent row was noted as literal: %q", line)
	}
	// An ordinary entry never gets the note, literal in its name or not.
	if line := (browseEntry{name: "a.bin", dir: false, size: 12}).line(); strings.Contains(line, "literal") {
		t.Errorf("an ordinary entry was noted as literal: %q", line)
	}
}

// padToWidth measures display width through the embedded ANSI styling
// literalNote adds, not the escape codes themselves.
func TestLiteralNoteDoesNotThrowOffWidth(t *testing.T) {
	e := browseEntry{name: "..", dir: true}
	padded := padToWidth(e.line(), 80)
	if w := ansi.StringWidth(padded); w != 80 {
		t.Errorf("padded to %d display columns, want 80 (line: %q)", w, padded)
	}
}
