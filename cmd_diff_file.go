package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// diffContext is how many unchanged lines are shown around each change.
var diffContext = contextLines

// pairNodes opens the two things to compare: each input as it is, or, with a
// member, the file at that path inside each (a directory, an archive, an image,
// as ls and extract take a path). name is what the pair is called.
func pairNodes(pathA, pathB, member string) (a, b *carve.Node, name string, err error) {
	if a, err = diffRoot(pathA); err != nil {
		return nil, nil, "", err
	}
	if b, err = diffRoot(pathB); err != nil {
		return nil, nil, "", err
	}
	name = infile.Base(pathA)
	if bn := infile.Base(pathB); bn != name {
		name += " -> " + bn
	}
	if member == "" {
		return a, b, name, nil
	}
	if a, err = a.Walk(member); err != nil {
		return nil, nil, "", fmt.Errorf("%s: %w", pathA, err)
	}
	if b, err = b.Walk(member); err != nil {
		return nil, nil, "", fmt.Errorf("%s: %w", pathB, err)
	}
	return a, b, member, nil
}

// viewMode is the view a --view value names.
func viewMode(v string) (int, error) {
	for i, n := range modeNames {
		if n == v {
			return i, nil
		}
	}
	return 0, fmt.Errorf("--view %q: want one of %v", v, modeNames)
}

// runFileDiff prints what differs between two files, as the interactive view
// shows it: a line diff for text; for a binary, whether only its strings differ,
// how much is shared and how much unique to each side, and a diff of the strings
// in it. The two files are the inputs, or the member at member inside each. Plain
// text on a pipe, coloured and wrapped to the window on a terminal.
func runFileDiff(pathA, pathB, member, view string) error {
	mode, err := viewMode(view)
	if err != nil {
		return err
	}
	a, b, name, err := pairNodes(pathA, pathB, member)
	if err != nil {
		return err
	}
	if a.IsDirNode() || b.IsDirNode() {
		return fmt.Errorf("%s is a directory: name two files, or a file in them with --path (without --path, directories are compared whole)", name)
	}
	d := loadPair(a, b, viewLimitMore)
	fmt.Printf("%s vs %s\n", infile.Base(pathA), infile.Base(pathB))
	if d.err == nil && !d.truncA && !d.truncB && bytes.Equal(d.a, d.b) {
		fmt.Println("identical")
		return nil
	}
	tty := term.IsTerminal(int(os.Stdout.Fd()))
	width, wrap := 1<<20, false // a pipe gets whole lines
	if tty {
		wrap = true
		if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 20 {
			width = w
		} else {
			width = 100
		}
	}
	out := renderDetail(diffItem{kind: '~', path: name, a: a, b: b}, d, mode, width, wrap, true, tty)
	if !tty {
		out = ansi.Strip(out)
	}
	fmt.Print(out)
	return nil
}
