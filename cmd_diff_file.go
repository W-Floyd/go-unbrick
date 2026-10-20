package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// diffContext is how many unchanged lines are shown around each change.
var diffContext = contextLines

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
	a, b, name, err := analysis.PairNodes(pathA, pathB, member)
	if err != nil {
		return err
	}
	if a.IsDirNode() || b.IsDirNode() {
		return fmt.Errorf("%s is a directory: name two files, or a file in them with --path (without --path, directories are compared whole)", name)
	}
	e := analysis.PairEntry(name, a, b)
	d := analysis.Load(e, viewLimitMore)
	da, db := d.Bytes()
	fmt.Printf("%s vs %s\n", infile.Base(pathA), infile.Base(pathB))
	if d.Err == nil && !d.TruncA && !d.TruncB && bytes.Equal(da, db) {
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
	out := renderDetail(itemOf(e), d, mode, width, wrap, true, tty)
	if !tty {
		out = ansi.Strip(out)
	}
	fmt.Print(out)
	return nil
}
