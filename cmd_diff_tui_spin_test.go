package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// spinnerIn is the spinner glyph at the start of a rendered row, if it has one.
func spinnerIn(row string) string {
	for _, f := range spinFrames {
		if strings.HasPrefix(strings.TrimLeft(row, " "), f) {
			return f
		}
	}
	return ""
}

// listRows are the rows of the list as drawn, cut to the list's own width.
func listRows(m *diffTUI, from, to int) []string {
	var out []string
	rows := strings.Split(plain(m.View().Content), "\n")
	for _, r := range rows[from:to] {
		if rs := []rune(r); len(rs) > m.listWidth() {
			r = string(rs[:m.listWidth()])
		}
		out = append(out, strings.TrimRight(r, " "))
	}
	return out
}

// runningDiffLines are what a comparison part-way has found: pkg.tar is still
// being compared (what is found inside it so far is hung from it), sub/ holds a
// changed file and another container still going, and done.txt is finished.
func runningDiffLines() []analysis.FakeLine {
	return []analysis.FakeLine{
		{Kind: analysis.Changed, Path: "done.txt"},
		{Kind: analysis.Changed, Path: "pkg.tar", Pending: true, Kids: []analysis.FakeLine{{Kind: analysis.Changed, Path: "pkg.tar/m.bin"}}},
		{Kind: analysis.Changed, Path: "sub/changed.txt"},
		{Kind: analysis.Changed, Path: "sub/deep.tar", Pending: true},
	}
}

func runningDiff() (*diffTUI, *analysis.Run) {
	run := analysis.NewFakeRun(runningDiffLines(), false)
	m := newDiffTUI("t", run)
	open(m, 100, 20)
	return m, run
}

func TestRowsInProgressShowASpinner(t *testing.T) {
	m, _ := runningDiff()
	if got := names(m.lines); got != "sub/ | done.txt | pkg.tar/" {
		t.Fatalf("the level: %q", got)
	}
	byName := map[string]diffItem{}
	for _, it := range m.lines {
		byName[it.name] = it
	}
	if !byName["pkg.tar/"].pending || !byName["sub/"].pending || byName["done.txt"].pending {
		t.Fatalf("pending: pkg.tar/ %v, sub/ %v, done.txt %v (a directory holding something in progress is in progress)",
			byName["pkg.tar/"].pending, byName["sub/"].pending, byName["done.txt"].pending)
	}
	// The row's marker becomes the spinner; the rest of it is as it was.
	pend := m.rowText(byName["pkg.tar/"])
	if spinnerIn(pend) == "" || !strings.HasSuffix(pend, " pkg.tar/") {
		t.Errorf("a pending leaf row: %q", pend)
	}
	dir := m.rowText(byName["sub/"])
	if spinnerIn(dir) == "" || !strings.Contains(dir, "sub/") || !strings.Contains(dir, "2 changed") {
		t.Errorf("a pending directory row: %q", dir)
	}
	if got := m.rowText(byName["done.txt"]); got != "~ done.txt" {
		t.Errorf("a finished row: %q", got)
	}
	// And so it is drawn: on the rows in progress, not on the finished one.
	var with, without []string
	for _, r := range listRows(m, 1, 4) {
		if spinnerIn(r) != "" {
			with = append(with, r)
		} else {
			without = append(without, r)
		}
	}
	joined := strings.Join(with, "|")
	if len(with) != 2 || !strings.Contains(joined, "pkg.tar/") || !strings.Contains(joined, "sub/") {
		t.Errorf("rows with a spinner: %q", with)
	}
	if len(without) != 1 || !strings.Contains(without[0], "done.txt") {
		t.Errorf("rows without: %q", without)
	}
}

func TestTheSpinnerAnimatesWhileSomethingIsInProgress(t *testing.T) {
	m, _ := runningDiff()
	if !m.spinning {
		t.Fatal("the spinner's clock did not start with something in progress")
	}
	var pending diffItem
	for _, it := range m.lines {
		if it.name == "pkg.tar/" {
			pending = it
		}
	}
	seen := map[string]bool{}
	for i := 0; i < len(spinFrames)+3; i++ {
		seen[spinnerIn(m.rowText(pending))] = true
		if _, cmd := m.Update(spinMsg{}); cmd == nil {
			t.Fatalf("the clock stopped while rows are still in progress (beat %d)", i)
		}
	}
	if len(seen) != len(spinFrames) || seen[""] {
		t.Errorf("saw %d distinct frames, want %d: %v", len(seen), len(spinFrames), seen)
	}
	// The same clock is not started twice.
	if m.maybeSpin() != nil {
		t.Error("a second clock was started while one is running")
	}
}

func TestTheSpinnerStopsWhenTheWorkIsDone(t *testing.T) {
	m, run := runningDiff()
	// Everything finishes, and the viewer takes its last snapshot.
	run.FakeFinish()
	drive(m, m.syncLines())
	if m.anyPending() {
		t.Fatal("something is still marked in progress")
	}
	// The next beat of the clock stops it.
	if _, cmd := m.Update(spinMsg{}); cmd != nil {
		t.Error("the clock keeps running with nothing in progress")
	}
	if m.spinning {
		t.Error("the clock is marked running after it stopped")
	}
	for i, r := range listRows(m, 1, 8) {
		if spinnerIn(r) != "" {
			t.Errorf("row %d still has a spinner: %q", i, r)
		}
	}
	// And it starts again for something that goes into progress.
	// a comparison that is not finished, with something new in progress
	m.run = analysis.NewFakeRun(append(runningDiffLines(), analysis.FakeLine{Kind: analysis.Changed, Path: "later.tar", Pending: true}), false)
	if cmd := m.syncLines(); cmd == nil || !m.spinning {
		t.Error("the clock did not start for a row that went into progress")
	}
}

func TestSpinnerFramesAreOneColumnWide(t *testing.T) {
	if len(spinFrames) < 4 {
		t.Fatal("too few frames to look like it is moving")
	}
	seen := map[string]bool{}
	for _, f := range spinFrames {
		if w := ansi.StringWidth(f); w != 1 {
			t.Errorf("frame %q is %d columns wide: it would shift the row", f, w)
		}
		if seen[f] {
			t.Errorf("frame %q is repeated", f)
		}
		seen[f] = true
	}
}

// A finished comparison does not keep the screen redrawing.
func TestNoClockForAFinishedComparison(t *testing.T) {
	m := nested(t) // finished, nothing pending
	if m.spinning || m.anyPending() {
		t.Errorf("spinning=%v pending=%v on a finished comparison", m.spinning, m.anyPending())
	}
	if cmd := m.maybeSpin(); cmd != nil {
		t.Error("a clock was started with nothing in progress")
	}
	if cmd := m.syncLines(); cmd != nil {
		if _, ok := cmd().(spinMsg); ok {
			t.Error("syncing a finished comparison asks for a spinner beat")
		}
	}
}
