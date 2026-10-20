package main

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func numbered(i int) (string, string) {
	return fmt.Sprintf("file %d\nold\n", i), fmt.Sprintf("file %d\nnew\n", i)
}

// Switching entries faster than they can be read must not read them all at once
// (the filesystems underneath are not safe for it), must not read the ones passed
// over, and must end up showing the one the cursor stopped on.
func TestFastSwitchingReadsOneAtATimeAndEndsOnTheLastEntry(t *testing.T) {
	m := manyFiles(t, 20, 100, 30, numbered)
	m.rendered = map[renderKey]string{} // forget the first entry's, to start clean
	m.data = map[itemKey]*pairData{}
	m.order, m.loading = nil, map[itemKey]bool{}

	// Ten key presses, none of whose commands has run yet: as when keys arrive
	// faster than the reads finish.
	var cmds []tea.Cmd
	for i := 0; i < 10; i++ {
		_, cmd := m.key("j")
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}
	if len(cmds) != 1 {
		t.Fatalf("%d reads started for ten moves; want exactly one at a time", len(cmds))
	}
	if len(m.loading) != 1 {
		t.Fatalf("%d reads in flight", len(m.loading))
	}
	// Let them run, as the runtime would, and catch up.
	for len(cmds) > 0 {
		cmd := cmds[0]
		cmds = cmds[1:]
		_, next := m.Update(cmd())
		if next != nil {
			cmds = append(cmds, next)
		}
		if len(m.loading) > 1 {
			t.Fatalf("%d reads in flight at once", len(m.loading))
		}
	}
	if m.cur != 10 {
		t.Fatalf("cursor %d, want 10", m.cur)
	}
	it, _ := m.selected()
	if got := plain(m.rendered[m.rk(it)]); !strings.Contains(got, "f010.txt") || !strings.Contains(got, "file 10") {
		t.Errorf("the pane does not show the entry the cursor stopped on:\n%s", got)
	}
	// Only the first (already under way) and the last were ever read; the eight
	// between were passed over.
	if len(m.data) < 1 || len(m.data) > 2 { // the first may be a probe of its head, not a read
		var names []string
		for k := range m.data {
			names = append(names, k.path)
		}
		t.Errorf("%d files were read, want 1 or 2 (where the cursor stopped, and perhaps the first): %v", len(m.data), names)
	}
}

func TestOnlyAFewFilesStayInMemory(t *testing.T) {
	m := manyFiles(t, 15, 100, 30, numbered)
	for i := 1; i < 15; i++ {
		key(m, "j")
		if len(m.data) > cachedFiles {
			t.Fatalf("after %d entries, %d files' bytes are held; want at most %d", i+1, len(m.data), cachedFiles)
		}
	}
	// The one being shown is among them.
	it, _ := m.selected()
	if _, ok := m.data[it.key()]; !ok {
		t.Error("the entry on screen was let go")
	}
	// Going back to an old one reads it again.
	for i := 0; i < 14; i++ {
		key(m, "k")
	}
	first, _ := m.selected()
	if got := plain(m.rendered[m.rk(first)]); !strings.Contains(got, "file 0") {
		t.Errorf("the first entry again:\n%s", got)
	}
}

// A read for an entry the cursor has left must not leave the pane showing it.
func TestAStaleReadDoesNotReplaceThePane(t *testing.T) {
	m := manyFiles(t, 5, 100, 30, numbered)
	m.rendered = map[renderKey]string{}
	m.data = map[itemKey]*pairData{}
	m.order, m.loading = nil, map[itemKey]bool{}

	_, first := m.key("j") // starts reading entry 1
	_, none := m.key("j")  // entry 2: waits
	if first == nil || none != nil {
		t.Fatalf("first %v, second %v", first != nil, none != nil)
	}
	_, next := m.Update(first()) // entry 1 arrives; the cursor is on 2
	if got := plain(m.pane.View()); strings.Contains(got, "f001.txt") {
		t.Errorf("the pane shows the entry the cursor left:\n%s", got)
	}
	drive(m, next)
	if got := plain(m.pane.View()); !strings.Contains(got, "f002.txt") {
		t.Errorf("the pane does not end up on entry 2:\n%s", got)
	}
}
