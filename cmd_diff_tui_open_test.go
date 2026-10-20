package main

import (
	"archive/tar"
	"bytes"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// tarAt is a tar of files (name, content pairs) with every member stamped mtime:
// the same members stamped differently are the same files in a different tar.
func tarAt(t *testing.T, mtime time.Time, files ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i+1 < len(files); i += 2 {
		h := &tar.Header{Name: files[i], Mode: 0o644, Size: int64(len(files[i+1])), ModTime: mtime}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(files[i+1]))
	}
	tw.Close()
	return buf.Bytes()
}

// containers opens a viewer on two directories:
//
//	pkg_v1.tar / pkg_v2.tar  the same members (one a tar itself), packed at different times
//	changed_v1.tar / _v2.tar one member differs
//	top.txt                  an ordinary file, changed
func containers(t *testing.T) *diffTUI {
	t1, t2 := time.Unix(1_700_000_000, 0), time.Unix(1_800_000_000, 0)
	inner := func(time.Time) string { return string(tarAt(t, t1, "x.bin", "inner-x", "y.bin", "inner-y")) } // the same bytes on both sides
	members := func(at time.Time) []byte {
		return tarAt(t, at, "a.bin", strings.Repeat("alpha-", 200), "b.bin", strings.Repeat("bravo-", 200), "inner.tar", inner(at))
	}
	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{
		"pkg_v1.tar": members(t1), "changed_v1.tar": tarAt(t, t1, "m.bin", "old", "k.bin", "keep"), "top.txt": []byte("one\n"),
	})
	writeTree(t, b, map[string][]byte{
		"pkg_v2.tar": members(t2), "changed_v2.tar": tarAt(t, t1, "m.bin", "NEW!", "k.bin", "keep"), "top.txt": []byte("two\n"),
	})
	m := newDiffTUI("t", compared(t, a, b))
	open(m, 130, 30)
	return m
}

// awaitClosed waits for ch, and fails the test instead of hanging if it is not closed.
func awaitClosed(t *testing.T, ch chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// waitListed runs the snapshot clock until the level in view has been listed.
func waitListed(t *testing.T, m *diffTUI) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for m.busy() || m.ticking {
		if time.Now().After(deadline) {
			t.Fatal("the level was never finished being listed")
		}
		_, cmd := m.Update(tickMsg{})
		drive(m, cmd)
		time.Sleep(5 * time.Millisecond)
	}
	drive(m, m.syncLines())
}

func TestAContainerPairReadsNothingAndSaysWhatIsInside(t *testing.T) {
	m := containers(t)
	if got := names(m.lines); got != "changed_v1.tar -> changed_v2.tar | pkg_v1.tar -> pkg_v2.tar | top.txt" &&
		!strings.Contains(got, "pkg_v1.tar -> pkg_v2.tar") {
		t.Fatalf("the level: %q", got)
	}
	find := func(sub string) int {
		for i, it := range m.lines {
			if strings.Contains(it.name, sub) {
				return i
			}
		}
		t.Fatalf("no entry with %q in %s", sub, names(m.lines))
		return 0
	}

	// Renamed, every member the same: its own bytes differ (the times), and it says
	// what is true, not "content identical".
	m.move(find("pkg_v1"))
	if cmd := m.refresh(); cmd != nil {
		t.Error("looking at a container started a read")
	}
	pane := plain(m.pane.View())
	for _, want := range []string{"renamed, nothing inside it differs", "Nothing inside it differs", "enter or l to list its members"} {
		if !strings.Contains(pane, want) {
			t.Errorf("the pane lacks %q:\n%s", want, pane)
		}
	}
	if strings.Contains(pane, "content identical") {
		t.Errorf("claims the contents are identical:\n%s", pane)
	}
	if len(m.data) != 0 || len(m.loading) != 0 {
		t.Errorf("a container's pane read %d files (%d loading)", len(m.data), len(m.loading))
	}

	// A container with a change inside: what, and no read.
	m.move(find("changed_v1"))
	pane = plain(m.pane.View())
	if !strings.Contains(pane, "Inside it: 1 changed") || !strings.Contains(pane, "enter or l to go in") {
		t.Errorf("a container with a change inside:\n%s", pane)
	}
	if len(m.data) != 0 {
		t.Errorf("read %d files for a container", len(m.data))
	}

	// The overlap view is how to ask for its raw bytes.
	key(m, "3")
	if len(m.data) == 0 || !strings.Contains(plain(m.pane.View()), "Overlap") {
		t.Errorf("view 3 did not read the container's bytes: %d files, pane:\n%s", len(m.data), plain(m.pane.View()))
	}
	key(m, "1")
	if strings.Contains(plain(m.pane.View()), "Overlap") {
		t.Error("view 1 shows the overlap of a container")
	}
}

// What the headers say is shown, so a pair of tars that differ only in their
// times says so; it is read in the background, and no member is read.
func TestAContainerPairShowsWhatTheirHeadersDiffer(t *testing.T) {
	m := containers(t)
	var cmd tea.Cmd
	for i, it := range m.lines {
		if strings.Contains(it.name, "pkg_v1") {
			_, cmd = m.move(i)
		}
	}
	if cmd == nil {
		t.Fatal("the headers were not read")
	}
	if !strings.Contains(plain(m.pane.View()), "reading their headers") {
		t.Errorf("no sign it is reading:\n%s", plain(m.pane.View()))
	}
	drive(m, cmd)
	pane := plain(m.pane.View())
	for _, want := range []string{"mtime of 3 of 3 members", "a.bin", "2023-11-14 22:13:20 -> 2027-01-15 08:00:00"} {
		if !strings.Contains(pane, want) {
			t.Errorf("the pane lacks %q:\n%s", want, pane)
		}
	}
	if len(m.data) != 0 {
		t.Errorf("read %d files", len(m.data))
	}
	// Unchanged headers are said to be unchanged.
	goTo(t, m, "changed_v1.tar -> changed_v2.tar/")
	if pane := plain(m.pane.View()); !strings.Contains(pane, "size") || !strings.Contains(pane, "m.bin") {
		t.Errorf("changed_v1 pane:\n%s", pane)
	}
}

func TestEnterOpensAContainerWithNothingDifferingAndListsItsMembers(t *testing.T) {
	m := containers(t)
	for i, it := range m.lines {
		if strings.Contains(it.name, "pkg_v1") {
			m.move(i)
		}
	}
	if sel(m) == "" || m.lines[m.cur].kids {
		t.Fatalf("on %q, kids=%v: this container has nothing differing inside, so no lines of its own", sel(m), m.lines[m.cur].kids)
	}
	// It used to say "nothing inside it differs" and refuse.
	key(m, "enter")
	if len(m.frames) != 2 {
		t.Fatalf("enter did not open it: %d frames, note %q", len(m.frames), m.note)
	}
	waitListed(t, m)
	if got := names(m.lines); got != ".. | a.bin | b.bin | inner.tar" {
		t.Fatalf("its members: %q", got)
	}
	for _, it := range m.lines[1:] {
		if it.kind != '=' {
			t.Errorf("%s is %q, want unchanged", it.name, it.kind)
		}
	}
	if !strings.Contains(crumb(m), "pkg_v1.tar -> pkg_v2.tar") {
		t.Errorf("breadcrumb: %q", crumb(m))
	}

	// A member's own pane.
	goTo(t, m, "a.bin")
	if got := plain(m.rendered[m.rk(m.lines[m.cur])]); !strings.Contains(got, "identical content") {
		t.Errorf("an unchanged member's pane:\n%s", got)
	}

	// A member that is a container goes the same way, a level further in.
	goTo(t, m, "inner.tar")
	key(m, "enter")
	waitListed(t, m)
	if got := names(m.lines); got != ".. | x.bin | y.bin" || len(m.frames) != 3 {
		t.Fatalf("inside inner.tar: %q, %d frames", got, len(m.frames))
	}
	// And back out, the cursor on where it went in.
	key(m, "h")
	if sel(m) != "inner.tar" || len(m.frames) != 2 {
		t.Errorf("back up: on %q, %d frames", sel(m), len(m.frames))
	}
	key(m, "h")
	if len(m.frames) != 1 || !strings.Contains(sel(m), "pkg_v1") {
		t.Errorf("back at the top: on %q, %d frames", sel(m), len(m.frames))
	}
	// An ordinary file still has nothing to go into.
	goTo(t, m, "top.txt")
	key(m, "enter")
	if len(m.frames) != 1 || !strings.Contains(crumb(m), "nothing inside it differs") {
		t.Errorf("a plain file: %d frames, %q", len(m.frames), crumb(m))
	}
}

// While its members are being listed the level says so, shows what it has so
// far, and the clocks run; when it is done they stop.
func TestAMembersLevelFillsInAndShowsItIsBusy(t *testing.T) {
	m := containers(t)
	for i, it := range m.lines {
		if strings.Contains(it.name, "pkg_v1") {
			m.move(i)
		}
	}
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	analysis.SetStepHook(func(path string) {
		if path == "b.bin" {
			once.Do(func() { close(reached) })
			<-release
		}
	})
	t.Cleanup(func() { analysis.SetStepHook(nil) })

	key(m, "enter")
	awaitClosed(t, reached, "the listing to reach b.bin") // a.bin is listed; b.bin is next
	drive(m, m.syncLines())
	if !m.busy() || !m.ticking || !m.spinning {
		t.Fatalf("busy=%v ticking=%v spinning=%v part-way", m.busy(), m.ticking, m.spinning)
	}
	if got := names(m.lines); got != ".. | a.bin" {
		t.Errorf("part-way: %q, want what has been found", got)
	}
	if !strings.Contains(plain(m.View().Content), "listing its members") {
		t.Error("the footer does not say it is still listing")
	}
	close(release)
	waitListed(t, m)
	if got := names(m.lines); got != ".. | a.bin | b.bin | inner.tar" {
		t.Errorf("when done: %q", got)
	}
	if m.busy() || m.ticking {
		t.Errorf("still busy=%v ticking=%v when done", m.busy(), m.ticking)
	}
	if _, cmd := m.Update(spinMsg{}); cmd != nil || m.spinning {
		t.Error("the spinner's clock kept running after the level was listed")
	}
	if strings.Contains(plain(m.View().Content), "listing its members") {
		t.Error("the footer still says it is listing")
	}
}

func TestLabelForARenamedContainer(t *testing.T) {
	c := containers(t)
	var it diffItem
	for _, x := range c.lines {
		if x.kind == '>' || x.kind == '≈' {
			it = x
		}
	}
	if it.kind == 0 {
		t.Skip("no renamed container in this tree")
	}
	if it.kind == '>' && it.e.Title() != "renamed, nothing inside it differs" {
		t.Errorf("label %q", it.e.Title())
	}
	// A renamed plain file really is identical.
	if got := (analysis.Entry{Kind: analysis.Renamed}).Title(); got != "renamed, content identical" {
		t.Errorf("label for a renamed file: %q", got)
	}
}

// Looking at a container pair the first pass stopped at has it compared there: the
// viewer tells the comparison where it is looking, and the level fills in.
func TestSelectingAContainerComparesItsMembers(t *testing.T) {
	t1 := time.Unix(1_700_000_000, 0)
	pkg := func(content string) []byte {
		return tarAt(t, t1, "inner.tar", string(tarAt(t, t1, "x.bin", content)), "keep.txt", "same")
	}
	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{"pkg_v1.tar": pkg("old")})
	writeTree(t, b, map[string][]byte{"pkg_v2.tar": pkg("new!")})
	run := analysis.Start(analysis.Config{A: a, B: b, Depth: 1, AutoDeepen: 1})
	defer run.Close()
	<-run.Done()
	m := newDiffTUI("t", run)
	open(m, 120, 30)
	if len(m.lines) != 1 {
		t.Fatalf("the level: %s", names(m.lines))
	}
	drive(m, m.refresh()) // looking at it: the comparison goes into it
	waitListed(t, m)
	if it, ok := m.selected(); !ok || !it.e.Compared || !it.kids || !strings.Contains(it.summary, "changed") {
		t.Errorf("after looking at it: %+v", it)
	}
}
