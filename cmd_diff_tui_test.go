package main

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// drive runs cmd and every command its result asks for, feeding the messages
// back as bubbletea would (a batch runs each of its commands), until nothing is
// left to do. Timer ticks are not followed: a test steps time itself.
func drive(m *diffTUI, cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	switch msg := cmd().(type) {
	case tickMsg, spinMsg:
	case tea.BatchMsg:
		for _, c := range msg {
			drive(m, c)
		}
	default:
		_, next := m.Update(msg)
		drive(m, next)
	}
}

func key(m *diffTUI, k string) {
	_, cmd := m.key(k)
	drive(m, cmd)
}

// finished is a comparison that has already run to the end.
func finished(t *treeDiffTally) *liveRun {
	r := newLiveRun()
	r.setRoot(t)
	close(r.done)
	return r
}

// open sizes the window and takes the first snapshot, as bubbletea would.
func open(m *diffTUI, w, h int) {
	_, cmd := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	drive(m, cmd)
	drive(m, m.syncLines())
}

func writeTree(t *testing.T, root string, files map[string][]byte) {
	for n, b := range files {
		p := filepath.Join(root, n)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func plain(s string) string { return ansi.Strip(s) }

func noStrings(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	r.Read(b)
	for i, c := range b { // keep it free of accidental strings
		if c >= 0x20 && c < 0x7f {
			b[i] = 0
		}
	}
	return b
}

func TestInteractiveDiffShowsWhatDiffers(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	blob, insert := noStrings(r, 120<<10), noStrings(r, 2000)
	binA := append(append([]byte("version=1.0.0\x00"), blob...), "tail marker\x00"...)
	binB := append(append(append([]byte("version=1.0.1\x00"), blob[:50000]...), insert...), append(blob[50000:], "tail marker\x00new feature flag\x00"...)...)

	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{
		"notes.txt": []byte("alpha\nbeta\ngamma\ndelta\n"),
		"blob.bin":  binA,
		"gone.txt":  []byte("only on the A side\n"),
		"same.txt":  []byte("unchanged\n"),
	})
	writeTree(t, b, map[string][]byte{
		"notes.txt": []byte("alpha\nBETA CHANGED\ngamma\ndelta\n"),
		"blob.bin":  binB,
		"new.bin":   {0x7f, 'E', 'L', 'F', 0, 1, 2, 3, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0},
		"same.txt":  []byte("unchanged\n"),
	})
	tally, ok, err := diffTree(a, b, 3, false, nil)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	m := newDiffTUI("test", finished(tally))
	open(m, 140, 40)

	byPath := map[string]int{}
	for i, it := range m.lines {
		byPath[it.path] = i
	}
	for _, p := range []string{"notes.txt", "blob.bin", "gone.txt", "new.bin"} {
		if _, ok := byPath[p]; !ok {
			t.Fatalf("no line for %s among %d lines", p, len(m.lines))
		}
	}
	if _, ok := byPath["same.txt"]; ok {
		t.Error("an unchanged file is listed")
	}
	show := func(p string) string {
		t.Helper()
		_, cmd := m.move(byPath[p])
		if cmd == nil { // already there, in another view
			cmd = m.refresh()
		}
		drive(m, cmd)
		it, _ := m.selected()
		return plain(m.rendered[m.rk(it)])
	}

	// A text file: a line diff, with the changed line and numbers.
	m.mode = modeAuto
	got := show("notes.txt")
	for _, want := range []string{"1 removed, 1 added", "- beta", "+ BETA CHANGED", "@@ -1,4 +1,4 @@"} {
		if !strings.Contains(got, want) {
			t.Errorf("text diff lacks %q:\n%s", want, got)
		}
	}

	// A binary: shared vs unique, and the strings that differ.
	got = show("blob.bin")
	for _, want := range []string{"Overlap", "shared", "unique", "identical start", "- version=1.0.0", "+ version=1.0.1", "+ new feature flag"} {
		if !strings.Contains(got, want) {
			t.Errorf("binary view lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "unchanged lines") {
		t.Error("a binary was shown as a line diff")
	}

	// The strings view is the full diff of the strings.
	m.mode = modeStrings
	got = show("blob.bin")
	for _, want := range []string{"Strings", "1 removed, 2 added", "version=1.0.0", "new feature flag"} {
		if !strings.Contains(got, want) {
			t.Errorf("strings view lacks %q:\n%s", want, got)
		}
	}

	// The overlap view finds the shared content past the insertion.
	m.mode = modeOverlap
	got = show("blob.bin")
	if !strings.Contains(got, "content-defined chunks") || !strings.Contains(got, "each cell is 1/64") {
		t.Errorf("overlap view: %s", got)
	}

	// Files on one side only show their content.
	m.mode = modeAuto
	if got = show("gone.txt"); !strings.Contains(got, "only in A") || !strings.Contains(got, "only on the A side") {
		t.Errorf("A-only text:\n%s", got)
	}
	if got = show("new.bin"); !strings.Contains(got, "only in B") || !strings.Contains(got, "hello world") {
		t.Errorf("B-only binary shows no strings:\n%s", got)
	}
}

func TestInteractiveNavigationAndModes(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		writeTree(t, a, map[string][]byte{n: []byte("one\n")})
		writeTree(t, b, map[string][]byte{n: []byte("two\n")})
	}
	tally, _, err := diffTree(a, b, 3, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := newDiffTUI("t", finished(tally))
	open(m, 100, 30)
	if len(m.lines) != 3 || m.cur != 0 {
		t.Fatalf("%d lines, cursor %d", len(m.lines), m.cur)
	}
	key(m, "j")
	key(m, "j")
	key(m, "j") // stops at the last
	if m.cur != 2 {
		t.Errorf("cursor %d after j j j, want 2", m.cur)
	}
	key(m, "g")
	if m.cur != 0 {
		t.Errorf("cursor %d after g", m.cur)
	}
	key(m, "G")
	if m.cur != 2 {
		t.Errorf("cursor %d after G", m.cur)
	}
	key(m, "tab")
	if m.mode != modeStrings {
		t.Errorf("mode %d after tab", m.mode)
	}
	key(m, "3")
	if m.mode != modeOverlap {
		t.Errorf("mode %d after 3", m.mode)
	}
	key(m, "4")
	if m.mode != modeHex {
		t.Errorf("mode %d after 4", m.mode)
	}
	key(m, "tab")
	if m.mode != modeAuto {
		t.Errorf("tab does not wrap: mode %d", m.mode)
	}
	key(m, "x")
	if m.mode != modeHex || !m.hexMore {
		t.Errorf("x: mode %d, more %v", m.mode, m.hexMore)
	}
	key(m, "x")
	if m.hexMore {
		t.Error("x does not toggle")
	}
	key(m, "1")
	if _, cmd := m.key("q"); cmd == nil {
		t.Error("q does not quit")
	}
	// The view draws every row at the window's width, list and pane side by side.
	rows := strings.Split(plain(m.View().Content), "\n")
	if len(rows) != 30 {
		t.Errorf("%d rows, want the window's 30", len(rows))
	}
	for i, r := range rows {
		if w := ansi.StringWidth(r); w > 100 {
			t.Errorf("row %d is %d wide in a 100-wide window", i, w)
		}
	}
}

func names(items []diffItem) string {
	var n []string
	for _, it := range items {
		n = append(n, it.name)
	}
	return strings.Join(n, " | ")
}

// A level lists its directories (made from the paths) first, then its lines in
// the order found; a container with something inside, or still being compared,
// can be gone into; dropped lines are not there; a rename is one name, not a path.
func TestSnapshotLevel(t *testing.T) {
	inner := &treeDiffTally{lines: []*diffLine{{kind: '~', path: "pkg.tar/m.bin"}}}
	running := &diffLine{kind: '~', path: "pkg.tar", subT: inner} // its inside is being compared
	done := &diffLine{kind: '~', path: "cont.zip", sub: []*diffLine{{kind: '+', path: "cont.zip/in.bin"}}}
	root := &treeDiffTally{lines: []*diffLine{
		{kind: '~', path: "top.txt"},
		{kind: '+', path: "sub/new.txt"},
		{kind: '~', path: "sub/deep/x.txt"},
		{kind: '-', path: "sub/old.txt"},
		{kind: '~', path: "gone.txt", drop: true},
		running,
		done,
		{kind: '>', path: "old/a -> new/a"},
		{text: "      (oops)"},
	}}
	m := newDiffTUI("t", newLiveRun())
	top := m.frames[0]

	got := snapshotLevel(root, top, false)
	if want := "sub/ | top.txt | pkg.tar/ | cont.zip/ | old/a -> new/a | (oops)"; names(got) != want {
		t.Errorf("root level:\n got %s\nwant %s", names(got), want)
	}
	byName := map[string]diffItem{}
	for _, it := range got {
		byName[it.name] = it
	}
	if it := byName["sub/"]; it.kind != '/' || !it.kids || it.summary != "1 changed, 1 added, 1 removed" {
		t.Errorf("sub/: %+v", it)
	}
	if it := byName["pkg.tar/"]; !it.pending || !it.kids {
		t.Errorf("pkg.tar/ should be pending and enterable: %+v", it)
	}
	if it := byName["cont.zip/"]; it.pending || !it.kids {
		t.Errorf("cont.zip/ should be enterable and not pending: %+v", it)
	}
	if it := byName["top.txt"]; it.kids || it.pending {
		t.Errorf("top.txt has nothing inside: %+v", it)
	}
	// A pending row keeps its marker in the snapshot; the viewer draws a spinner there.
	if got := byName["pkg.tar/"].text; got != "~ pkg.tar/" {
		t.Errorf("pending row: %q", got)
	}

	// ".." heads every level but the first.
	if up := snapshotLevel(root, top, true); up[0].name != ".." || up[0].kind != '↑' || len(up) != len(got)+1 {
		t.Errorf("with up: %s", names(up))
	}

	// Into a directory: its own names, and the directories below it.
	sub := navFrame{source: top.source, dir: "sub/"}
	if want := "deep/ | new.txt | old.txt"; names(snapshotLevel(root, sub, false)) != want {
		t.Errorf("sub/: %s, want %s", names(snapshotLevel(root, sub, false)), want)
	}
	deep := navFrame{source: top.source, dir: "sub/deep/"}
	if got := snapshotLevel(root, deep, false); names(got) != "x.txt" || got[0].kind != '~' {
		t.Errorf("sub/deep/: %s", names(got))
	}

	// Into a container: what was found inside it, live while it is still running.
	in := navFrame{strip: "pkg.tar", source: func(*treeDiffTally) []*diffLine { return lineKids(running) }}
	if names(snapshotLevel(root, in, false)) != "m.bin" {
		t.Errorf("pkg.tar: %s", names(snapshotLevel(root, in, false)))
	}
	liveMu.Lock()
	inner.lines = append(inner.lines, &diffLine{kind: '+', path: "pkg.tar/n.bin"}) // found since
	liveMu.Unlock()
	if names(snapshotLevel(root, in, false)) != "m.bin | n.bin" {
		t.Errorf("pkg.tar after more was found: %s", names(snapshotLevel(root, in, false)))
	}
	live(func() { running.subT, running.sub = nil, inner.lines }) // finished: same frame, now from sub
	if names(snapshotLevel(root, in, false)) != "m.bin | n.bin" {
		t.Errorf("pkg.tar once finished: %s", names(snapshotLevel(root, in, false)))
	}

	if got := snapshotLevel(nil, top, false); len(got) != 0 {
		t.Errorf("before there is anything: %s", names(got))
	}
}

// The viewer opens before the comparison is done, shows what has been found so
// far including inside a container still being compared, keeps the cursor where
// it was as more arrives, and has the whole result once it finishes.
func TestInteractiveOpensBeforeTheComparisonFinishes(t *testing.T) {
	mkTar := func(files map[string]string) []byte {
		bs, _ := os.ReadFile(writeTar(t, "x.tar", files))
		return bs
	}
	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{
		"a1.txt": []byte("one\n"), "a2.txt": []byte("one\n"),
		"pkg.tar": mkTar(map[string]string{"x.txt": "old", "y.txt": "same"}),
		"z9.txt":  []byte("one\n"),
	})
	writeTree(t, b, map[string][]byte{
		"a1.txt": []byte("two\n"), "a2.txt": []byte("two\n"),
		"pkg.tar": mkTar(map[string]string{"x.txt": "new!", "y.txt": "same"}),
		"z9.txt":  []byte("two\n"),
	})

	// Hold the comparison when it reaches a member inside the tar, until released.
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	diffStep = func(path string) {
		if path == "pkg.tar/y.txt" {
			once.Do(func() { close(reached) })
			<-release
		}
	}
	t.Cleanup(func() { diffStep = nil })

	run := newLiveRun()
	go func() {
		defer close(run.done)
		diffTree(a, b, 3, false, run.setRoot)
	}()
	<-reached // part-way: a1, a2 are done; pkg.tar is open, x.txt found

	m := newDiffTUI("t", run)
	open(m, 120, 30)
	got := names(m.lines)
	if got != "a1.txt | a2.txt | pkg.tar/" {
		t.Errorf("part-way the level is %q; want what is found so far, the container among it", got)
	}
	if m.lines[2].pending != true {
		t.Error("the container still being compared is not marked")
	}
	if m.complete {
		t.Error("the viewer thinks the comparison is complete")
	}
	if !strings.Contains(plain(m.View().Content), "comparing") {
		t.Error("the footer does not say the comparison is running")
	}

	// The pending container is selectable and says so, and reads nothing.
	m.move(2)
	drive(m, m.refresh())
	if !strings.Contains(plain(m.pane.View()), "still being compared") {
		t.Errorf("pending container's pane: %s", plain(m.pane.View()))
	}

	// Going into it shows what has been found inside so far.
	_, cmd := m.descend()
	drive(m, cmd)
	if got := names(m.lines); got != ".. | x.txt" {
		t.Errorf("inside the running container: %q, want what is found so far", got)
	}
	if !strings.Contains(plain(m.View().Content), "pkg.tar") {
		t.Error("the breadcrumb does not name where we are")
	}

	// Let it finish: the level we are in stays, with the same cursor, and no longer
	// reads as running.
	m.move(1) // on x.txt
	close(release)
	<-run.done
	drive(m, m.syncLines())
	if !m.complete {
		t.Error("not complete after the comparison finished")
	}
	if sel, _ := m.selected(); sel.name != "x.txt" {
		t.Errorf("the cursor moved off x.txt to %q as the comparison finished", sel.name)
	}
	if got := names(m.lines); got != ".. | x.txt" { // y.txt is unchanged: not listed
		t.Errorf("inside, once finished: %q", got)
	}

	// Back up: the cursor is on the container it went into, which has finished.
	_, cmd = m.ascend()
	drive(m, cmd)
	if sel, _ := m.selected(); sel.name != "pkg.tar/" || sel.pending {
		t.Errorf("after coming back up: on %q pending=%v", sel.name, sel.pending)
	}
	if got := names(m.lines); got != "a1.txt | a2.txt | pkg.tar/ | z9.txt" {
		t.Errorf("the finished level: %q", got)
	}
	// A tick after it finished does not ask for another.
	if _, cmd := m.Update(tickMsg{}); cmd != nil {
		if _, again := cmd().(tickMsg); again {
			t.Error("still ticking after the comparison finished")
		}
	}
}

// The viewer reads the tree while the comparison writes it: under the race
// detector this fails if any of it is not guarded.
func TestInteractiveSnapshotsWhileComparing(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	a, b := t.TempDir(), t.TempDir()
	for i := 0; i < 60; i++ {
		name := filepath.Join("d", strings.Repeat("x", i%3), "f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".bin")
		body := noStrings(r, 20<<10)
		writeTree(t, a, map[string][]byte{name: body})
		other := append([]byte(nil), body...)
		if i%2 == 0 {
			other[100] ^= 0xff
		}
		writeTree(t, b, map[string][]byte{name: other})
	}
	run := newLiveRun()
	go func() {
		defer close(run.done)
		diffTree(a, b, 3, false, run.setRoot)
	}()
	m := newDiffTUI("t", run)
	open(m, 120, 30)
	for !run.finished() {
		root, _, _ := run.get()
		snapshotLevel(root, m.frame(), false)
		m.View()
	}
	drive(m, m.syncLines())
	// Everything is under d/: one directory, counting the thirty changed files below it.
	if len(m.lines) != 1 || m.lines[0].name != "d/" || m.lines[0].summary != "30 changed" {
		t.Errorf("the finished level: %s (%q), want d/ with 30 changed", names(m.lines), m.lines[0].summary)
	}
}
