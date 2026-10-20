package main

import (
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
	"os"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// nested opens a viewer on two directories with changes at several depths:
//
//	top.txt          changed
//	pkg.tar          a container, x.bin changed inside it
//	sub/y.txt        changed
//	sub/new.txt      only in B
//	sub/old.txt      only in A
//	sub/deep/x.txt   changed
func nested(t *testing.T) *diffTUI {
	bs := func(files map[string]string) []byte {
		b, _ := os.ReadFile(writeTar(t, "x.tar", files))
		return b
	}
	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{
		"top.txt": []byte("one\n"), "sub/y.txt": []byte("one\n"), "sub/old.txt": []byte("only a\n"),
		"sub/deep/x.txt": []byte("one\n"), "same.txt": []byte("same\n"),
		"pkg.tar": bs(map[string]string{"x.bin": "old", "same.bin": "same"}),
	})
	writeTree(t, b, map[string][]byte{
		"top.txt": []byte("two\n"), "sub/y.txt": []byte("two\n"), "sub/new.txt": []byte("only b\n"),
		"sub/deep/x.txt": []byte("two\n"), "same.txt": []byte("same\n"),
		"pkg.tar": bs(map[string]string{"x.bin": "new!", "same.bin": "same"}),
	})
	m := newDiffTUI("t", compared(t, a, b))
	open(m, 120, 30)
	return m
}

func sel(m *diffTUI) string {
	it, _ := m.selected()
	return it.name
}

func goTo(t *testing.T, m *diffTUI, name string) {
	t.Helper()
	for i, it := range m.lines {
		if it.name == name {
			_, cmd := m.move(i)
			drive(m, cmd)
			return
		}
	}
	t.Fatalf("no entry %q in %s", name, names(m.lines))
}

func crumb(m *diffTUI) string {
	rows := strings.Split(plain(m.View().Content), "\n")
	return strings.TrimSpace(rows[len(rows)-2])
}

func TestNavigateIntoDirectoriesAndBack(t *testing.T) {
	m := nested(t)
	if got := names(m.lines); got != "sub/ | pkg.tar/ | top.txt" {
		t.Fatalf("the top level: %q, want directories first, then the changed files and containers", got)
	}
	if crumb(m) != "t" {
		t.Errorf("breadcrumb at the top: %q", crumb(m))
	}

	// A directory: its pane says what is under it.
	if sel(m) != "sub/" {
		t.Fatalf("starts on %q", sel(m))
	}
	pane := plain(m.pane.View())
	for _, want := range []string{"sub/", "3 changed", "1 added", "1 removed", "enter or l to go in"} {
		if want == "3 changed" {
			want = "changed"
		}
		if !strings.Contains(pane, want) {
			t.Errorf("a directory's pane lacks %q:\n%s", want, pane)
		}
	}

	// In: the names are relative to it, ".." leads, and the crumb says where we are.
	key(m, "enter")
	if got := names(m.lines); got != ".. | deep/ | new.txt | old.txt | y.txt" {
		t.Fatalf("inside sub/: %q", got)
	}
	if crumb(m) != "t / sub" {
		t.Errorf("breadcrumb: %q", crumb(m))
	}
	if !strings.Contains(plain(m.pane.View()), "back up to t") {
		t.Errorf(".. pane: %s", plain(m.pane.View()))
	}
	// A level in a level, and a file there shows its diff.
	goTo(t, m, "deep/")
	key(m, "l")
	if got := names(m.lines); got != ".. | x.txt" || crumb(m) != "t / sub / deep" {
		t.Fatalf("inside sub/deep/: %q, crumb %q", got, crumb(m))
	}
	goTo(t, m, "x.txt")
	if got := plain(m.rendered[m.rk(m.lines[m.cur])]); !strings.Contains(got, "+ two") || !strings.Contains(got, "- one") {
		t.Errorf("the file's diff:\n%s", got)
	}

	// Out, one level at a time, the cursor back on the entry we went in by.
	key(m, "backspace")
	if got := sel(m); got != "deep/" || crumb(m) != "t / sub" {
		t.Errorf("after backspace: on %q, crumb %q; want deep/ in sub", got, crumb(m))
	}
	key(m, "h")
	if got := sel(m); got != "sub/" || crumb(m) != "t" {
		t.Errorf("after h: on %q, crumb %q; want sub/ at the top", got, crumb(m))
	}
	// Nowhere further up.
	key(m, "left")
	if sel(m) != "sub/" || len(m.frames) != 1 {
		t.Errorf("ascended past the top: %d frames", len(m.frames))
	}
	// The arrows go in and out as well.
	key(m, "right")
	if len(m.frames) != 2 {
		t.Errorf("right did not go in: %d frames", len(m.frames))
	}
	key(m, "left")
	if len(m.frames) != 1 || sel(m) != "sub/" {
		t.Errorf("left did not come out: %d frames, on %q", len(m.frames), sel(m))
	}
}

func TestNavigateIntoAContainerAndTheDotDotRow(t *testing.T) {
	m := nested(t)
	goTo(t, m, "pkg.tar/")
	// The container's own pane is the pair, and says what is inside is listed.
	if got := plain(m.pane.View()); !strings.Contains(got, "pkg.tar") {
		t.Errorf("a container's pane: %s", got)
	}
	key(m, "enter")
	if got := names(m.lines); got != ".. | x.bin" {
		t.Fatalf("inside pkg.tar: %q (same.bin is unchanged: not listed)", got)
	}
	if crumb(m) != "t / pkg.tar" {
		t.Errorf("crumb %q", crumb(m))
	}
	goTo(t, m, "x.bin")
	if m.lines[m.cur].path != "pkg.tar/x.bin" {
		t.Errorf("x.bin's path is %q", m.lines[m.cur].path)
	}
	// The ".." row, entered, goes back.
	goTo(t, m, "..")
	key(m, "enter")
	if len(m.frames) != 1 || sel(m) != "pkg.tar/" {
		t.Errorf("enter on ..: %d frames, on %q", len(m.frames), sel(m))
	}

	// Entering something with nothing inside says so, and stays.
	goTo(t, m, "top.txt")
	key(m, "enter")
	if len(m.frames) != 1 || sel(m) != "top.txt" {
		t.Errorf("entered a file: %d frames, on %q", len(m.frames), sel(m))
	}
	if !strings.Contains(crumb(m), "nothing inside it differs") {
		t.Errorf("no note on entering a file: %q", crumb(m))
	}
	key(m, "k") // the note goes with the next key
	if strings.Contains(crumb(m), "nothing inside") {
		t.Errorf("the note stayed: %q", crumb(m))
	}

	// esc goes back up, and quits only from the top.
	goTo(t, m, "sub/")
	key(m, "enter")
	key(m, "esc")
	if len(m.frames) != 1 {
		t.Error("esc did not go back up")
	}
	if _, cmd := m.key("esc"); cmd == nil {
		t.Error("esc at the top does not quit")
	}
	if _, cmd := m.key("q"); cmd == nil {
		t.Error("q does not quit")
	}
}

// Going back up puts the cursor on the entry gone in by, at every level, even
// when the level is longer than the screen.
func TestAscendingRestoresTheCursorAndTheScroll(t *testing.T) {
	tar := func(body string) []byte {
		b, _ := os.ReadFile(writeTar(t, "x.tar", map[string]string{"m.bin": body}))
		return b
	}
	a, b := t.TempDir(), t.TempDir()
	for i := 0; i < 60; i++ {
		name := "d/f" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".txt"
		writeTree(t, a, map[string][]byte{name: []byte("one\n")})
		writeTree(t, b, map[string][]byte{name: []byte("two\n")})
	}
	// A container at the end of a long level, so reaching it scrolls.
	writeTree(t, a, map[string][]byte{"d/zzz.tar": tar("old")})
	writeTree(t, b, map[string][]byte{"d/zzz.tar": tar("new!")})
	m := newDiffTUI("t", compared(t, a, b))
	open(m, 100, 14)

	key(m, "enter") // into d/
	goTo(t, m, "zzz.tar/")
	level, top := m.cur, m.top
	if top == 0 || level != len(m.lines)-1 {
		t.Fatalf("the level did not scroll to its last entry: cursor %d of %d, top %d", level, len(m.lines), top)
	}
	key(m, "enter") // into the container
	if got := names(m.lines); got != ".. | m.bin" {
		t.Fatalf("inside zzz.tar: %q", got)
	}
	key(m, "h")
	if sel(m) != "zzz.tar/" || m.cur != level || m.top != top {
		t.Errorf("back in d/: on %q, cursor %d top %d; want zzz.tar/ at cursor %d top %d", sel(m), m.cur, m.top, level, top)
	}
	if m.cur < m.top || m.cur >= m.top+m.bodyHeight() {
		t.Errorf("the restored cursor %d is off screen [%d, %d)", m.cur, m.top, m.top+m.bodyHeight())
	}
	key(m, "h")
	if sel(m) != "d/" || len(m.frames) != 1 {
		t.Errorf("back at the top: on %q, %d frames", sel(m), len(m.frames))
	}
	// Going in again starts a fresh level at its top, as browse does.
	key(m, "l")
	if m.cur != 0 || m.top != 0 {
		t.Errorf("re-entering d/: cursor %d top %d, want a fresh level", m.cur, m.top)
	}
}

func TestMouseNavigatesLikeBrowse(t *testing.T) {
	m := nested(t) // sub/ | pkg.tar/ | top.txt, the cursor on sub/
	rowY := func(i int) int { return 1 + i - m.top }

	// A click on a row that is not chosen chooses it, and only that.
	click(m, 3, rowY(1), tea.MouseLeft)
	if sel(m) != "pkg.tar/" || len(m.frames) != 1 {
		t.Fatalf("clicked pkg.tar/: on %q with %d frames", sel(m), len(m.frames))
	}
	// A click on the chosen row goes in.
	click(m, 3, rowY(1), tea.MouseLeft)
	if len(m.frames) != 2 || names(m.lines) != ".. | x.bin" {
		t.Fatalf("clicked the chosen row: %d frames, %q", len(m.frames), names(m.lines))
	}
	// A click on ".." goes up at once, however it was chosen.
	click(m, 3, rowY(0), tea.MouseLeft)
	if len(m.frames) != 1 || sel(m) != "pkg.tar/" {
		t.Errorf("clicked ..: %d frames, on %q", len(m.frames), sel(m))
	}
	// The wheel moves the cursor within the level.
	wheel(m, 3, 5, tea.MouseWheelUp)
	if sel(m) != "sub/" {
		t.Errorf("wheel up: on %q", sel(m))
	}
	wheel(m, 3, 5, tea.MouseWheelDown)
	wheel(m, 3, 5, tea.MouseWheelDown)
	if sel(m) != "top.txt" {
		t.Errorf("wheel down twice: on %q", sel(m))
	}
	// Clicking a file's row twice does not go anywhere: there is nowhere to go.
	click(m, 3, rowY(2), tea.MouseLeft)
	if len(m.frames) != 1 {
		t.Errorf("entered a file by clicking: %d frames", len(m.frames))
	}
}

func TestAViewOfADirectoryHasABreadcrumbRowAndFits(t *testing.T) {
	m := nested(t)
	key(m, "enter")
	rows := strings.Split(plain(m.View().Content), "\n")
	if len(rows) != 30 {
		t.Fatalf("%d rows, want the window's 30", len(rows))
	}
	if !strings.Contains(rows[28], "t / sub") {
		t.Errorf("the breadcrumb is not the row above the keys: %q", rows[28])
	}
	if !strings.Contains(rows[29], "enter/l in") || !strings.Contains(rows[29], "q quit") {
		t.Errorf("the keys row: %q", rows[29])
	}
	// A deep path is cut at its start, keeping where we are.
	deeper := new(analysis.Level)
	deeper.SetTitle(strings.Repeat("deeper/", 30) + "here")
	m.frames = append(m.frames, navFrame{level: deeper})
	if c := crumb(m); !strings.HasSuffix(c, "here") || !strings.HasPrefix(c, "…") {
		t.Errorf("a long breadcrumb: %q", c)
	}
}
