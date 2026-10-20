package main

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func click(m *diffTUI, x, y int, button tea.MouseButton) {
	_, cmd := m.Update(tea.MouseClickMsg(tea.Mouse{X: x, Y: y, Button: button}))
	drive(m, cmd)
}

func wheel(m *diffTUI, x, y int, button tea.MouseButton) {
	_, cmd := m.Update(tea.MouseWheelMsg(tea.Mouse{X: x, Y: y, Button: button}))
	drive(m, cmd)
}

// manyFiles opens a viewer on n changed text files, the window w by h.
func manyFiles(t *testing.T, n, w, h int, body func(i int) (a, b string)) *diffTUI {
	a, b := t.TempDir(), t.TempDir()
	for i := 0; i < n; i++ {
		x, y := "one\n", "two\n"
		if body != nil {
			x, y = body(i)
		}
		name := fmt.Sprintf("f%03d.txt", i)
		writeTree(t, a, map[string][]byte{name: []byte(x)})
		writeTree(t, b, map[string][]byte{name: []byte(y)})
	}
	m := newDiffTUI("t", compared(t, a, b))
	open(m, w, h)
	return m
}

func TestMouseClickSelectsARow(t *testing.T) {
	m := manyFiles(t, 12, 100, 20, nil)
	// Row 0 is the title; the list starts on row 1.
	click(m, 3, 1+5, tea.MouseLeft)
	if m.cur != 5 {
		t.Fatalf("clicked the 6th row, cursor is %d", m.cur)
	}
	if it, _ := m.selected(); !strings.Contains(plain(m.rendered[m.rk(it)]), "f005.txt") {
		t.Errorf("the pane was not read for the clicked row")
	}
	// Anywhere along the row, as far as the list goes.
	click(m, m.listWidth()-1, 1+8, tea.MouseLeft)
	if m.cur != 8 {
		t.Errorf("a click at the row's far edge: cursor %d, want 8", m.cur)
	}
	// Not on: the empty rows under the last entry, the title, the footer, the
	// separator between list and pane, another button.
	for name, c := range map[string][3]int{
		"below the last entry": {3, 1 + 14, int(tea.MouseLeft)},
		"the title":            {3, 0, int(tea.MouseLeft)},
		"the footer":           {3, 19, int(tea.MouseLeft)},
		"the separator":        {m.listWidth(), 1 + 2, int(tea.MouseLeft)},
		"the right button":     {3, 1 + 2, int(tea.MouseRight)},
		"the middle button":    {3, 1 + 2, int(tea.MouseMiddle)},
	} {
		click(m, c[0], c[1], tea.MouseButton(c[2]))
		if m.cur != 8 {
			t.Errorf("a click on %s moved the cursor to %d", name, m.cur)
		}
	}
}

// As in browse, the wheel over the list moves the cursor.
func TestMouseWheelMovesTheCursor(t *testing.T) {
	m := manyFiles(t, 40, 100, 14, nil) // 11 body rows, 40 entries
	if m.top != 0 || m.cur != 0 {
		t.Fatalf("start: top %d cursor %d", m.top, m.cur)
	}
	wheel(m, 3, 5, tea.MouseWheelDown)
	if m.cur != 1 {
		t.Errorf("one notch down: cursor %d, want 1", m.cur)
	}
	if it, _ := m.selected(); !strings.Contains(plain(m.rendered[m.rk(it)]), "f001.txt") {
		t.Error("the pane was not read for the entry the wheel moved to")
	}
	// A refresh tick leaves the cursor where it is.
	for i := 0; i < 3; i++ {
		_, cmd := m.Update(tickMsg{})
		drive(m, cmd)
	}
	if m.cur != 1 {
		t.Errorf("a tick moved the cursor to %d", m.cur)
	}
	// Down past the page: the view follows, and it stops at the ends.
	for i := 0; i < 60; i++ {
		wheel(m, 3, 5, tea.MouseWheelDown)
		if m.cur < m.top || m.cur >= m.top+m.bodyHeight() {
			t.Fatalf("cursor %d is outside the view [%d, %d)", m.cur, m.top, m.top+m.bodyHeight())
		}
	}
	if m.cur != 39 || m.top != 40-m.bodyHeight() {
		t.Errorf("at the end: cursor %d top %d, want 39 and %d", m.cur, m.top, 40-m.bodyHeight())
	}
	for i := 0; i < 60; i++ {
		wheel(m, 3, 5, tea.MouseWheelUp)
	}
	if m.cur != 0 || m.top != 0 {
		t.Errorf("back at the start: cursor %d top %d", m.cur, m.top)
	}
	// Ignored: other buttons, and the title and footer rows.
	wheel(m, 3, 5, tea.MouseWheelLeft)
	wheel(m, 3, 0, tea.MouseWheelDown)
	wheel(m, 3, m.height-1, tea.MouseWheelDown)
	wheel(m, 3, m.height-2, tea.MouseWheelDown) // the breadcrumb row
	if m.cur != 0 {
		t.Errorf("the cursor moved for something that is not a wheel over the list: %d", m.cur)
	}
}

func TestMouseWheelScrollsThePane(t *testing.T) {
	long := func(i int) (string, string) {
		var a, b strings.Builder
		for l := 0; l < 200; l++ {
			fmt.Fprintf(&a, "line %d\n", l)
			fmt.Fprintf(&b, "LINE %d\n", l)
		}
		return a.String(), b.String()
	}
	m := manyFiles(t, 3, 100, 20, long)
	if m.pane.YOffset() != 0 {
		t.Fatal("the pane starts scrolled")
	}
	paneX := m.listWidth() + 5
	wheel(m, paneX, 6, tea.MouseWheelDown)
	if m.pane.YOffset() != wheelStep {
		t.Errorf("one notch over the pane: offset %d, want %d", m.pane.YOffset(), wheelStep)
	}
	wheel(m, paneX, 6, tea.MouseWheelUp)
	wheel(m, paneX, 6, tea.MouseWheelUp)
	if m.pane.YOffset() != 0 {
		t.Errorf("scrolled above the top: %d", m.pane.YOffset())
	}
	// Over the list it moves the cursor, not the pane.
	wheel(m, paneX, 6, tea.MouseWheelDown)
	before := m.pane.YOffset()
	wheel(m, 3, 6, tea.MouseWheelUp) // to a row that is already there: at the top, nothing moves
	if m.pane.YOffset() != before {
		t.Errorf("a wheel over the list scrolled the pane: %d -> %d", before, m.pane.YOffset())
	}
	// Moving to another entry starts the pane at the top.
	wheel(m, 3, 6, tea.MouseWheelDown)
	if m.cur != 1 || m.pane.YOffset() != 0 {
		t.Errorf("a new entry: cursor %d, pane offset %d; want the next entry with its pane at the top", m.cur, m.pane.YOffset())
	}
}

func TestMouseTabsSwitchViewsAndWrap(t *testing.T) {
	m := manyFiles(t, 2, 100, 20, nil)
	lw := m.listWidth()
	_, hits := m.tabStrip()
	if len(hits) != modeCount+2 {
		t.Fatalf("%d hit regions, want a tab per view, the wrap and the word switches", len(hits))
	}
	at := func(h tabHit) (x, y int) { return lw + 1 + h.x0 + 1, 1 }
	for i := 1; i < len(hits); i++ {
		if hits[i].x0 < hits[i-1].x1 {
			t.Errorf("regions %d and %d overlap", i-1, i)
		}
	}

	// Click each view.
	for _, mode := range []int{modeStrings, modeOverlap, modeAuto} {
		x, y := at(hits[mode])
		click(m, x, y, tea.MouseLeft)
		if m.mode != mode {
			t.Errorf("clicked the %s tab: mode is %s", modeNames[mode], modeNames[m.mode])
		}
	}
	// The strip says which is on, and the right column's first row is the strip.
	m.mode = modeStrings
	rows := strings.Split(plain(m.View().Content), "\n")
	if strip := rows[1]; !strings.Contains(strip, "diff") || !strings.Contains(strip, "strings") ||
		!strings.Contains(strip, "overlap") || !strings.Contains(strip, "[x] wrap") {
		t.Errorf("the strip over the pane: %q", rows[1])
	}
	if len(rows) != 20 {
		t.Errorf("%d rows, want the window's 20", len(rows))
	}
	for i, r := range rows {
		if w := ansi.StringWidth(r); w > 100 {
			t.Errorf("row %d is %d wide in a 100-wide window", i, w)
		}
	}

	// The wrap switch.
	x, y := at(hits[modeCount])
	click(m, x, y, tea.MouseLeft)
	if m.wrap {
		t.Error("clicking wrap did not turn it off")
	}
	if !strings.Contains(plain(strings.Split(m.View().Content, "\n")[1]), "[ ] wrap") {
		t.Error("the strip still shows wrap on")
	}
	click(m, x, y, tea.MouseLeft)
	if !m.wrap {
		t.Error("clicking wrap again did not turn it on")
	}

	// Between tabs, on the strip but on nothing, and on the strip's empty end.
	before := m.mode
	click(m, lw+1+hits[0].x1, 1, tea.MouseLeft) // the gap after the first tab
	click(m, 98, 1, tea.MouseLeft)
	click(m, lw+1+hits[modeStrings].x0+1, 2, tea.MouseLeft) // a row below the strip
	if m.mode != before || !m.wrap {
		t.Errorf("a click on nothing changed something: mode %d wrap %v", m.mode, m.wrap)
	}
	// Clicking the tab already on asks for nothing more.
	x, y = at(hits[m.mode])
	if _, cmd := m.Update(tea.MouseClickMsg(tea.Mouse{X: x, Y: y, Button: tea.MouseLeft})); cmd != nil {
		t.Error("clicking the active tab started a redraw")
	}
}

func TestMouseIsOnAndYCopies(t *testing.T) {
	m := manyFiles(t, 2, 100, 20, nil)
	if m.View().MouseMode != tea.MouseModeCellMotion {
		t.Errorf("mouse mode %v: wheel and click are not reported", m.View().MouseMode)
	}
	if _, cmd := m.key("y"); cmd == nil {
		t.Error("y does not copy the pane")
	}
	if !strings.Contains(plain(m.View().Content), "y copy") {
		t.Error("the footer does not mention y")
	}
}
