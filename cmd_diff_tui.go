package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// The interactive diff: the tree of differences on the left, and for the one
// under the cursor what actually differs on the right — a line diff for text;
// for a binary, how much of it is shared and how much unique to each side, and
// a diff of the strings inside it.
//
// It opens at once and fills in as the comparison runs, which is a goroutine of
// its own. The viewer never touches the live tree: it takes snapshots of it
// (snapshotDiff) every so often, under the lock the comparison writes under.

const (
	viewLimit     = 32 << 20  // bytes of each side read to show a difference
	viewLimitMore = 256 << 20 // ... after asking for more ('f')
	contextLines  = 3
	stringsMin    = 6
	tickEvery     = 250 * time.Millisecond
)

// The right pane's views.
const (
	modeAuto    = iota // a line diff for text; overlap and strings for a binary
	modeStrings        // a diff of the printable strings in each side
	modeOverlap        // shared and unique bytes
	modeHex            // the bytes that differ, in hex
	modeCount
)

var modeNames = [modeCount]string{"diff", "strings", "overlap", "hex"}

const (
	hexAuto      = 256     // bytes differing, up to which a binary's pane shows them in hex unasked
	hexBytes     = 4 << 10 // ... in the hex view
	hexMoreBytes = 1 << 20 // ... in the hex view after x
)

// diffItem is one row of the list as the viewer holds it: an entry of the level,
// as the comparison had it when the snapshot was taken.
type diffItem struct {
	e       analysis.Entry
	name    string // as listed in its level: "notes.txt", "sub/", "pkg.tar/" (it has something inside), ".."
	text    string // the row
	kind    rune   // the entry's: ~ > ≈ + - =; '/' for a directory; '↑' for ".."
	path    string
	pending bool   // its inside is still being compared
	kids    bool   // there is somewhere to go in: a directory, or a container with differences inside
	summary string // for a directory: what is under it
}

// itemKey is what an item is, so a line that has become something else (an
// added file found to be a rename, a container whose comparison finished) is
// read again.
type itemKey = analysis.EntryKey

func (it diffItem) key() itemKey { return it.e.Key() }

// itemOf is an entry as the list shows it.
func itemOf(e analysis.Entry) diffItem {
	it := diffItem{e: e, name: e.Name, kind: rune(e.Kind), path: e.Path, pending: e.Pending, kids: e.HasKids, summary: e.Summary}
	if e.Kind == analysis.Note {
		it.text = e.Text
		return it
	}
	it.text = rowText(it)
	return it
}

// navFrame is one level being looked at, as in browse: the entries of a
// directory or of a container, to go into and come back out of.
type navFrame struct {
	level *analysis.Level
	// Kept while a deeper level is on top, to put the cursor back where it was.
	cur, top int
	sel      string
}

// rowText is how an item reads in the list.
func rowText(it diffItem) string {
	switch it.kind {
	case '↑':
		return "  .."
	case '/':
		return "  " + it.name + "  (" + it.summary + ")"
	}
	s := string(it.kind) + " " + it.name
	if n := it.e.SizeNote; n != "" {
		s += "  " + n
	}
	return s // a pending row's marker is drawn as a spinner (diffTUI.rowText)
}

var (
	styAdd    = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styDel    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styHunk   = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	styDim    = lipgloss.NewStyle().Faint(true)
	styMid    = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	styTitle  = lipgloss.NewStyle().Bold(true)
	styCursor = lipgloss.NewStyle().Reverse(true)
)

// clean makes a line safe to put on a terminal: tabs widened, other control
// characters shown as a dot.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteString("    ")
		case r < 0x20 || r == 0x7f:
			b.WriteRune('·')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// gutter is the width of a diff line's two line numbers and its mark.
const gutter = 16

// fit puts text after prefix on one or more lines of at most width columns:
// wrapped, each continuation indented under the text with a ↳ so it is not taken
// for a line of its own, or, with wrap off, cut off at width.
func fit(prefix, text string, width int, wrap bool, sty lipgloss.Style) string {
	pw := ansi.StringWidth(prefix)
	if !wrap {
		return sty.Render(ansi.Truncate(prefix+text, width, "…"))
	}
	tw := max(width-pw, 8)
	var b strings.Builder
	for i, part := range strings.Split(ansi.Wrap(text, tw, ""), "\n") {
		if i == 0 {
			b.WriteString(sty.Render(prefix + part))
		} else {
			b.WriteString("\n" + sty.Render(strings.Repeat(" ", max(pw-2, 0))+"↳ "+part))
		}
	}
	return b.String()
}

// renderLines draws a unified diff, coloured, wrapped or cut to width.
func renderLines(ls []analysis.Line, width int, wrap bool) string {
	var b strings.Builder
	for _, l := range ls {
		text := clean(l.Text)
		if len(l.Hi) > 0 {
			text = markWords(l.Text, l.Hi)
		}
		var s string
		switch l.Op {
		case '@':
			s = styHunk.Render(ansi.Truncate(text, width, "…"))
		case '+':
			s = fit(fmt.Sprintf("%6s %6d + ", "", l.B), text, width, wrap, styAdd)
		case '-':
			s = fit(fmt.Sprintf("%6d %6s - ", l.A, ""), text, width, wrap, styDel)
		default:
			s = fit(fmt.Sprintf("%6d %6d   ", l.A, l.B), text, width, wrap, styDim)
		}
		b.WriteString(s)
		b.WriteByte('\n')
	}
	return b.String()
}

// markWords is clean(text) with the byte ranges hi in reverse video. Reverse is
// switched off again by itself, not reset, so the line's own colour carries on.
func markWords(text string, hi [][2]int) string {
	var b strings.Builder
	at := 0
	for _, r := range hi {
		b.WriteString(clean(text[at:r[0]]))
		b.WriteString("\x1b[7m" + clean(text[r[0]:r[1]]) + "\x1b[27m")
		at = r[1]
	}
	b.WriteString(clean(text[at:]))
	return b.String()
}

// byteCount is a number of bytes spelt out, as opposed to a size: "1 byte",
// "31 bytes".
func byteCount(n int64) string {
	if n == 1 {
		return "1 byte"
	}
	return fmt.Sprintf("%d bytes", n)
}

// differs is the verb to go with a count: "1 byte differs", "31 bytes differ".
func differs(n int64) string {
	if n == 1 {
		return "differs"
	}
	return "differ"
}

// verdictLine says, for two binaries, whether only their printable strings
// differ: whether everything outside them is identical.
func verdictLine(det *analysis.Detail) string {
	v := det.Verdict
	if v == nil {
		return ""
	}
	part := ""
	if det.A.Truncated || det.B.Truncated {
		part = " (in the part read)"
	}
	switch {
	case v.Only:
		return styAdd.Render(fmt.Sprintf("Only strings differ%s: the %s outside printable strings are identical", part, humanBytes(v.ResidueA))) + "\n"
	case v.ResidueDiffering > 0:
		// The count has its own unit: "31 of the 21.1 MiB" reads as 31 MiB.
		return styMid.Render(fmt.Sprintf("Not only strings%s: %s of the %s outside printable strings %s too", part, byteCount(v.ResidueDiffering), humanBytes(v.ResidueA), differs(v.ResidueDiffering))) + "\n"
	case v.ResidueDiffering < 0:
		return styMid.Render(fmt.Sprintf("Not only strings%s: what is outside them differs in size too (A %s, B %s)", part, humanBytes(v.ResidueA), humanBytes(v.ResidueB))) + "\n"
	}
	return ""
}

func pct(part, whole int64) string {
	if whole == 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(part)/float64(whole))
}

// mapBar draws how shared each stretch of a file is: tall and green where the
// other side has the same content, short and red where it is unique.
func mapBar(cells []float64) string {
	rs := []rune(" ▁▂▃▄▅▆▇█")
	var b strings.Builder
	for _, f := range cells {
		if f <= 0 { // nothing here is in the other file: a low red bar, not a blank that reads as no data
			b.WriteString(styDel.Render("▁"))
			continue
		}
		r := rs[int(f*float64(len(rs)-1)+0.5)]
		switch {
		case f >= 0.9:
			b.WriteString(styAdd.Render(string(r)))
		case f >= 0.5:
			b.WriteString(styMid.Render(string(r)))
		default:
			b.WriteString(styDel.Render(string(r)))
		}
	}
	return b.String()
}

// renderHex draws where two binaries differ outside strings: each hunk's bytes on
// each side, with the rest of the rows they fall in as context. explicit is the
// hex view (which says why there is nothing to show); otherwise it is the auto
// view's section, which h == nil leaves out.
func renderHex(h *analysis.HexReport, explicit bool, width int) string {
	switch {
	case h == nil:
		if explicit {
			return "no bytes differ outside the printable strings (see the strings view)\n"
		}
		return ""
	case h.Unavailable:
		return styDim.Render("too large, and different in size, to find the bytes that differ") + "\n"
	case h.Total == 0:
		return "no bytes differ outside the printable strings (see the strings view)\n"
	}
	per := 16
	if width < 80 {
		per = 8
	}
	var sb strings.Builder
	sb.WriteString(styTitle.Render(fmt.Sprintf("Bytes: %s differ in %d place(s)", byteCount(int64(h.Total)), h.Places)))
	if !explicit {
		sb.WriteString(styDim.Render("   (4 for hex view, x for more)"))
	}
	sb.WriteString("\n\n")
	for _, hk := range h.Hunks {
		fmt.Fprintf(&sb, "%s\n", styMid.Render(fmt.Sprintf("@@ A 0x%x +%d   B 0x%x +%d @@", hk.OffA, hk.LenA, hk.OffB, hk.LenB)))
		sb.WriteString(hexRows("- ", hk.A, per, styDel))
		sb.WriteString(hexRows("+ ", hk.B, per, styAdd))
		sb.WriteString("\n")
	}
	if h.More > 0 {
		sb.WriteString(styDim.Render(fmt.Sprintf("… %d more place(s); x shows more", h.More)) + "\n")
	}
	return sb.String()
}

// hexRows lays out a window of bytes in rows of per, the hunk's bytes in style
// and the rest dim.
func hexRows(mark string, w analysis.HexRow, per int, sty lipgloss.Style) string {
	if len(w.Bytes) == 0 {
		return styDim.Render(fmt.Sprintf("%s(nothing at 0x%x)", mark, w.Offset)) + "\n"
	}
	var sb strings.Builder
	for row := 0; row < len(w.Bytes); row += per {
		var hexs, asc strings.Builder
		for i := row; i < row+per; i++ {
			if i >= len(w.Bytes) {
				hexs.WriteString("   ")
				continue
			}
			st := styDim
			if i >= w.From && i < w.To {
				st = sty
			}
			c := w.Bytes[i]
			hexs.WriteString(st.Render(fmt.Sprintf("%02x", c)) + " ")
			if c < 0x20 || c >= 0x7f {
				c = '.'
			}
			asc.WriteString(st.Render(string(c)))
		}
		fmt.Fprintf(&sb, "%s%08x  %s |%s|\n", mark, w.Offset+row, hexs.String(), asc.String())
	}
	return sb.String()
}

func renderOverlap(o analysis.Overlap, truncA, truncB bool) string {
	var b strings.Builder
	how := "measured byte for byte: the stretches the two have in common, in order"
	if o.Chunk > 0 {
		how = fmt.Sprintf("content-defined chunks, about %s: an insertion does not shift what follows; a changed byte makes its whole chunk unique", humanBytes(int64(o.Chunk)))
	}
	b.WriteString(styTitle.Render("Overlap") + styDim.Render("  ("+how+")") + "\n\n")
	row := func(name string, size, shared, unique int64, trunc bool) {
		note := ""
		if trunc {
			note = styDim.Render("  (first part only)")
		}
		fmt.Fprintf(&b, "  %s  %12s   shared %12s %5s   unique %12s %5s%s\n", name,
			humanBytes(size), humanBytes(shared), pct(shared, size), humanBytes(unique), pct(unique, size), note)
	}
	row("A", o.SizeA, o.SharedA, o.UniqueA(), truncA)
	row("B", o.SizeB, o.SharedB, o.UniqueB(), truncB)
	b.WriteString("\n")
	fmt.Fprintf(&b, "  A %s\n  B %s\n", mapBar(o.MapA), mapBar(o.MapB))
	b.WriteString(styDim.Render("    each cell is 1/64 of the file: tall green = shared with the other, yellow = partly, low red = only in this one") + "\n\n")
	fmt.Fprintf(&b, "  identical start %s, identical end %s\n", humanBytes(o.Prefix), humanBytes(o.Suffix))
	if o.Differing >= 0 {
		if o.Differing == 0 {
			b.WriteString("  same size, every byte equal\n")
		} else {
			fmt.Fprintf(&b, "  same size: %s %s at the same offset (%s), first at 0x%x\n", byteCount(o.Differing), differs(o.Differing), pct(o.Differing, o.SizeA), o.FirstDiff)
		}
	}
	return b.String()
}

// sideNote says when only part of a file was read.
func sideNote(d *analysis.EntryDetail) string {
	var parts []string
	if d.A.Truncated {
		parts = append(parts, fmt.Sprintf("A: first %s of %s", humanBytes(int64(d.A.Read)), humanBytes(d.A.Size)))
	}
	if d.B.Truncated {
		parts = append(parts, fmt.Sprintf("B: first %s of %s", humanBytes(int64(d.B.Read)), humanBytes(d.B.Size)))
	}
	if len(parts) == 0 {
		return ""
	}
	return styMid.Render("only part was read ("+strings.Join(parts, "; ")+"); f reads more") + "\n"
}

// maxMetaLines bounds the differences listed for one pair of containers.
const maxMetaLines = 24

// renderHeaders says what differs in the headers of a pair of tars (or the
// directories of two zips): which details, in how many members, and the first few.
func renderHeaders(h *analysis.Headers) string {
	var b strings.Builder
	b.WriteString("\n" + styTitle.Render("What each records about its members") + styDim.Render("  (times, owners, modes: not their contents)") + "\n\n")
	if h.Err != "" {
		b.WriteString(styDel.Render("could not read the headers: "+h.Err) + "\n")
		return b.String()
	}
	r := h.Report
	if r.Identical() {
		b.WriteString(fmt.Sprintf("All %d members' headers are identical too: the containers differ only in what lies between\nthem (padding, a trailer).\n", r.Members))
		return b.String()
	}
	if s := r.Summary(); s != "" {
		b.WriteString(styMid.Render("Differs: "+s) + "\n")
	}
	if n := len(r.OnlyA); n > 0 {
		b.WriteString(styDel.Render(fmt.Sprintf("%d member(s) only in A, e.g. %s", n, r.OnlyA[0])) + "\n")
	}
	if n := len(r.OnlyB); n > 0 {
		b.WriteString(styAdd.Render(fmt.Sprintf("%d member(s) only in B, e.g. %s", n, r.OnlyB[0])) + "\n")
	}
	b.WriteString("\n")
	for i, d := range r.Diffs {
		if i == maxMetaLines {
			b.WriteString(styDim.Render(fmt.Sprintf("… and %d more", len(r.Diffs)-maxMetaLines)) + "\n")
			break
		}
		b.WriteString(fmt.Sprintf("  %s\n      %-6s %s -> %s\n", clean(d.Name), d.Field, d.A, d.B))
	}
	return b.String()
}

// loadMeta reads the headers of a pair of containers in the background, one pair
// at a time, as the contents of a file are read.
func (m *diffTUI) loadMeta(it diffItem) tea.Cmd {
	if m.metaBusy {
		return nil // when it lands, the pair the cursor is on by then goes next
	}
	m.metaBusy = true
	k := it.key()
	return func() tea.Msg { return metaMsg{k, renderHeaders(it.e.ReadHeaders())} }
}

// probe reads the heads of an entry's sides, off the viewer's goroutine.
func probe(it diffItem) tea.Cmd {
	k := it.key()
	return func() tea.Msg {
		it.e.Probe()
		return probedMsg{k}
	}
}

// describeContainer is the pane for a pair of containers: what was found inside
// them, with no read of either. The overlap view (3) is how to ask for their raw
// bytes.
func (m *diffTUI) describeContainer(it diffItem) string {
	var b strings.Builder
	b.WriteString(styTitle.Render(it.e.Title()+"  "+it.path) + "\n")
	b.WriteString(styDim.Render(fmt.Sprintf("A %s    B %s", humanBytes(it.e.SizeA), humanBytes(it.e.SizeB))) + "\n\n")
	if it.summary != "" {
		b.WriteString("Inside it: " + it.summary + "\n\n" + styDim.Render("enter or l to go in") + "\n")
	} else {
		b.WriteString("Nothing inside it differs: its members are all the same.\n\n" +
			styDim.Render("enter or l to list its members") + "\n")
	}
	b.WriteString("\n" + styDim.Render(fmt.Sprintf("3 shows how much of the container's own bytes are shared; that reads the first %s of each.", humanBytes(m.limit))) + "\n")
	return b.String()
}

// renderDetail is the right pane for an item in view mode: what differs between
// the two sides, from the bytes read.
func renderDetail(it diffItem, p *analysis.Pair, mode, width int, wrap, hexMore, words bool) string {
	opts := analysis.Options{Context: diffContext, StringsMin: stringsMin, Words: words, HexBudget: hexBytes}
	if diffContext == 0 {
		opts.Context = analysis.NoContext
	}
	if hexMore {
		opts.HexBudget = hexMoreBytes
	}
	switch mode {
	case modeOverlap:
		opts.View = analysis.ViewOverlap
	case modeHex:
		opts.View = analysis.ViewHex
	case modeStrings:
		opts.View = analysis.ViewStrings
	}
	d := p.Detail(it.e, opts)
	var b strings.Builder
	b.WriteString(styTitle.Render(d.Title+"  "+it.path) + "\n")
	if it.e.SizeA >= 0 && it.e.SizeB >= 0 {
		fmt.Fprintf(&b, styDim.Render("A %s    B %s")+"\n", humanBytes(d.A.Size), humanBytes(d.B.Size))
	}
	b.WriteString("\n")
	if d.Err != "" {
		b.WriteString(styDel.Render("reading: "+d.Err) + "\n")
		return b.String()
	}
	b.WriteString(sideNote(d))
	switch {
	case d.Identical:
		b.WriteString("identical content\n")
		return b.String()
	case d.OneSide != nil:
		return b.String() + renderOneSide(d.OneSide, width, wrap)
	}
	det := d.Bytes
	if det.Verdict != nil {
		b.WriteString(verdictLine(det) + "\n")
	}
	switch {
	case mode == modeOverlap:
		b.WriteString(renderOverlap(*det.Overlap, d.A.Truncated, d.B.Truncated))
	case mode == modeHex:
		b.WriteString(renderHex(det.Hex, true, width))
	case mode == modeStrings:
		b.WriteString(styTitle.Render(fmt.Sprintf("Strings (%d+ chars): %d removed, %d added", stringsMin, det.Strings.Stats.Removed, det.Strings.Stats.Added)) + "\n\n")
		if len(det.Strings.Lines) == 0 {
			b.WriteString("the printable strings are identical\n")
		}
		b.WriteString(renderLines(det.Strings.Lines, width, wrap))
		if det.Strings.Truncated {
			b.WriteString(styDim.Render("… cut off") + "\n")
		}
	case d.Container:
		b.WriteString("a container: what differs inside it is listed beneath it on the left.\n\n")
		b.WriteString(renderOverlap(*det.Overlap, d.A.Truncated, d.B.Truncated))
	case det.Text:
		st := det.Diff.Stats
		b.WriteString(styTitle.Render(fmt.Sprintf("%d removed, %d added, %d unchanged lines", st.Removed, st.Added, st.Same)) + "\n\n")
		if len(det.Diff.Lines) == 0 {
			b.WriteString("the text is identical\n")
		}
		b.WriteString(renderLines(det.Diff.Lines, width, wrap))
		if det.Diff.Truncated {
			b.WriteString(styDim.Render("… cut off") + "\n")
		}
	default:
		b.WriteString(renderOverlap(*det.Overlap, d.A.Truncated, d.B.Truncated))
		if hx := renderHex(det.Hex, false, width); hx != "" {
			b.WriteString("\n" + hx)
		}
		b.WriteString("\n" + styTitle.Render(fmt.Sprintf("Strings: %d removed, %d added", det.Strings.Stats.Removed, det.Strings.Stats.Added)) + styDim.Render("   (tab for the full diff)") + "\n\n")
		b.WriteString(renderLines(det.Strings.Lines, width, wrap))
		if det.Strings.Truncated {
			b.WriteString(styDim.Render("… more in the strings view") + "\n")
		}
	}
	return b.String()
}

// renderOneSide shows a file present on one side only: its start if it is
// text, else the strings in it.
func renderOneSide(o *analysis.OneSide, width int, wrap bool) string {
	var b strings.Builder
	if o.Text {
		for i, ln := range o.Lines {
			b.WriteString(fit(fmt.Sprintf("%6d  ", i+1), clean(ln), width, wrap, lipgloss.NewStyle()) + "\n")
		}
		if o.More {
			b.WriteString(styDim.Render("… more") + "\n")
		}
		return b.String()
	}
	b.WriteString(styDim.Render("binary; the printable strings in it:") + "\n\n")
	for _, s := range o.Strings {
		b.WriteString(fit("", clean(s), width, wrap, lipgloss.NewStyle()) + "\n")
	}
	if o.More {
		b.WriteString(styDim.Render("… more") + "\n")
	}
	return b.String()
}

// ---- the model ----

type diffTUI struct {
	title         string
	run           *analysis.Run
	frames        []navFrame // the levels gone through, the one in view last
	lines         []diffItem // that level's entries
	cur, top      int
	note          string // a word about the last key, until the next one
	want          string // an entry to put the cursor on when the level is next drawn
	width, height int
	pane          viewport.Model
	mode          int
	limit         int64
	wrap          bool // long lines wrapped in the pane, or cut off
	hexMore       bool // the hex view shows hexMoreBytes of what differs, not hexBytes
	words         bool // the words that differ within a changed line are marked
	complete      bool // the last snapshot was taken after the comparison finished
	spinFrame     int  // which frame of the spinner is showing
	spinning      bool // the spinner's clock is running
	ticking       bool // the clock that takes snapshots is running

	data     map[itemKey]*analysis.Pair
	rendered map[renderKey]string
	loading  map[itemKey]bool
	meta     map[itemKey]string // what containers' headers say, by pair
	metaBusy bool               // a pair's headers are being read
	order    []itemKey          // the files in data, oldest first
}

type renderKey struct {
	k     itemKey
	mode  int
	wrap  bool
	more  bool // hexMore
	words bool
}

// rk is what the pane's text for an item depends on.
func (m *diffTUI) rk(it diffItem) renderKey {
	return renderKey{it.key(), m.mode, m.wrap, m.hexMore, m.words}
}

type (
	tickMsg   struct{}
	loadedMsg struct {
		k itemKey
		d *analysis.Pair
	}
	renderedMsg struct {
		k    renderKey
		text string
	}
	// probedMsg says an entry's sides have had their heads read, so what they are is known.
	probedMsg struct{ k itemKey }
	// metaMsg is what a pair of containers' headers say, once read.
	metaMsg struct {
		k    itemKey
		text string
	}
)

func newDiffTUI(title string, run *analysis.Run) *diffTUI {
	m := &diffTUI{
		title: title, run: run, pane: viewport.New(), limit: viewLimit, wrap: true, words: true,
		data: map[itemKey]*analysis.Pair{}, rendered: map[renderKey]string{}, loading: map[itemKey]bool{}, meta: map[itemKey]string{},
		frames: []navFrame{{level: run.Root()}},
	}
	m.frames[0].level.SetTitle(title)
	// Titles, notes and anything else that is not a diff line wrap here; diff
	// lines are wrapped with an indent under their text before they get this far.
	m.pane.SoftWrap = true
	return m
}

func tick() tea.Cmd { return tea.Tick(tickEvery, func(time.Time) tea.Msg { return tickMsg{} }) }

// The spinner on a row still being compared. It has a clock of its own, faster
// than the one that takes snapshots, and one that runs only while something in
// view is in progress, so a finished comparison does not keep redrawing.
var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const spinEvery = 100 * time.Millisecond

type spinMsg struct{}

func spinTick() tea.Cmd { return tea.Tick(spinEvery, func(time.Time) tea.Msg { return spinMsg{} }) }

func (m *diffTUI) anyPending() bool {
	if m.busy() { // the level itself is still being listed
		return true
	}
	for _, it := range m.lines {
		if it.pending {
			return true
		}
	}
	return false
}

// maybeSpin starts the spinner's clock if a row in view is in progress and it is
// not already running.
func (m *diffTUI) maybeSpin() tea.Cmd {
	if m.spinning || !m.anyPending() {
		return nil
	}
	m.spinning = true
	return spinTick()
}

// rowText is how an entry reads in the list now: a row in progress has its
// marker (or the blank where a directory has none) replaced by the spinner.
func (m *diffTUI) rowText(it diffItem) string {
	if !it.pending {
		return it.text
	}
	glyph := spinFrames[m.spinFrame%len(spinFrames)]
	if r := []rune(it.text); len(r) > 0 {
		return glyph + string(r[1:])
	}
	return glyph
}

func (m *diffTUI) Init() tea.Cmd { return tea.Batch(m.syncLines(), m.ensureTick()) }

func (m *diffTUI) selected() (diffItem, bool) {
	if m.cur < 0 || m.cur >= len(m.lines) {
		return diffItem{}, false
	}
	return m.lines[m.cur], true
}

func (m *diffTUI) listWidth() int { return m.width * 2 / 5 }
func (m *diffTUI) paneWidth() int { return max(m.width-m.listWidth()-1, 10) }
func (m *diffTUI) bodyHeight() int {
	return max(m.height-3, 3) // the title above, and the breadcrumb and the keys below
}

func (m *diffTUI) frame() navFrame { return m.frames[len(m.frames)-1] }

// breadcrumb is the levels gone through, as in browse.
func (m *diffTUI) breadcrumb() string {
	var t []string
	for _, f := range m.frames {
		t = append(t, f.level.Title())
	}
	return strings.Join(t, " / ")
}

func (m *diffTUI) layout() {
	m.pane.SetWidth(m.paneWidth())
	m.pane.SetHeight(m.bodyHeight() - 1) // the tab strip is the first row of the right column
}

// ensureVisible scrolls the list so the cursor's row is on screen.
func (m *diffTUI) ensureVisible() {
	if h := m.bodyHeight(); m.cur < m.top {
		m.top = m.cur
	} else if m.cur >= m.top+h {
		m.top = m.cur - h + 1
	}
	m.clampTop()
}

// clampTop keeps the list's first row where there is a list to show.
func (m *diffTUI) clampTop() {
	m.top = max(0, min(m.top, len(m.lines)-m.bodyHeight()))
}

// A tab is a view of the right pane, or the wrap switch, as drawn in the strip
// along its top and as clicked.
type tabHit struct {
	x0, x1 int // columns [x0, x1) of the pane
	mode   int
	wrap   bool // this is the wrap switch, not a view
	words  bool // this is the word-diff switch
}

// tabStrip draws the strip of views and the wrap switch, and says where each is.
func (m *diffTUI) tabStrip() (string, []tabHit) {
	var b strings.Builder
	var hits []tabHit
	x := 0
	add := func(label string, active bool, h tabHit) {
		w := ansi.StringWidth(label)
		h.x0, h.x1 = x, x+w
		hits = append(hits, h)
		if active {
			b.WriteString(styCursor.Render(label))
		} else {
			b.WriteString(styDim.Render(label))
		}
		b.WriteString(" ")
		x += w + 1
	}
	for i, name := range modeNames {
		add(" "+name+" ", i == m.mode, tabHit{mode: i})
	}
	b.WriteString(" ")
	x++
	mark := "[ ]"
	if m.wrap {
		mark = "[x]"
	}
	add(mark+" wrap", false, tabHit{wrap: true})
	mark = "[ ]"
	if m.words {
		mark = "[x]"
	}
	add(mark+" words", false, tabHit{words: true})
	return b.String(), hits
}

// hasDetail says whether an item is something with sides to read.
func hasDetail(it diffItem) bool { return it.e.HasFiles() }

// syncLines takes a snapshot of the comparison and, if it has changed, shows it:
// the cursor stays on the line it was on, and the right pane is redrawn if that
// line became something else.
func (m *diffTUI) syncLines() tea.Cmd {
	cmd := m.syncLevel()
	if spin := m.maybeSpin(); spin != nil {
		return tea.Batch(cmd, spin)
	}
	return cmd
}

func (m *diffTUI) syncLevel() tea.Cmd {
	// Whether it had finished is read first: a snapshot taken after that point is
	// the whole result.
	done := m.run.Finished()
	var items []diffItem
	for _, e := range m.run.Entries(m.frame().level, len(m.frames) > 1) {
		items = append(items, itemOf(e))
	}
	m.complete = done
	prev, hadPrev := m.selected()
	m.lines = items
	// The cursor stays on its entry by name, as more is found around it; or goes
	// to the entry asked for, coming back up from below.
	stay := m.want
	if stay == "" && hadPrev {
		stay = prev.name
	}
	if stay != "" {
		for i, it := range items {
			if it.name == stay {
				m.cur = i
				if m.want != "" {
					hadPrev = false // a new place: draw it
				}
				break
			}
		}
		m.want = ""
	}
	cursorWas := m.cur
	m.cur = max(0, min(m.cur, len(m.lines)-1))
	if m.cur != cursorWas {
		m.ensureVisible()
	} else {
		m.clampTop()
	}
	sel, ok := m.selected()
	if hadPrev && ok && sel.key() == prev.key() {
		return nil
	}
	return m.refresh()
}

// refresh shows what is known for the selected line and starts what is not:
// reading its two sides, then analysing them for the current view.
func (m *diffTUI) refresh() tea.Cmd {
	it, ok := m.selected()
	m.pane.GotoTop()
	switch {
	case !ok && m.complete:
		m.pane.SetContent("nothing differs")
		return nil
	case !ok:
		m.pane.SetContent(styDim.Render("comparing…"))
		return nil
	case it.pending:
		m.pane.SetContent(styTitle.Render(it.path) + "\n\n" + styDim.Render("still being compared; what differs inside it appears beneath it on the left as it is found"))
		return nil
	case !hasDetail(it):
		m.pane.SetContent(m.describe(it))
		return nil
	case it.e.NeedsProbe():
		// Whether it is a container takes a read of its head; one at a time, with
		// the other reads (when it lands the cursor's entry goes next).
		m.pane.SetContent(styDim.Render("looking at it…"))
		if len(m.loading) > 0 {
			return nil
		}
		m.loading[it.key()] = true
		return probe(it)
	case m.mode != modeOverlap && it.e.ContainerPair():
		// Two containers are compared by their members: say what was found, and
		// read none of their contents (a GiB tar's first 32 MiB, over ssh, shows
		// nothing of use). What they record about their members, though, is where
		// they can differ when every member is the same: a header's time.
		base := m.describeContainer(it)
		if sec, ok := m.meta[it.key()]; ok {
			m.pane.SetContent(base + sec)
			return nil
		}
		if !it.e.HeaderFormat() {
			m.pane.SetContent(base)
			return nil
		}
		m.pane.SetContent(base + "\n" + styDim.Render("reading their headers…") + "\n")
		return m.loadMeta(it)
	}
	k := it.key()
	if s, ok := m.rendered[m.rk(it)]; ok {
		m.pane.SetContent(s)
		return nil
	}
	m.pane.SetContent(styDim.Render("reading…"))
	d, ok := m.data[k]
	if !ok || d.Limit != m.limit {
		// One read at a time: moving quickly down the list would otherwise start a
		// read for every row passed, all at once. When this one lands, the next
		// goes for wherever the cursor has got to by then (see loadedMsg).
		if len(m.loading) > 0 {
			return nil
		}
		m.loading[k] = true
		limit := m.limit
		return func() tea.Msg { return loadedMsg{k, analysis.Load(it.e, limit)} }
	}
	return m.analyse(it, d)
}

// describe is the pane for an entry with no pair of files to show: a directory,
// "..", or a note.
func (m *diffTUI) describe(it diffItem) string {
	switch {
	case it.kind == '↑':
		up := "the top"
		if len(m.frames) > 1 {
			up = m.frames[len(m.frames)-2].level.Title()
		}
		return styTitle.Render("..") + "\n\n" + styDim.Render("back up to "+up)
	case it.kind == '/':
		s := styTitle.Render(it.name) + "\n\n" + it.summary + "\n\n" + styDim.Render("enter or l to go in")
		if it.pending {
			s += "\n" + styDim.Render("some of it is still being compared")
		}
		return s
	}
	return styDim.Render(strings.TrimSpace(it.text))
}

// descend goes into the selected entry, as browse does: a directory, or a
// container with differences inside it. ".." goes back up.
func (m *diffTUI) descend() (tea.Model, tea.Cmd) {
	it, ok := m.selected()
	switch {
	case !ok:
		return m, nil
	case it.kind == '↑':
		return m.ascend()
	}
	level, err := m.run.Open(m.frame().level, it.e)
	if err != nil {
		m.note = strings.TrimSuffix(it.name, "/") + ": " + err.Error()
		return m, nil
	}
	next := navFrame{level: level}
	// Remember where we were, so coming back puts the cursor on this entry.
	m.frames[len(m.frames)-1].cur, m.frames[len(m.frames)-1].top, m.frames[len(m.frames)-1].sel = m.cur, m.top, it.name
	m.frames = append(m.frames, next)
	m.lines, m.cur, m.top = nil, 0, 0
	m.note = ""
	return m, tea.Batch(m.syncLines(), m.ensureTick())
}

// busy says whether the level in view is still being listed.
func (m *diffTUI) busy() bool {
	return m.frame().level.Busy()
}

// ensureTick starts the clock that takes snapshots, unless it is running.
func (m *diffTUI) ensureTick() tea.Cmd {
	if m.ticking {
		return nil
	}
	m.ticking = true
	return tick()
}

// ascend goes back up a level, the cursor on the entry it went in by.
func (m *diffTUI) ascend() (tea.Model, tea.Cmd) {
	if len(m.frames) <= 1 {
		return m, nil
	}
	m.frames = m.frames[:len(m.frames)-1]
	f := m.frame()
	m.lines, m.cur, m.top, m.want = nil, f.cur, f.top, f.sel
	m.note = ""
	return m, m.syncLines()
}

// cachedFiles is how many files' bytes are kept: each can be tens of MiB a side.
const cachedFiles = 4

// remember keeps what was read for k, and lets the oldest go beyond cachedFiles.
func (m *diffTUI) remember(k itemKey, d *analysis.Pair) {
	if _, ok := m.data[k]; !ok {
		m.order = append(m.order, k)
	}
	m.data[k] = d
	for len(m.order) > cachedFiles {
		delete(m.data, m.order[0])
		m.order = m.order[1:]
	}
}

// have says whether an item can be shown without reading it again.
func (m *diffTUI) have(it diffItem) bool {
	if _, ok := m.rendered[m.rk(it)]; ok {
		return true
	}
	d, ok := m.data[it.key()]
	return ok && d.Limit == m.limit
}

func (m *diffTUI) analyse(it diffItem, d *analysis.Pair) tea.Cmd {
	k, w := m.rk(it), m.paneWidth()
	return func() tea.Msg { return renderedMsg{k, renderDetail(it, d, k.mode, w, k.wrap, k.more, k.words)} }
}

func (m *diffTUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		m.rendered = map[renderKey]string{} // drawn to a width
		return m, m.refresh()
	case spinMsg:
		m.spinFrame++
		if m.anyPending() {
			return m, spinTick()
		}
		m.spinning = false // nothing in view is in progress: the clock stops
		return m, nil
	case tickMsg:
		// Whether the level was still being listed is read before the snapshot, as
		// with the comparison: a snapshot taken after that point is all of it.
		wasBusy := m.busy()
		cmd := m.syncLines()
		if m.complete && !wasBusy {
			m.ticking = false
			return m, cmd // the last snapshot was of everything there is
		}
		return m, tea.Batch(cmd, tick())
	case loadedMsg:
		delete(m.loading, msg.k)
		m.remember(msg.k, msg.d)
		it, ok := m.selected()
		switch {
		case ok && it.key() == msg.k:
			return m, m.analyse(it, msg.d)
		case ok && hasDetail(it) && !m.have(it):
			// The cursor moved on while that was being read: read where it is now.
			return m, m.refresh()
		}
		return m, nil
	case probedMsg:
		delete(m.loading, msg.k)
		if it, ok := m.selected(); ok && hasDetail(it) {
			return m, m.refresh()
		}
		return m, nil
	case metaMsg:
		m.metaBusy = false
		m.meta[msg.k] = msg.text
		if it, ok := m.selected(); ok && it.e.ContainerPair() && m.mode != modeOverlap {
			if _, have := m.meta[it.key()]; have {
				return m, m.refresh() // the pair the cursor is on: now it can be drawn
			}
			return m, m.loadMeta(it) // the cursor moved on while that was read
		}
		return m, nil
	case renderedMsg:
		m.rendered[msg.k] = msg.text
		if it, ok := m.selected(); ok && msg.k == m.rk(it) {
			m.pane.SetContent(msg.text)
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.key(msg.Keystroke())
	case tea.MouseWheelMsg:
		return m, m.wheel(msg.Mouse())
	case tea.MouseClickMsg:
		return m.click(msg.Mouse())
	}
	return m, nil
}

// wheelStep is the rows a notch of the wheel scrolls.
const wheelStep = 3

// wheel acts on whichever side the pointer is over, as in browse: over the list
// it moves the cursor, over the pane it scrolls.
func (m *diffTUI) wheel(ms tea.Mouse) tea.Cmd {
	dir := 0
	switch ms.Button {
	case tea.MouseWheelUp:
		dir = -1
	case tea.MouseWheelDown:
		dir = 1
	default:
		return nil
	}
	switch {
	case ms.Y < 1 || ms.Y > m.bodyHeight(): // the title and footer rows
	case ms.X < m.listWidth():
		_, cmd := m.move(m.cur + dir)
		return cmd
	case dir < 0:
		m.pane.ScrollUp(wheelStep)
	default:
		m.pane.ScrollDown(wheelStep)
	}
	return nil
}

// click chooses what is under a left click: a row of the list, or a view or the
// wrap switch in the strip over the pane. Row 0 is the title; the body starts at 1.
func (m *diffTUI) click(ms tea.Mouse) (tea.Model, tea.Cmd) {
	if ms.Button != tea.MouseLeft || ms.Y < 1 || ms.Y > m.bodyHeight() {
		return m, nil
	}
	lw := m.listWidth()
	switch {
	case ms.X < lw:
		if row := m.top + ms.Y - 1; row < len(m.lines) {
			// As in browse: a click chooses; a click on what is already chosen, or
			// on "..", goes in (or up) at once.
			already := row == m.cur
			_, cmd := m.move(row)
			if already || m.lines[row].kind == '↑' {
				_, more := m.descend()
				return m, tea.Batch(cmd, more)
			}
			return m, cmd
		}
	case ms.X > lw && ms.Y == 1:
		_, hits := m.tabStrip()
		for _, h := range hits {
			if x := ms.X - lw - 1; x >= h.x0 && x < h.x1 {
				if h.wrap {
					return m.key("w")
				}
				if h.words {
					return m.key("d")
				}
				if h.mode != m.mode {
					m.mode = h.mode
					return m, m.refresh()
				}
			}
		}
	}
	return m, nil
}

func (m *diffTUI) move(to int) (tea.Model, tea.Cmd) {
	to = max(0, min(len(m.lines)-1, to))
	if to == m.cur {
		return m, nil
	}
	m.cur = to
	m.ensureVisible()
	return m, m.refresh()
}

func (m *diffTUI) key(k string) (tea.Model, tea.Cmd) {
	page := max(m.bodyHeight()-1, 1)
	m.note = ""
	switch k {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		if len(m.frames) > 1 {
			return m.ascend()
		}
		return m, tea.Quit
	case "enter", "l", "right":
		return m.descend()
	case "backspace", "h", "left":
		return m.ascend()
	case "j", "down":
		return m.move(m.cur + 1)
	case "k", "up":
		return m.move(m.cur - 1)
	case "g", "home":
		return m.move(0)
	case "G", "end":
		return m.move(len(m.lines) - 1)
	case "ctrl+d":
		return m.move(m.cur + page/2)
	case "ctrl+u":
		return m.move(m.cur - page/2)
	case "pgdown", "space":
		m.pane.PageDown()
	case "pgup", "b":
		m.pane.PageUp()
	case "tab", "m":
		m.mode = (m.mode + 1) % modeCount
		return m, m.refresh()
	case "1", "2", "3", "4":
		m.mode = int(k[0] - '1')
		return m, m.refresh()
	case "d":
		m.words = !m.words
		return m, m.refresh()
	case "x":
		m.hexMore = !m.hexMore
		m.mode = modeHex
		return m, m.refresh()
	case "y":
		// The pane as plain text, to the clipboard, since mouse reporting is what
		// stops the terminal selecting it.
		return m, tea.SetClipboard(ansi.Strip(m.pane.GetContent()))
	case "w":
		m.wrap = !m.wrap
		m.pane.SoftWrap = m.wrap
		return m, m.refresh()
	case "f":
		if m.limit < viewLimitMore {
			m.limit = viewLimitMore
			m.rendered = map[renderKey]string{}
			return m, m.refresh()
		}
	}
	return m, nil
}

func kindStyle(k rune) lipgloss.Style {
	switch k {
	case '+':
		return styAdd
	case '-':
		return styDel
	case '~', '≈':
		return styMid
	case '>', '/':
		return styHunk
	}
	return styDim
}

func (m *diffTUI) View() tea.View {
	lw := m.listWidth()
	var list strings.Builder
	for i := m.top; i < min(len(m.lines), m.top+m.bodyHeight()); i++ {
		it := m.lines[i]
		row := padToWidth(strings.TrimRight(clean(m.rowText(it)), " "), lw)
		if i == m.cur {
			row = styCursor.Render(row)
		} else {
			row = kindStyle(it.kind).Render(row)
		}
		list.WriteString(row + "\n")
	}
	left := strings.Split(strings.TrimRight(list.String(), "\n"), "\n")
	for len(left) < m.bodyHeight() {
		left = append(left, strings.Repeat(" ", lw))
	}
	tabs, _ := m.tabStrip()
	right := append([]string{tabs}, strings.Split(m.pane.View(), "\n")...)
	var body strings.Builder
	for i := 0; i < m.bodyHeight(); i++ {
		r := ""
		if i < len(right) {
			r = right[i]
		}
		body.WriteString(left[i] + " " + padToWidth(r, m.paneWidth()) + "\n")
	}
	summary, runErr := m.run.Summary(), m.run.Err()
	title := m.title
	if summary != "" {
		title += "    " + summary
	}
	status := fmt.Sprintf("%d/%d  view: %s", min(m.cur+1, len(m.lines)), len(m.lines), modeNames[m.mode])
	if it, ok := m.selected(); ok && m.loading[it.key()] {
		status += "  reading…"
	}
	switch {
	case runErr != nil:
		status += "  " + styDel.Render("error: "+runErr.Error())
	case !m.run.Finished():
		if s := m.run.Status(); s != "" {
			status += "  " + styMid.Render("comparing: "+s)
		} else {
			status += "  " + styMid.Render("opening…")
		}
	case m.busy():
		status += "  " + styMid.Render(spinFrames[m.spinFrame%len(spinFrames)]+" listing its members…")
	}
	head := padToWidth(styTitle.Render(title), m.width)
	// Where we are, as in browse, or a word about the last key.
	where := m.breadcrumb()
	if w := ansi.StringWidth(where); w > m.width { // keep the end: that is where we are
		where = ansi.TruncateLeft(where, w-m.width+1, "…")
	}
	if m.note != "" {
		where = m.note
	}
	crumb := padToWidth(styMid.Render(where), m.width)
	foot := padToWidth(styDim.Render("j/k move  enter/l in  h/⌫ out  tab view  w wrap  d words  f more  x hex+  y copy  q quit")+status, m.width)
	v := tea.NewView(head + "\n" + strings.TrimRight(body.String(), "\n") + "\n" + crumb + "\n" + foot)
	v.AltScreen = true
	// Wheel and click. (It is also what stops the terminal's own text selection,
	// which y makes up for by copying the pane.)
	v.MouseMode = tea.MouseModeCellMotion
	return v
}

// runDiffInteractive compares two inputs and browses the result while it is
// still being found: a tree of differences for containers and directories, or
// the one pair for two files.
func runDiffInteractive(cfg analysis.Config) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("--interactive needs a terminal")
	}
	run := analysis.Start(cfg)
	title := fmt.Sprintf("%s  vs  %s", infile.Base(cfg.A), infile.Base(cfg.B))
	_, err := tea.NewProgram(newDiffTUI(title, run)).Run()
	return err
}
