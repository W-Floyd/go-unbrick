package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/diffview"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/infile"
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

// diffItem is one line of the diff as the viewer holds it: a copy, taken under
// the lock, of what the comparison had found by then.
type diffItem struct {
	src     *diffLine // identity only: never read from here, the comparison still writes it; nil for a directory or ".."
	name    string    // as listed in its level: "notes.txt", "sub/", "pkg.tar/" (it has something inside), ".."
	text    string    // the row
	kind    rune      // the line's: ~ > ≈ + - =; '/' for a directory; '↑' for ".."
	path    string
	a, b    *carve.Node
	pending bool   // its inside is still being compared
	kids    bool   // there is somewhere to go in: a directory, or a container with differences inside
	summary string // for a directory: what is under it
}

// itemKey is what an item is, so a line that has become something else (an
// added file found to be a rename, a container whose comparison finished) is
// read again.
type itemKey struct {
	src     *diffLine
	kind    rune
	path    string
	a, b    *carve.Node
	pending bool
}

func (it diffItem) key() itemKey { return itemKey{it.src, it.kind, it.path, it.a, it.b, it.pending} }

// navFrame is one level being looked at, as in browse: the entries of a
// directory or of a container, to go into and come back out of.
type navFrame struct {
	title string
	// source is this level's lines, as the comparison has them now. Called under
	// liveMu; the root is the comparison's own tree.
	source func(root *treeDiffTally) []*diffLine
	// strip is the path the level's lines carry in front of their own names (a
	// container's path, for what was found inside it); dir narrows the level to
	// one directory of it ("" or ending in /).
	strip, dir string
	// Kept while a deeper level is on top, to put the cursor back where it was.
	cur, top int
	sel      string
	// busy, for a level that is built as it is looked at, says it is still being.
	busy func() bool
}

// lineKids is what was found inside a line's container: as it goes, while the
// comparison of the inside is running, and when it has finished.
func lineKids(l *diffLine) []*diffLine {
	if l.subT != nil {
		return l.subT.lines
	}
	return l.sub
}

// sizeNote is the sizes a row shows: both for a change, the one there is otherwise.
func sizeNote(kind rune, a, b *carve.Node) string {
	switch {
	case kind == '+' && b != nil:
		return size(b)
	case (kind == '-' || kind == '>' || kind == '=') && a != nil:
		return size(a)
	case a != nil && b != nil:
		return size(a) + " -> " + size(b)
	}
	return ""
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
	if n := sizeNote(it.kind, it.a, it.b); n != "" {
		s += "  " + n
	}
	return s // a pending row's marker is drawn as a spinner (diffTUI.rowText)
}

// snapshotLevel lists the entries of one level as they stand now, copied under
// the lock the comparison writes under: directories first (made from the paths,
// as many levels deep as the paths go), then the lines, in the order found, with
// ".." first when there is a level above. Safe to call while the comparison runs.
func snapshotLevel(root *treeDiffTally, f navFrame, up bool) []diffItem {
	liveMu.Lock()
	defer liveMu.Unlock()
	var src []*diffLine
	if f.source != nil {
		src = f.source(root)
	}
	var leaves []diffItem
	type agg struct {
		counts  map[rune]int
		pending bool
	}
	dirs := map[string]*agg{}
	var dirNames []string
	for _, l := range src {
		if l.drop {
			continue
		}
		if l.path == "" { // a note, not a pair: an error from comparing, say
			if f.dir == "" {
				it := diffItem{name: strings.TrimSpace(l.text), text: strings.TrimRight(l.text, " ")}
				leaves = append(leaves, it)
			}
			continue
		}
		within := l.path
		renamed := l.kind == '>' || l.kind == '≈' // "old -> new": a name, not a path to split
		if !renamed && f.strip != "" && strings.HasPrefix(within, f.strip+"/") {
			within = within[len(f.strip)+1:]
		}
		if !strings.HasPrefix(within, f.dir) {
			continue
		}
		rel := within[len(f.dir):]
		if i := strings.IndexByte(rel, '/'); i > 0 && !renamed {
			name := rel[:i+1]
			a := dirs[name]
			if a == nil {
				a = &agg{counts: map[rune]int{}}
				dirs[name] = a
				dirNames = append(dirNames, name)
			}
			a.counts[l.kind]++
			a.pending = a.pending || l.subT != nil
			continue
		}
		// Something inside it to go into: lines that are still there (a comparison
		// that found nothing different leaves its dropped lines behind), or a
		// comparison still running.
		counts := map[rune]int{}
		for _, k := range lineKids(l) {
			if !k.drop && k.path != "" {
				counts[k.kind]++
			}
		}
		kids := l.subT != nil || len(counts) > 0
		name := rel
		if kids {
			name += "/"
		}
		it := diffItem{src: l, name: name, kind: l.kind, path: l.path, a: l.a, b: l.b, pending: l.subT != nil, kids: kids}
		if kids { // what was found inside it, for its pane
			it.summary = summarise(counts)
		}
		it.text = rowText(it)
		leaves = append(leaves, it)
	}
	sort.Strings(dirNames)
	var out []diffItem
	if up {
		out = append(out, diffItem{name: "..", kind: '↑', text: rowText(diffItem{kind: '↑'})})
	}
	for _, name := range dirNames {
		a := dirs[name]
		it := diffItem{name: name, kind: '/', path: f.dir + name, kids: true, pending: a.pending, summary: summarise(a.counts)}
		it.text = rowText(it)
		out = append(out, it)
	}
	return append(out, leaves...)
}

// kindWords are what a count of each kind of line is a count of.
var kindWords = []struct {
	kind rune
	word string
}{{'~', "changed"}, {'+', "added"}, {'-', "removed"}, {'>', "renamed"}, {'≈', "renamed and changed"}, {'=', "unchanged"}}

// summarise reads counts of lines by kind as "3 changed, 1 added".
func summarise(counts map[rune]int) string {
	var parts []string
	for _, w := range kindWords {
		if n := counts[w.kind]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, w.word))
		}
	}
	return strings.Join(parts, ", ")
}

// pairData is the bytes of the two sides of a line, as far as they were read.
type pairData struct {
	a, b           []byte
	sizeA, sizeB   int64 // whole sizes; -1 for a side with no file
	truncA, truncB bool  // more of the file than was read
	limit          int64
	err            error
}

func readHead(n *carve.Node, limit int64) (data []byte, size int64, trunc bool, err error) {
	if n == nil || n.IsDirNode() {
		return nil, -1, false, nil
	}
	r, err := n.Reader()
	if err != nil {
		return nil, n.Size, false, err
	}
	defer r.Close()
	data, err = io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(data)) > limit {
		data, trunc = data[:limit], true
	}
	return data, n.Size, trunc, err
}

func loadPair(a, b *carve.Node, limit int64) *pairData {
	d := &pairData{limit: limit}
	var errA, errB error
	d.a, d.sizeA, d.truncA, errA = readHead(a, limit)
	d.b, d.sizeB, d.truncB, errB = readHead(b, limit)
	if errA != nil {
		d.err = errA
	} else {
		d.err = errB
	}
	return d
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
func renderLines(ls []diffview.Line, width int, wrap bool) string {
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
func verdictLine(d *pairData) string {
	v := diffview.StringsOnly(d.a, d.b, stringsMin)
	part := ""
	if d.truncA || d.truncB {
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

// renderHex shows the bytes where a and b differ: each hunk's bytes on each side,
// with the rest of the rows they fall in as context. At most budget differing
// bytes are shown. Unasked (explicit false) it shows nothing unless every one
// fits, and says nothing if they do not: the hex view is for that.
func renderHex(a, b []byte, budget, width int, explicit bool) string {
	hunks, total, ok := diffview.HexDiffOutsideStrings(a, b, stringsMin) // the strings are the strings diff's
	switch {
	case !ok:
		if explicit {
			return styDim.Render("too large, and different in size, to find the bytes that differ") + "\n"
		}
		return ""
	case total == 0:
		if explicit {
			return "no bytes differ outside the printable strings (see the strings view)\n"
		}
		return ""
	case !explicit && total > budget:
		return ""
	}
	per := 16
	if width < 80 {
		per = 8
	}
	var sb strings.Builder
	title := fmt.Sprintf("Bytes: %s differ in %d place(s)", byteCount(int64(total)), len(hunks))
	sb.WriteString(styTitle.Render(title))
	if !explicit {
		sb.WriteString(styDim.Render("   (4 for hex view, x for more)"))
	}
	sb.WriteString("\n\n")
	shown := 0
	for i, h := range hunks {
		if shown >= budget {
			sb.WriteString(styDim.Render(fmt.Sprintf("… %d more place(s); x shows more", len(hunks)-i)) + "\n")
			break
		}
		shown += h.Len()
		fmt.Fprintf(&sb, "%s\n", styMid.Render(fmt.Sprintf("@@ A 0x%x +%d   B 0x%x +%d @@", h.OffA, len(h.A), h.OffB, len(h.B))))
		sb.WriteString(hexRows("- ", a, h.OffA, len(h.A), per, styDel))
		sb.WriteString(hexRows("+ ", b, h.OffB, len(h.B), per, styAdd))
		sb.WriteString("\n")
	}
	return sb.String()
}

// hexRows lays out the rows of data that hold [off, off+n), the bytes in that
// range in style and the rest dim.
func hexRows(mark string, data []byte, off, n, per int, sty lipgloss.Style) string {
	if n == 0 {
		return styDim.Render(fmt.Sprintf("%s(nothing at 0x%x)", mark, off)) + "\n"
	}
	var sb strings.Builder
	for row := off / per * per; row < off+n; row += per {
		var hexs, asc strings.Builder
		for i := row; i < row+per; i++ {
			switch {
			case i >= len(data):
				hexs.WriteString("   ")
				continue
			case i >= off && i < off+n:
				hexs.WriteString(sty.Render(fmt.Sprintf("%02x", data[i])) + " ")
			default:
				hexs.WriteString(styDim.Render(fmt.Sprintf("%02x", data[i])) + " ")
			}
			c := data[i]
			if c < 0x20 || c >= 0x7f {
				c = '.'
			}
			if i >= off && i < off+n {
				asc.WriteString(sty.Render(string(c)))
			} else {
				asc.WriteString(styDim.Render(string(c)))
			}
		}
		fmt.Fprintf(&sb, "%s%08x  %s |%s|\n", mark, row, hexs.String(), asc.String())
	}
	return sb.String()
}

func renderOverlap(o diffview.Overlap, d *pairData) string {
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
	row("A", o.SizeA, o.SharedA, o.UniqueA(), d.truncA)
	row("B", o.SizeB, o.SharedB, o.UniqueB(), d.truncB)
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
func sideNote(d *pairData) string {
	var parts []string
	if d.truncA {
		parts = append(parts, fmt.Sprintf("A: first %s of %s", humanBytes(int64(len(d.a))), humanBytes(d.sizeA)))
	}
	if d.truncB {
		parts = append(parts, fmt.Sprintf("B: first %s of %s", humanBytes(int64(len(d.b))), humanBytes(d.sizeB)))
	}
	if len(parts) == 0 {
		return ""
	}
	return styMid.Render("only part was read ("+strings.Join(parts, "; ")+"); f reads more") + "\n"
}

// labelFor is a line's kind in words, for the pane's title. A renamed container
// was found identical by comparing its members, not its bytes, which may differ
// (a tar's headers carry times), so "content identical" would be too much.
func labelFor(it diffItem) string {
	if it.kind == '>' && isContainerNode(it.a) {
		return "renamed, nothing inside it differs"
	}
	return kindLabel(it.kind)
}

// headerFormat says whether a pair of containers keep a record per member that
// can be compared: a pair of tars, or of zips.
func headerFormat(it diffItem) bool {
	ka, kb := filetype.Detect(it.a.Head()), filetype.Detect(it.b.Head())
	return ka == kb && (ka == filetype.Tar || ka == filetype.Zip)
}

// maxMetaLines bounds the differences listed for one pair of containers.
const maxMetaLines = 24

// metaSection reads the headers of a pair of tars (or the directories of two
// zips) and says what differs: which details, in how many members, and the first
// few. It reads a header per member, not the members.
func metaSection(it diffItem) string {
	read := func(n *carve.Node) ([]diffview.MetaEntry, error) {
		ra, err := n.ReaderAt()
		if err != nil {
			return nil, err
		}
		if filetype.Detect(n.Head()) == filetype.Zip {
			return diffview.ZipMeta(ra, n.Size)
		}
		return diffview.TarMeta(ra, n.Size)
	}
	var b strings.Builder
	b.WriteString("\n" + styTitle.Render("What each records about its members") + styDim.Render("  (times, owners, modes: not their contents)") + "\n\n")
	ea, errA := read(it.a)
	eb, errB := read(it.b)
	if err := errors.Join(errA, errB); err != nil {
		b.WriteString(styDel.Render("could not read the headers: "+err.Error()) + "\n")
		return b.String()
	}
	r := diffview.CompareMeta(ea, eb)
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
	return func() tea.Msg { return metaMsg{k, metaSection(it)} }
}

// containerPair says whether an entry is two containers, which are compared by
// their members: reading their raw bytes would show nothing of use.
// It never reads: a node whose head has not been read yet is not a container
// here, and needsProbe says so.
func containerPair(it diffItem) bool {
	if it.a == nil || it.b == nil {
		return false
	}
	ca, _ := it.a.IsContainerCached()
	cb, _ := it.b.IsContainerCached()
	return ca && cb
}

// needsProbe says whether telling if an entry is a container would read: the
// viewer's goroutine must not, with the comparison filling the link.
func needsProbe(it diffItem) bool {
	for _, n := range []*carve.Node{it.a, it.b} {
		if n != nil {
			if _, known := n.IsContainerCached(); !known {
				return true
			}
		}
	}
	return false
}

// probe reads the heads of an entry's sides, off the viewer's goroutine.
func probe(it diffItem) tea.Cmd {
	k := it.key()
	return func() tea.Msg {
		isContainerNode(it.a)
		isContainerNode(it.b)
		return probedMsg{k}
	}
}

// describeContainer is the pane for a pair of containers: what was found inside
// them, with no read of either. The overlap view (3) is how to ask for their raw
// bytes.
func (m *diffTUI) describeContainer(it diffItem) string {
	var b strings.Builder
	b.WriteString(styTitle.Render(labelFor(it)+"  "+it.path) + "\n")
	b.WriteString(styDim.Render(fmt.Sprintf("A %s    B %s", size(it.a), size(it.b))) + "\n\n")
	if it.summary != "" {
		b.WriteString("Inside it: " + it.summary + "\n\n" + styDim.Render("enter or l to go in") + "\n")
	} else {
		b.WriteString("Nothing inside it differs: its members are all the same.\n\n" +
			styDim.Render("enter or l to list its members") + "\n")
	}
	b.WriteString("\n" + styDim.Render(fmt.Sprintf("3 shows how much of the container's own bytes are shared; that reads the first %s of each.", humanBytes(m.limit))) + "\n")
	return b.String()
}

// kindLabel is what a line's kind means, for the pane's title.
func kindLabel(k rune) string {
	switch k {
	case '~':
		return "changed"
	case '>':
		return "renamed, content identical"
	case '≈':
		return "renamed and changed"
	case '+':
		return "only in B"
	case '-':
		return "only in A"
	case '=':
		return "unchanged"
	}
	return ""
}

func isContainerNode(n *carve.Node) bool { return n != nil && n.IsContainer() }

// renderDetail is the right pane for an item in view mode: what differs between
// the two sides, from the bytes read.
func renderDetail(it diffItem, d *pairData, mode, width int, wrap, hexMore, words bool) string {
	var b strings.Builder
	b.WriteString(styTitle.Render(labelFor(it)+"  "+it.path) + "\n")
	if it.a != nil && it.b != nil {
		fmt.Fprintf(&b, styDim.Render("A %s    B %s")+"\n", humanBytes(d.sizeA), humanBytes(d.sizeB))
	}
	b.WriteString("\n")
	if d.err != nil {
		b.WriteString(styDel.Render("reading: "+d.err.Error()) + "\n")
		return b.String()
	}
	b.WriteString(sideNote(d))
	switch {
	case it.kind == '=' || (it.kind == '>' && it.a != nil && it.b != nil && !isContainerNode(it.a) && mode == modeAuto):
		b.WriteString("identical content\n")
		return b.String()
	case it.a == nil || it.b == nil:
		return b.String() + renderOneSide(it, d, width, wrap)
	}
	text := diffview.IsText(d.a) && diffview.IsText(d.b)
	if !text && !isContainerNode(it.a) {
		b.WriteString(verdictLine(d) + "\n")
	}
	switch mode {
	case modeOverlap:
		b.WriteString(renderOverlap(diffview.Compare(d.a, d.b), d))
	case modeHex:
		budget := hexBytes
		if hexMore {
			budget = hexMoreBytes
		}
		b.WriteString(renderHex(d.a, d.b, budget, width, true))
	case modeStrings:
		lines, st, trunc := diffview.StringDiff(d.a, d.b, stringsMin, diffContext)
		b.WriteString(styTitle.Render(fmt.Sprintf("Strings (%d+ chars): %d removed, %d added", stringsMin, st.Removed, st.Added)) + "\n\n")
		if len(lines) == 0 {
			b.WriteString("the printable strings are identical\n")
		}
		b.WriteString(renderLines(lines, width, wrap))
		if trunc {
			b.WriteString(styDim.Render("… cut off") + "\n")
		}
	default:
		if isContainerNode(it.a) && isContainerNode(it.b) {
			b.WriteString("a container: what differs inside it is listed beneath it on the left.\n\n")
			b.WriteString(renderOverlap(diffview.Compare(d.a, d.b), d))
			break
		}
		if text {
			lines, st, trunc := diffview.TextDiff(d.a, d.b, diffContext)
			if words {
				lines = diffview.MarkWords(lines)
			}
			b.WriteString(styTitle.Render(fmt.Sprintf("%d removed, %d added, %d unchanged lines", st.Removed, st.Added, st.Same)) + "\n\n")
			if len(lines) == 0 {
				b.WriteString("the text is identical\n")
			}
			b.WriteString(renderLines(lines, width, wrap))
			if trunc {
				b.WriteString(styDim.Render("… cut off") + "\n")
			}
			break
		}
		b.WriteString(renderOverlap(diffview.Compare(d.a, d.b), d))
		if hx := renderHex(d.a, d.b, hexAuto, width, false); hx != "" {
			b.WriteString("\n" + hx)
		}
		lines, st, trunc := diffview.StringDiff(d.a, d.b, stringsMin, 1)
		b.WriteString("\n" + styTitle.Render(fmt.Sprintf("Strings: %d removed, %d added", st.Removed, st.Added)) + styDim.Render("   (tab for the full diff)") + "\n\n")
		const peek = 60
		if len(lines) > peek {
			lines, trunc = lines[:peek], true
		}
		b.WriteString(renderLines(lines, width, wrap))
		if trunc {
			b.WriteString(styDim.Render("… more in the strings view") + "\n")
		}
	}
	return b.String()
}

// renderOneSide shows a file present on one side only: its start if it is
// text, else the strings in it.
func renderOneSide(it diffItem, d *pairData, width int, wrap bool) string {
	data := d.a
	if it.a == nil {
		data = d.b
	}
	var b strings.Builder
	if diffview.IsText(data) {
		for i, ln := range strings.SplitAfter(string(data), "\n") {
			if i >= 200 {
				b.WriteString(styDim.Render("… more") + "\n")
				break
			}
			if ln == "" {
				continue
			}
			b.WriteString(fit(fmt.Sprintf("%6d  ", i+1), clean(strings.TrimRight(ln, "\r\n")), width, wrap, lipgloss.NewStyle()) + "\n")
		}
		return b.String()
	}
	b.WriteString(styDim.Render("binary; the printable strings in it:") + "\n\n")
	for i, s := range diffview.Strings(data, stringsMin) {
		if i >= 200 {
			b.WriteString(styDim.Render("… more") + "\n")
			break
		}
		b.WriteString(fit("", clean(s), width, wrap, lipgloss.NewStyle()) + "\n")
	}
	return b.String()
}

// ---- the comparison, running ----

// liveRun is a comparison running in the background that the viewer watches.
type liveRun struct {
	mu      sync.Mutex
	root    *treeDiffTally
	summary string
	err     error
	done    chan struct{} // closed when the comparison has finished, successfully or not
}

func newLiveRun() *liveRun { return &liveRun{done: make(chan struct{})} }

func (r *liveRun) setRoot(t *treeDiffTally) {
	r.mu.Lock()
	r.root = t
	r.mu.Unlock()
}

func (r *liveRun) get() (root *treeDiffTally, summary string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.root, r.summary, r.err
}

func (r *liveRun) finished() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// ---- the model ----

type diffTUI struct {
	title         string
	run           *liveRun
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

	data     map[itemKey]*pairData
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
		d *pairData
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

func newDiffTUI(title string, run *liveRun) *diffTUI {
	m := &diffTUI{
		title: title, run: run, pane: viewport.New(), limit: viewLimit, wrap: true, words: true,
		data: map[itemKey]*pairData{}, rendered: map[renderKey]string{}, loading: map[itemKey]bool{}, meta: map[itemKey]string{},
		frames: []navFrame{{title: title, source: func(root *treeDiffTally) []*diffLine {
			if root == nil {
				return nil
			}
			return root.lines
		}}},
	}
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
		t = append(t, f.title)
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
func hasDetail(it diffItem) bool { return !it.pending && (it.a != nil || it.b != nil) }

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
	done := m.run.finished()
	root, _, _ := m.run.get()
	items := snapshotLevel(root, m.frame(), len(m.frames) > 1)
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
	case needsProbe(it):
		// Whether it is a container takes a read of its head; one at a time, with
		// the other reads (when it lands the cursor's entry goes next).
		m.pane.SetContent(styDim.Render("looking at it…"))
		if len(m.loading) > 0 {
			return nil
		}
		m.loading[it.key()] = true
		return probe(it)
	case m.mode != modeOverlap && containerPair(it):
		// Two containers are compared by their members: say what was found, and
		// read none of their contents (a GiB tar's first 32 MiB, over ssh, shows
		// nothing of use). What they record about their members, though, is where
		// they can differ when every member is the same: a header's time.
		base := m.describeContainer(it)
		if sec, ok := m.meta[it.key()]; ok {
			m.pane.SetContent(base + sec)
			return nil
		}
		if !headerFormat(it) {
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
	if !ok || d.limit != m.limit {
		// One read at a time: moving quickly down the list would otherwise start a
		// read for every row passed, all at once. When this one lands, the next
		// goes for wherever the cursor has got to by then (see loadedMsg).
		if len(m.loading) > 0 {
			return nil
		}
		m.loading[k] = true
		limit := m.limit
		return func() tea.Msg { return loadedMsg{k, loadPair(it.a, it.b, limit)} }
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
			up = m.frames[len(m.frames)-2].title
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
	case !it.kids && !containerPair(it):
		m.note = strings.TrimSuffix(it.name, "/") + ": nothing inside it differs"
		return m, nil
	}
	cur := m.frame()
	var next navFrame
	switch {
	case !it.kids: // two containers with nothing differing inside: list their members
		next = membersFrame(it)
	case it.src == nil: // a directory made from the paths: the same lines, narrowed
		next = navFrame{title: strings.TrimSuffix(it.name, "/"), source: cur.source, strip: cur.strip, dir: cur.dir + it.name}
	default:
		l := it.src
		next = navFrame{title: path.Base(strings.TrimSuffix(it.name, "/")), strip: l.path,
			source: func(*treeDiffTally) []*diffLine { return lineKids(l) }}
	}
	// Remember where we were, so coming back puts the cursor on this entry.
	m.frames[len(m.frames)-1].cur, m.frames[len(m.frames)-1].top, m.frames[len(m.frames)-1].sel = m.cur, m.top, it.name
	m.frames = append(m.frames, next)
	m.lines, m.cur, m.top = nil, 0, 0
	m.note = ""
	return m, tea.Batch(m.syncLines(), m.ensureTick())
}

// membersFrame is the level for two containers whose comparison found nothing
// different inside: their members, all unchanged, listed by comparing them now.
// It runs in the background and the level fills in as it goes. (Their digests
// were taken, or stated, when they were first compared, so it is mostly lookups.)
func membersFrame(it diffItem) navFrame {
	a, b := it.a, it.b
	t := &treeDiffTally{depth: 1, verbose: true, claimsA: subClaims(a, ""), claimsB: subClaims(b, "")}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := diffNodes(a, b, "", "", 1, true, t); err != nil {
			t.out("  (%v)", err)
			return
		}
		t.pairRenames()
	}()
	return navFrame{
		title:  path.Base(strings.TrimSuffix(it.name, "/")),
		source: func(*treeDiffTally) []*diffLine { return t.lines },
		busy: func() bool {
			select {
			case <-done:
				return false
			default:
				return true
			}
		},
	}
}

// busy says whether the level in view is still being listed.
func (m *diffTUI) busy() bool {
	f := m.frame()
	return f.busy != nil && f.busy()
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
func (m *diffTUI) remember(k itemKey, d *pairData) {
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
	return ok && d.limit == m.limit
}

func (m *diffTUI) analyse(it diffItem, d *pairData) tea.Cmd {
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
		if it, ok := m.selected(); ok && containerPair(it) && m.mode != modeOverlap {
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
	_, summary, runErr := m.run.get()
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
	case !m.run.finished():
		if s := dprog.status(); s != "" {
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
func runDiffInteractive(pathA, pathB string, depth int, verbose bool, member string) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("--interactive needs a terminal")
	}
	diffQuiet = true // the viewer draws the progress itself
	run := newLiveRun()
	go func() {
		defer close(run.done)
		if member != "" { // one file out of each, not the trees
			run.setRoot(pairRoot(pathA, pathB, member, run))
			return
		}
		t, ok, err := diffTree(pathA, pathB, depth, verbose, run.setRoot)
		switch {
		case err != nil:
			run.mu.Lock()
			run.err = err
			run.mu.Unlock()
		case ok:
			run.mu.Lock()
			run.summary = fmt.Sprintf("%d changed, %d added, %d removed, %d renamed, %d unchanged",
				t.changed, t.added, t.removed, t.renamed+t.similar, t.same)
			run.mu.Unlock()
		default:
			run.setRoot(pairRoot(pathA, pathB, "", run))
		}
	}()
	title := fmt.Sprintf("%s  vs  %s", infile.Base(pathA), infile.Base(pathB))
	_, err := tea.NewProgram(newDiffTUI(title, run)).Run()
	return err
}

// pairRoot is the tree for one pair: two inputs that are not containers, or the
// member at member inside each.
func pairRoot(pathA, pathB, member string, run *liveRun) *treeDiffTally {
	a, b, name, err := pairNodes(pathA, pathB, member)
	if err != nil {
		run.mu.Lock()
		run.err = err
		run.mu.Unlock()
		return nil
	}
	root := &treeDiffTally{}
	root.lines = []*diffLine{(&diffLine{text: "  ~ " + name}).tag('~', name, a, b)}
	return root
}
