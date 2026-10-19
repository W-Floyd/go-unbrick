package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
)

// browse is the one TUI in go-unbrick: everything else (ls, tree, extract,
// recon) is a flat command meant for scripts and pipes, and stays that way.
// This is the file-manager-style front end over the same primitives: a
// directory on disk, and anything carve can open inside a file.
func newBrowseCmd() *cobra.Command {
	var skip []string
	c := &cobra.Command{
		Use:   "browse <file | dir | url>",
		Short: "interactively navigate a directory or anything carve can open inside a file",
		Long: `browse is go-unbrick's one TUI: a file-manager-style view over a local
directory, or over anything carve can open inside a file (archive members,
payload partitions, filesystem files, boot image sections, ...).

Every reconnable entry in the current list recons itself in the background,
one at a time, lowest-index first; just highlighting an entry (arrow keys,
j/k, click, or wheel) jumps its recon to the front of that queue, so whatever
you're looking at finishes soonest and the preview pane fills in with the
full report on its own — there's no separate "recon this" key to press. Two
progress bars in the footer track it: how much of the current page is done,
and how much of everything seen so far across the whole session.

A text file (syntax-highlighted via chroma) previews as its content directly,
not a generic size/type blurb — no need to extract it first to read it. A
format browse can reformat (currently: JSON) shows pretty-printed by default.

  enter / l / →     descend into the selected directory or container
  backspace/h/←     go back up one level (lands back on what you came from)
  x                 extract the selected entry to the current directory
  p                 toggle a reformatted text file between pretty and raw
  y                 copy the whole preview pane's text to the clipboard
  /                 filter the current list
  click / wheel     select, activate, or scroll with the mouse
  q, ctrl+c         quit

Mouse reporting (for click/wheel above) is also what stops a terminal's own
click-drag text selection from reaching it - most terminals still allow that
under a modifier key (Option on macOS Terminal/iTerm2, Shift on many Linux
terminals) if you want to select and copy only part of what's shown; 'y'
above copies the whole pane without needing either.

There is no flat/non-interactive mode for this command; it requires a real
terminal. Use ls/tree/recon/extract directly for scripting or piping.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isInteractive() {
				return fmt.Errorf("browse needs an interactive terminal (stdin and stdout); use ls/tree/recon/extract instead")
			}
			m, err := newBrowseModel(args[0], skip)
			if err != nil {
				return err
			}
			_, err = tea.NewProgram(m).Run()
			return err
		},
	}
	c.Flags().StringSliceVar(&skip, "skip", nil, "directory listings: leave files out (they're never listed, so never preemptively reconned either): \"navi\" for the navigation map parts, or a glob on the file name; repeatable or comma-separated - same values as 'recon --skip'")
	return addSecrets(addFullDownload(c))
}

// isInteractive reports whether both stdin and stdout are a real terminal —
// bubbletea needs to read key/mouse events from one and draw to the other.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fi, err = os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// browseEntry is one row in a browse frame's list: a plain OS directory entry
// (osPath set, node nil) or a carve.Node child of an already-opened container
// (node set, osPath ""). dir is true for an OS subdirectory, the one case
// that is a container without being a carve.Node.
type browseEntry struct {
	name        string
	size        int64 // -1 unknown
	label       string
	dir         bool
	isContainer bool // carve-recognized container (meaningless when osPath != "": that's resolved lazily on Enter)
	isText      bool // previewed as syntax-highlighted content instead of reconned - see reconKey
	osPath      string
	node        *carve.Node
}

func (e browseEntry) FilterValue() string { return e.name }

// reconKey identifies e for the recon queue/cache: a real path for an OS
// file, or the carve.Node's own identity for a package member (two different
// members can share a name, e.g. "boot.img" in two variants, so the name
// alone isn't unique - the node pointer is, for as long as its frame is on
// the stack). ok is false for anything recon can't run on at all.
func reconKey(e browseEntry) (key string, ok bool) {
	switch {
	case e.dir:
		return "", false
	case e.osPath != "":
		return "os:" + e.osPath, true
	case e.node != nil:
		return fmt.Sprintf("node:%p", e.node), true
	default:
		return "", false
	}
}

// selectedIdentity names whatever list.Model.SelectedItem() currently is, for
// detecting a selection change around a list.Update call. Index() alone
// isn't enough: while filtering, the cursor can sit at the same numeric
// index (often 0) across every keystroke while the item actually there
// changes with each narrowing of the match set - comparing indices missed
// that entirely, leaving the preview pane showing whatever was selected
// before filtering started, through the entire session of typing a filter
// and confirming it.
func selectedIdentity(l list.Model) string {
	e, ok := l.SelectedItem().(browseEntry)
	if !ok {
		return ""
	}
	return e.name + "\x00" + e.osPath + "\x00" + fmt.Sprintf("%p", e.node)
}

const browseNameWidth = 42

// fitWidth pads or truncates s to exactly w cells (ASCII-width; these are
// filenames, not arbitrary text), so a column after it lines up the same way
// on every row regardless of how long any one name is.
func fitWidth(s string, w int) string {
	switch {
	case w <= 0:
		return ""
	case len(s) == w:
		return s
	case len(s) < w:
		return s + strings.Repeat(" ", w-len(s))
	case w == 1:
		return s[:1]
	default:
		return s[:w-1] + "…"
	}
}

// line is the single-line "name  size  type" text a flat `ls` would print;
// browseDelegate renders exactly this, so the list stays one row per entry
// instead of list.DefaultDelegate's two-line, blank-line-separated layout.
// The name column is a fixed width regardless of how the full line is later
// clipped to the pane's width, so a long name truncates in place instead of
// pushing the size/type out of alignment with every shorter name above it.
func (e browseEntry) line() string {
	desc := "directory"
	switch {
	case e.dir:
	case e.size < 0:
		desc = e.label
	default:
		desc = humanBytes(e.size) + "  " + e.label
	}
	return fitWidth(e.name, browseNameWidth) + "  " + desc
}

// browseDelegate renders one entry per terminal row: no blank-line spacing,
// no second description line — list.DefaultDelegate's two-line cards are
// built for a handful of items, not the dozens-to-thousands a firmware
// package or directory holds here.
type browseDelegate struct{}

func (browseDelegate) Height() int                         { return 1 }
func (browseDelegate) Spacing() int                        { return 0 }
func (browseDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (browseDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	e, ok := item.(browseEntry)
	if !ok {
		return
	}
	line := e.line()
	style := lipgloss.NewStyle()
	if index == m.Index() {
		style = style.Reverse(true).Bold(true)
	}
	fmt.Fprint(w, style.MaxWidth(m.Width()).Render(line))
}

// browseFrame is one level of navigation: the title shown above the list, and
// how to go back - node is nil at the initial OS-directory frame and at any
// OS-directory frame reached by descending into a subdirectory; it is set once
// a frame's contents came from carve.Node.Children.
type browseFrame struct {
	title    string
	osDir    string
	node     *carve.Node
	selected int // index to restore on ascend - set by descend() just before leaving this frame
}

type browseModel struct {
	frames  []browseFrame
	list    list.Model
	preview viewport.Model
	spin    spinner.Model
	rq      *reconQueue
	skip    []string // --skip: directory frames leave these files out entirely (same values as 'recon --skip')
	showRaw bool     // 'p' toggle: a pretty-printable text file (JSON, ...) shows reformatted by default
	status  string
	width   int
	height  int
}

func newBrowseModel(input string, skip []string) (*browseModel, error) {
	m := &browseModel{
		list:    list.New(nil, browseDelegate{}, 0, 0),
		preview: viewport.New(),
		spin:    spinner.New(),
		rq:      newReconQueue(),
		skip:    skip,
	}
	// Without this a long line just vanishes past the pane's width - no
	// scrollbar, no indicator it's cut off, and no keybinding here for
	// horizontal scroll either.
	m.preview.SoftWrap = true
	// This isn't list.DefaultDelegate's two-line card view, and the
	// breadcrumb/status line below the panes already says where we are and
	// what the last action did — the list's own title/status/pagination/help
	// chrome would just repeat that in a second place.
	m.list.SetShowTitle(false)
	m.list.SetShowStatusBar(false)
	m.list.SetShowPagination(false)
	m.list.SetShowHelp(false)
	// showFilter (unlike the four above) is true by default regardless of
	// Title, and list.Model.View renders its title/filter row whenever
	// showTitle || (showFilter && FilteringEnabled) - so with filtering
	// left on (it is: '/' is a real feature here), that row still rendered,
	// pushing every item down a row the preview pane - a plain viewport,
	// with no such reserved row of its own - never budgeted for. That's
	// what actually desynced which preview belonged to which highlighted
	// row. '/' still narrows the list with this off; you just don't see the
	// query text you're typing while you type it, same as a plain filter-
	// as-you-go without the input echoed.
	m.list.SetShowFilter(false)

	fi, err := os.Stat(input)
	if err == nil && fi.IsDir() {
		if err := m.pushDirFrame(input); err != nil {
			return nil, err
		}
		return m, nil
	}
	root, err := carveRoot(input)
	if err != nil {
		return nil, err
	}
	if err := m.pushNodeFrame(root); err != nil {
		return nil, err
	}
	return m, nil
}

// waitReady turns the queue's completion channel into a tea.Cmd: Update
// re-issues this after every reconReadyMsg, so it's always listening for the
// next one without a worker goroutine ever needing a *tea.Program reference.
func waitReady(ch <-chan reconReadyMsg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

func (m *browseModel) Init() tea.Cmd {
	return tea.Batch(waitReady(m.rq.ready), m.spin.Tick, func() tea.Msg {
		m.rq.start()
		return nil
	})
}

func (m *browseModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case spinner.TickMsg:
		// Always kept alive (bubbles' spinner self-chains its own next tick):
		// it also drives the periodic redraw that lets the progress bars and
		// the "reconning ..." status line advance while nothing else is
		// happening - a bump from highlighting doesn't itself trigger a
		// render once the key event is handled.
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case reconReadyMsg:
		if sel, ok := m.selected(); ok {
			if k, ok := reconKey(sel); ok && k == msg.key {
				m.showPreview() // picks up the result that just landed in the cache
			}
		}
		return m, waitReady(m.rq.ready)
	case tea.KeyPressMsg:
		// While actively typing a filter query, every key belongs to it -
		// including ones that are otherwise our own bindings below (an 'x',
		// 'p', 'q', 'h' or 'l' in the query would otherwise never reach the
		// filter input, and 'enter' needs to confirm the filter, not
		// descend into whatever stale/wrong item was selected before the
		// filter changed what's showing).
		if m.list.FilterState() != list.Filtering {
			switch msg.Keystroke() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "enter", "l", "right":
				m.descend()
				return m, nil
			case "backspace", "h", "left":
				m.ascend()
				return m, nil
			case "x":
				m.extract()
				return m, nil
			case "p":
				m.showRaw = !m.showRaw
				m.showPreview()
				return m, nil
			case "y":
				// Our own mouse reporting (tea.MouseModeCellMotion, for
				// click/wheel) is exactly what stops a terminal's native
				// click-drag selection from reaching it at all - most
				// terminals still allow it under a modifier key (Option on
				// macOS Terminal/iTerm2, Shift on many Linux ones), but that's
				// a per-terminal trick to remember, not something here. OSC
				// 52 (tea.SetClipboard) copies the whole pane's plain text
				// (stripANSI: chroma's highlighting is real ANSI color codes,
				// not something to paste elsewhere) without needing either.
				m.setStatus("copied to clipboard")
				return m, tea.SetClipboard(stripANSI(m.preview.GetContent()))
			}
		}
	case tea.MouseClickMsg:
		m.handleClick(msg.Mouse())
		return m, nil
	case tea.MouseWheelMsg:
		m.handleWheel(msg.Mouse())
		return m, nil
	}
	var cmd tea.Cmd
	before := selectedIdentity(m.list)
	m.list, cmd = m.list.Update(msg)
	if selectedIdentity(m.list) != before {
		m.onSelectionChanged()
	}
	return m, cmd
}

func (m *browseModel) View() tea.View {
	listW := m.width * 2 / 5
	left := lipgloss.NewStyle().Width(listW).Render(m.list.View())
	right := lipgloss.NewStyle().Width(m.width - listW - 1).Render(m.preview.View())
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)

	status := m.status
	if name, ok := m.rq.inflightDisplay(); ok {
		status = m.spin.View() + " reconning " + name + "..."
	} else if status == "" {
		status = strings.Join(m.breadcrumb(), " / ")
	}

	v := tea.NewView(body + "\n" + m.progressLine() + "\n" + cLabel(status))
	v.MouseMode = tea.MouseModeCellMotion
	// Without this, bubbletea renders inline below the shell prompt instead
	// of taking over the screen - the prompt and command line stay visible,
	// eating into the window height WindowSizeMsg reports as fully ours, so
	// our content gets cut off at the bottom by exactly that much. This is
	// the real explanation for the "hidden rows" that no amount of height
	// math on our side could fix: the rows genuinely weren't ours to draw
	// into. (v1's tea.WithAltScreen() program option became a per-View
	// field in v2 - there's no equivalent program-level option to miss.)
	v.AltScreen = true
	return v
}

const progressBarWidth = 16

// progressLine shows two bars: how much of the entries listed right now are
// reconned, and how much of every entry browse has ever seen across the
// whole session (every frame visited, not just the current one) - the first
// answers "is this directory done yet", the second "how much is left overall".
func (m *browseModel) progressLine() string {
	pageDone, pageTotal := m.pageProgress()
	allDone, allTotal := m.rq.stats()
	bar := progress.New(progress.WithWidth(progressBarWidth), progress.WithoutPercentage())
	var pagePct, allPct float64
	if pageTotal > 0 {
		pagePct = float64(pageDone) / float64(pageTotal)
	}
	if allTotal > 0 {
		allPct = float64(allDone) / float64(allTotal)
	}
	return fmt.Sprintf("%s %d/%d this page   %s %d/%d overall",
		bar.ViewAs(pagePct), pageDone, pageTotal,
		bar.ViewAs(allPct), allDone, allTotal)
}

// pageProgress counts how many of the current frame's reconnable entries are
// already cached. Recomputed fresh on every render rather than tracked
// incrementally - it's a scan over a slice already in memory, cheap even for
// a few thousand entries, and avoids another piece of state to keep in sync.
func (m *browseModel) pageProgress() (done, total int) {
	for _, it := range m.list.Items() {
		e, ok := it.(browseEntry)
		if !ok {
			continue
		}
		key, ok := reconKey(e)
		if !ok {
			continue
		}
		total++
		if _, ok := m.rq.get(key); ok {
			done++
		}
	}
	return done, total
}

func (m *browseModel) breadcrumb() []string {
	out := make([]string, len(m.frames))
	for i, f := range m.frames {
		out[i] = f.title
	}
	return out
}

// listWidth is how wide the left pane is — also the X boundary mouse
// handling uses to tell the list from the preview.
func (m *browseModel) listWidth() int { return m.width * 2 / 5 }

func (m *browseModel) layout() {
	listW := m.listWidth()
	h := m.height - 2 // progress line + status line
	if h < 2 {
		h = 2
	}
	m.list.SetSize(listW, h)
	m.preview.SetWidth(m.width - listW - 1)
	// Same h as the list: with SetShowFilter(false) above, list.Model no
	// longer reserves one of its own rows for a filter prompt it would
	// otherwise draw even while not filtering - every one of its h rows is
	// a real item row now, so the plain viewport here needs the same h to
	// stay row-for-row aligned with it.
	m.preview.SetHeight(h)
	m.showPreview()
}

// selected returns the currently highlighted entry, if any.
func (m *browseModel) selected() (browseEntry, bool) {
	e, ok := m.list.SelectedItem().(browseEntry)
	return e, ok
}

// onSelectionChanged refreshes the preview for whatever is now highlighted
// and, if it's reconnable, jumps its background job to the front of the
// queue — the point of the preemptive queue is that by the time you've
// looked at an entry for more than a moment, its recon is either done or
// next in line, not buried behind everything else in the current directory.
func (m *browseModel) onSelectionChanged() {
	m.showRaw = false // land on pretty-by-default for whatever's now highlighted, not whatever 'p' last left set
	m.preview.GotoTop()
	m.showPreview()
	if e, ok := m.selected(); ok {
		if key, ok := reconKey(e); ok {
			m.rq.bump(key)
		}
	}
}

// handleClick selects the entry under the pointer; clicking the entry that
// was already selected activates it (same as pressing enter), matching the
// usual file-manager convention of a second interaction to open.
func (m *browseModel) handleClick(ms tea.Mouse) {
	if ms.X >= m.listWidth() {
		return
	}
	idx := m.list.Paginator.Page*m.list.Paginator.PerPage + ms.Y
	items := m.list.Items()
	if idx < 0 || idx >= len(items) {
		return
	}
	already := idx == m.list.Index()
	m.list.Select(idx)
	m.onSelectionChanged()
	if already {
		m.descend()
	}
}

func (m *browseModel) handleWheel(ms tea.Mouse) {
	onList := ms.X < m.listWidth()
	switch ms.Button {
	case tea.MouseWheelDown:
		if onList {
			m.list.CursorDown()
			m.onSelectionChanged()
		} else {
			m.preview.ScrollDown(3)
		}
	case tea.MouseWheelUp:
		if onList {
			m.list.CursorUp()
			m.onSelectionChanged()
		} else {
			m.preview.ScrollUp(3)
		}
	}
}

// showPreview sets the preview pane for the highlighted entry: the full
// cached recon report if the background queue has already reached it,
// otherwise cheap, always-available info (size, type label) plus a note that
// it's running - highlighting it already put it at the front of the queue.
func (m *browseModel) showPreview() {
	m.status = ""
	e, ok := m.selected()
	if !ok {
		m.preview.SetContent("")
		return
	}
	// A text file (isText is a direct content check - filetype.Text on its
	// own head bytes, not e.label, which is recon's often-less-specific
	// guess: a file this heuristic already calls readable can still earn an
	// "unknown" label from typeLabel's other, stricter checks) always
	// previews as itself immediately, rather than waiting on or being
	// evicted by a cached recon result. It's still reconned in the
	// background like everything else (enqueueAll doesn't check isText),
	// and textPreview appends that once it lands rather than replacing the
	// content with it - "text can match and be read" means both, not either.
	if !e.dir && e.isText {
		if out, ok := m.textPreview(e); ok {
			m.preview.SetContent(out)
			return
		}
	}
	if key, ok := reconKey(e); ok {
		if out, ok := m.rq.get(key); ok {
			m.preview.SetContent(out)
			return
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", cHdr(e.name))
	switch {
	case e.dir:
		fmt.Fprintln(&b, "directory")
	case e.osPath != "":
		fmt.Fprintf(&b, "%s\n%s\n", humanBytes(e.size), e.label)
		fmt.Fprintln(&b, "\nreconning in the background")
	default:
		fmt.Fprintf(&b, "%s\n%s\n", humanBytes(e.size), e.label)
		if e.isContainer {
			fmt.Fprintln(&b, "\npress enter to open")
		}
		fmt.Fprintln(&b, "reconning in the background (spooled to a temp file); x extracts")
	}
	m.preview.SetContent(b.String())
}

// textPreview reads e's content (bounded by textPreviewCap) and renders it
// syntax-highlighted, pretty-printed by default when a known format allows
// it (p toggles that - see m.showRaw). ok is false only on a read error
// (e.g. a carve.Node whose container can't be reopened), not on "not text" -
// callers already know e.isText before calling this.
func (m *browseModel) textPreview(e browseEntry) (string, bool) {
	content, truncated, err := readForPreview(e)
	if err != nil {
		return "", false
	}
	display := content
	prettyBytes, prettyOK := prettyPrint(e.name, content)
	usingPretty := prettyOK && !m.showRaw
	if usingPretty {
		display = prettyBytes
	}
	body := highlightText(e.name, display)
	switch {
	case usingPretty:
		body += "\n" + cLabel("p") + ": raw file contents"
	case prettyOK:
		body += "\n" + cLabel("p") + ": pretty-printed"
	}
	if truncated {
		body += "\n" + cWarn("[!] preview truncated; x to extract the whole file")
	}
	// Prepended, not swapped in: the content is already useful the instant
	// it's read, and recon - still running in the background for this entry
	// like any other - adds to that once it lands rather than replacing it.
	// Recon goes above: it's the shorter, structured summary, so it's the
	// first thing in view; the raw/pretty content, often much longer, scrolls
	// below it rather than pushing it out of the visible pane.
	if key, ok := reconKey(e); ok {
		if recon, ok := m.rq.get(key); ok {
			return cHdr("recon:") + "\n" + recon + "\n\n" + body, true
		}
	}
	return body, true
}

func (m *browseModel) setStatus(s string) { m.status = s }

// enqueueAll preemptively queues every reconnable entry of a freshly built
// frame, in list order, then bumps whichever one ends up selected (the first
// one, right after ResetSelected) to the front — so it, at least, starts
// immediately rather than waiting behind everything else just listed.
func (m *browseModel) enqueueAll(items []list.Item) {
	for _, it := range items {
		e, ok := it.(browseEntry)
		if !ok {
			continue
		}
		key, ok := reconKey(e)
		if !ok {
			continue
		}
		m.rq.enqueue(reconJob{key: key, name: e.name, osPath: e.osPath, node: e.node})
	}
	if e, ok := m.selected(); ok {
		if key, ok := reconKey(e); ok {
			m.rq.bump(key)
		}
	}
}

// pushDirFrame lists an OS directory's entries as the new top frame.
func (m *browseModel) pushDirFrame(dir string) error {
	des, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })
	var filePaths []string
	for _, d := range des {
		if !d.IsDir() {
			filePaths = append(filePaths, filepath.Join(dir, d.Name()))
		}
	}
	// applySkips prints a "Skipped navi: N file(s), ..." line straight to
	// os.Stdout, meant for recon's flat report; here it would just corrupt
	// bubbletea's screen, so it's captured and dropped rather than shown -
	// the files simply aren't in the listing, which says the same thing.
	var kept []string
	captureStdout(func() error { kept = applySkips(filePaths, m.skip); return nil }) //nolint:errcheck
	keep := map[string]bool{}
	for _, p := range kept {
		keep[p] = true
	}
	items := make([]list.Item, 0, len(des))
	for _, d := range des {
		if d.Name() != "." && strings.HasPrefix(d.Name(), ".") {
			continue
		}
		full := filepath.Join(dir, d.Name())
		if d.IsDir() {
			items = append(items, browseEntry{name: d.Name(), size: -1, dir: true, osPath: full})
			continue
		}
		if !keep[full] {
			continue
		}
		size := int64(-1)
		if fi, err := d.Info(); err == nil {
			size = fi.Size()
		}
		label, isText := fileHeadLabel(full)
		items = append(items, browseEntry{name: d.Name(), size: size, label: label, isText: isText, osPath: full})
	}
	m.frames = append(m.frames, browseFrame{title: filepath.Base(dir), osDir: dir})
	m.list.SetItems(items)
	m.list.ResetSelected()
	m.enqueueAll(items)
	m.showPreview()
	return nil
}

// pushNodeFrame lists a carve.Node's children as the new top frame.
func (m *browseModel) pushNodeFrame(n *carve.Node) error {
	_, kids, err := n.Children()
	if err != nil {
		return err
	}
	items := make([]list.Item, 0, len(kids))
	for _, k := range kids {
		label := typeLabel(k.Name, k.Head())
		isContainer := false
		if sub, ok := carve.Format(k); ok {
			label = sub.Kind
			isContainer = true
		}
		isText := looksLikeText(k.Name, k.Head())
		items = append(items, browseEntry{name: k.Name, size: k.Size, label: label, isContainer: isContainer, isText: isText, node: k})
	}
	title := n.Name
	if title == "" {
		title = "/"
	}
	m.frames = append(m.frames, browseFrame{title: title, node: n})
	m.list.SetItems(items)
	m.list.ResetSelected()
	m.enqueueAll(items)
	m.showPreview()
	return nil
}

// current is the frame browse is showing the contents of.
func (m *browseModel) current() browseFrame { return m.frames[len(m.frames)-1] }

func (m *browseModel) descend() {
	e, ok := m.selected()
	if !ok {
		return
	}
	// Remember where we were in this frame so ascend can put the cursor back
	// on the entry we came from, instead of always landing on the first item.
	if len(m.frames) > 0 {
		m.frames[len(m.frames)-1].selected = m.list.Index()
	}
	switch {
	case e.dir:
		if err := m.pushDirFrame(e.osPath); err != nil {
			m.setStatus(err.Error())
		}
	case e.osPath != "":
		root, err := carveRoot(e.osPath)
		if err != nil {
			m.setStatus(err.Error())
			return
		}
		if err := m.pushNodeFrame(root); err != nil {
			m.setStatus(e.name + ": " + err.Error())
		}
	case e.node != nil && e.isContainer:
		if err := m.pushNodeFrame(e.node); err != nil {
			m.setStatus(e.name + ": " + err.Error())
		}
	default:
		m.setStatus(e.name + ": not a container (" + e.label + ")")
	}
}

func (m *browseModel) ascend() {
	if len(m.frames) <= 1 {
		return
	}
	m.frames = m.frames[:len(m.frames)-1]
	f := m.current() // a copy: rebuild*Frame below pops and re-pushes the slice entry, but f.selected survives in this local copy
	var err error
	if f.node != nil {
		err = m.rebuildNodeFrame(f.node)
	} else {
		err = m.rebuildDirFrame(f.osDir)
	}
	if err != nil {
		m.setStatus(err.Error())
		return
	}
	if f.selected >= 0 && f.selected < len(m.list.Items()) {
		m.list.Select(f.selected)
		m.onSelectionChanged()
	}
}

// rebuildDirFrame/rebuildNodeFrame redraw a frame already on the stack
// (ascend popped back to it) without pushing a duplicate.
func (m *browseModel) rebuildDirFrame(dir string) error {
	m.frames = m.frames[:len(m.frames)-1]
	return m.pushDirFrame(dir)
}

func (m *browseModel) rebuildNodeFrame(n *carve.Node) error {
	m.frames = m.frames[:len(m.frames)-1]
	return m.pushNodeFrame(n)
}

// reconJob is one entry's recon work: a real OS path, or a package member
// spooled to a temp file first (see runReconJob).
type reconJob struct {
	key, name, osPath string
	node              *carve.Node
}

// reconReadyMsg announces that job.key's report is in the cache now.
type reconReadyMsg struct{ key, name string }

// reconQueue runs recon jobs one at a time in the background, in priority
// order: bump moves an entry to the front (used when it's highlighted),
// enqueue appends one at the back (used when a frame is first listed). One
// worker, deliberately: these can mean hashing or decompressing a multi-GB
// file, and running many at once would thrash disk/CPU for no benefit — the
// point of bumping is that whatever you're looking at gets there next, not
// that everything finishes faster.
type reconQueue struct {
	mu           sync.Mutex
	cond         *sync.Cond
	pending      []reconJob
	inflightKey  string
	inflightName string
	cache        map[string]string
	seen         map[string]bool // every key ever enqueued, whether done, pending, or in flight - stats()'s total
	ready        chan reconReadyMsg
	startOnce    sync.Once
}

// newReconQueue only allocates - start() launches the worker. A job's work
// (runReconJob) swaps the global os.Stdout to capture recon's printed report,
// and bubbletea's Program.Run reads that same global to find the terminal's
// real fd during its own startup; starting the worker any earlier races that
// startup (confirmed with -race: the worker's first job could run, and swap
// os.Stdout, before Run ever gets to look at it). newBrowseModel runs before
// Run is called, so it only builds the queue; Init - which bubbletea invokes
// after the terminal is set up - starts it.
func newReconQueue() *reconQueue {
	q := &reconQueue{cache: map[string]string{}, seen: map[string]bool{}, ready: make(chan reconReadyMsg, 32)}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *reconQueue) start() { q.startOnce.Do(func() { go q.run() }) }

func (q *reconQueue) run() {
	for {
		job := q.next()
		out := runReconJob(job)
		q.mu.Lock()
		q.cache[job.key] = out
		q.inflightKey, q.inflightName = "", ""
		q.mu.Unlock()
		q.ready <- reconReadyMsg{key: job.key, name: job.name}
	}
}

// next blocks until a job is pending, then claims it.
func (q *reconQueue) next() reconJob {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.pending) == 0 {
		q.cond.Wait()
	}
	job := q.pending[0]
	q.pending = q.pending[1:]
	q.inflightKey, q.inflightName = job.key, job.name
	return job
}

// enqueue appends job once per key, ever - a frame revisited later (ascend
// back into it) calls this again for the same entries, and seen is what
// keeps that from re-running or re-counting work already done.
func (q *reconQueue) enqueue(job reconJob) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.seen[job.key] {
		return
	}
	q.seen[job.key] = true
	q.pending = append(q.pending, job)
	q.cond.Signal()
}

// bump moves key to the front of the queue if it's waiting there; a no-op if
// it's already done, already in flight, or not queued at all (not every
// list entry is reconnable).
func (q *reconQueue) bump(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, p := range q.pending {
		if p.key == key {
			copy(q.pending[1:i+1], q.pending[:i])
			q.pending[0] = p
			return
		}
	}
}

func (q *reconQueue) get(key string) (string, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out, ok := q.cache[key]
	return out, ok
}

// stats is the global progress bar's (done, total) across every key this
// queue has ever seen, regardless of which frame it came from.
func (q *reconQueue) stats() (done, total int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.cache), len(q.seen)
}

// inflightDisplay is the name of the job actively running right now, if any.
func (q *reconQueue) inflightDisplay() (name string, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.inflightKey == "" {
		return "", false
	}
	return q.inflightName, true
}

// runReconJob is the actual work a queue worker does: a package member (node
// set) has no path recon's own machinery can open, so it's spooled to a temp
// file first, under its own base name (some recon checks match a known
// filename, e.g. "micom_sw.bin" - a random temp name would silently skip
// those) — the same bytes 'x' would extract.
func runReconJob(job reconJob) string {
	path := job.osPath
	if path == "" {
		tmp, cleanup, err := spoolNodeToTemp(job.node)
		if err != nil {
			return cWarn("[!] spooling for recon: " + err.Error())
		}
		defer cleanup()
		path = tmp
	}
	// recon's progress spinner/bar writes straight to os.Stderr assuming it
	// owns the terminal; browse already does, via bubbletea's alt screen, so
	// suppress it here or its redraws corrupt the TUI. Safe without a lock:
	// only one job runs at a time (see reconQueue's doc comment).
	prevTTY := stderrIsTTY
	stderrIsTTY = false
	out, rerr := captureStdout(func() error { return runFileRecon(path) })
	stderrIsTTY = prevTTY
	if rerr != nil {
		out += "\n" + cWarn("[!] "+rerr.Error())
	}
	return out
}

// spoolNodeToTemp writes n's bytes to a temp file under n's own base name.
func spoolNodeToTemp(n *carve.Node) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "unbrick-browse-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	dst := filepath.Join(dir, filepath.Base(strings.TrimSuffix(n.Name, "/")))
	if err := writeNode(n, dst, true); err != nil {
		cleanup()
		return "", nil, err
	}
	return dst, cleanup, nil
}

// extract writes the selected carve.Node to the current directory, the same
// as 'unbrick extract' without -r. A plain OS entry needs no extracting —
// it's already a file.
func (m *browseModel) extract() {
	e, ok := m.selected()
	if !ok || e.node == nil {
		m.setStatus("nothing to extract here")
		return
	}
	dst := filepath.Base(strings.TrimSuffix(e.node.Name, "/"))
	if err := writeNode(e.node, dst, false); err != nil {
		m.setStatus("extract: " + err.Error())
		return
	}
	m.setStatus("extracted to ./" + dst)
}

// prettyPrint reformats content for a format browse knows how to, by
// extension first and then by sniffing the content itself (a renamed or
// extensionless .json still opens brace-first). ok is false for anything
// else - a plain text file just shows as its (already readable) self, not
// "pretty-printed" vs. "raw" versions of the same bytes.
func prettyPrint(name string, content []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(content)
	looksJSON := len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
	if strings.ToLower(filepath.Ext(name)) != ".json" && !looksJSON {
		return nil, false
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, content, "", "  "); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// textPreviewCap bounds how much of a text file showPreview reads: enough
// for a real look at it, not so much that a mislabeled multi-GB file (text
// detection is a heuristic on the first 8KB, not a guarantee) stalls the UI.
const textPreviewCap = 256 << 10

// readForPreview reads up to textPreviewCap bytes of e's content, from disk
// or from its carve.Node - whichever e actually is.
func readForPreview(e browseEntry) (content []byte, truncated bool, err error) {
	var r io.ReadCloser
	switch {
	case e.osPath != "":
		r, err = os.Open(e.osPath)
	case e.node != nil:
		r, err = e.node.Reader()
	default:
		return nil, false, fmt.Errorf("%s has no readable content", e.name)
	}
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	content, err = io.ReadAll(io.LimitReader(r, textPreviewCap+1))
	if err != nil {
		return nil, false, err
	}
	if len(content) > textPreviewCap {
		return content[:textPreviewCap], true, nil
	}
	return content, false, nil
}

// highlightText renders content with chroma's syntax highlighting, matched
// by filename first and falling back to content analysis, when color is on;
// plain text otherwise (NO_COLOR - browse itself already requires a real
// terminal, so colorEnabled is normally true here already).
func highlightText(name string, content []byte) string {
	if !colorEnabled {
		return string(content)
	}
	lexer := lexers.Match(name)
	if lexer == nil {
		lexer = lexers.Analyse(string(content))
	}
	if lexer == nil {
		lexer = lexers.Fallback
	}
	iter, err := chroma.Coalesce(lexer).Tokenise(nil, string(content))
	if err != nil {
		return string(content)
	}
	var buf bytes.Buffer
	if err := formatters.TTY256.Format(&buf, styles.Get("monokai"), iter); err != nil {
		return string(content)
	}
	return buf.String()
}

// fileHeadLabel reads just enough of a plain OS file to type-label it, the
// way recon and ls already do — cheap even for a multi-GB file.
func fileHeadLabel(path string) (label string, isText bool) {
	f, err := os.Open(path)
	if err != nil {
		return "unknown", false
	}
	defer f.Close()
	head := make([]byte, 8192)
	n, _ := f.Read(head)
	head = head[:n]
	return typeLabel(filepath.Base(path), head), looksLikeText(path, head)
}

// textExts names extensions worth previewing as text even when
// filetype.Text's content heuristic says no - a real .ini/.log/.cfg can have
// one stray non-UTF8 or control byte (a mis-encoded string, a CRLF artifact,
// one binary-ish line in an otherwise-text log) and that heuristic rejects
// the whole file over it. The name already says "this is text" more
// reliably than a byte-level scan of just the head can refute.
var textExts = map[string]bool{
	".txt": true, ".ini": true, ".cfg": true, ".conf": true, ".config": true,
	".log": true, ".json": true, ".xml": true, ".yaml": true, ".yml": true,
	".md": true, ".markdown": true, ".csv": true, ".tsv": true, ".properties": true,
	".rc": true, ".env": true, ".sh": true, ".bash": true, ".inf": true,
}

// looksLikeText is the isText gate shared by OS files and carve.Node
// members: a real content check first, a known text extension as a
// fallback for what that check's strict UTF-8/control-byte rule rejects.
func looksLikeText(name string, head []byte) bool {
	if ok, _ := filetype.Text(head); ok {
		return true
	}
	return textExts[strings.ToLower(filepath.Ext(name))]
}
