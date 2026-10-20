package main

import (
	"bytes"
	cl "container/list" // aliased: "list" below is charm.land/bubbles/v2/list, the TUI widget - unrelated
	"encoding/base64"
	"fmt"
	"image"
	_ "image/jpeg" // registers the JPEG decoder with image.Decode; never called directly
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/NurramoX/streakboard/kitty"
	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/ansi/iterm2"
	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// browse is the one TUI in go-unbrick: everything else (ls, tree, extract,
// recon) is a flat command meant for scripts and pipes, and stays that way.
// This is the file-manager-style front end over the same primitives: a
// directory on disk, and anything carve can open inside a file.
func newBrowseCmd() *cobra.Command {
	var skip []string
	var webAddr string
	var noCrawl bool
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
			if webAddr != "" {
				return runBrowseWeb(args[0], skip, webAddr)
			}
			if !isInteractive() {
				return fmt.Errorf("browse needs an interactive terminal (stdin and stdout); use ls/tree/recon/extract instead")
			}
			m, err := newBrowseModel(args[0], skip, !noCrawl)
			if err != nil {
				return err
			}
			// Our own image placement is always id kittyImageID, deleted
			// and replaced on every render - but a previous run (killed,
			// crashed, or just exited normally without us ever clearing
			// on the way out) can leave a DIFFERENT placement, at
			// whatever geometry that session had, sitting on the
			// terminal indefinitely: Kitty placements outlive the
			// program that drew them. Confirmed live: this is what an
			// "image overlays the list, unpredictably, on files whose
			// own decode/position both check out fine" bug actually was
			// - a stale placement from an earlier invocation, not
			// anything about the current one. Delete everything before
			// drawing anything, and again on the way out, rather than
			// trusting that whatever's already on screen is ours.
			//
			// m.termOut, not os.Stdout: recon's background worker swaps
			// the global os.Stdout variable to capture a job's printed
			// output (cmd_recon_dir.go's captureStdout), and that worker
			// can already be running by the time this deferred write
			// happens on the way out. m.termOut is captured once in
			// newBrowseModel, before recon's worker goroutine exists to
			// race it - see its comment.
			fmt.Fprint(m.termOut, ansi.KittyGraphics(nil, "a=d", "d=A"))
			defer fmt.Fprint(m.termOut, ansi.KittyGraphics(nil, "a=d", "d=A"))
			_, err = tea.NewProgram(m).Run()
			return err
		},
	}
	c.Flags().StringSliceVar(&skip, "skip", nil, "directory listings: leave files out (they're never listed, so never preemptively reconned either): \"navi\" for the navigation map parts, or a glob on the file name; repeatable or comma-separated - same values as 'recon --skip'")
	c.Flags().BoolVar(&noCrawl, "no-auto-recon", false, "recon only what is listed and highlighted; by default the rest is reconned too, to any depth, in the background and behind whatever you navigate to")
	c.Flags().StringVar(&webAddr, "web", "", "serve the browser as a web page on this address instead, e.g. 127.0.0.1:8765 (port 0 picks one)")
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
	isImage     bool // previewed inline via the terminal's graphics protocol, if it has one - see imagePreview
	isParent    bool // the synthetic ".." row - clicking or entering it ascends, same as backspace/h/left
	osPath      string
	node        *carve.Node
}

func (e browseEntry) FilterValue() string { return e.name }

// parentEntry is the synthetic first row of every frame but the root one: a
// mouse-clickable (and enter-able) equivalent of backspace/h/left, since
// those have no on-screen representation to click at all.
var parentEntry = browseEntry{name: "..", size: -1, label: "up one level", isParent: true}

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
	level    *analysis.BrowseLevel
	selected int // index to restore on ascend - set by descend() just before leaving this frame
}

type browseModel struct {
	frames             []browseFrame
	list               list.Model
	preview            viewport.Model
	spin               spinner.Model
	rq                 *reconQueue
	skip               []string // --skip: directory frames leave these files out entirely (same values as 'recon --skip')
	showRaw            bool     // 'p' toggle: a pretty-printable text file (JSON, ...) shows reformatted by default
	graphics           graphicsProtocol
	previewImage       string // iTerm2 only: raw escape sequence for the currently previewed image, "" when not showing one - drawn separately in View(), never through m.preview/lipgloss (see showPreview)
	previewPlaceholder string // Kitty/Ghostty only: ordinary placeholder-glyph text for the currently previewed image, "" when not showing one - see startImageLoad
	lastKittyID        uint32 // most recent Kitty image id transmitted, 0 if none yet - see startImageLoad
	imgReady           chan imageLoadMsg
	// termOut is the real terminal, captured once here rather than read as
	// os.Stdout at write time: recon's background worker swaps that global
	// variable to capture a job's printed output (cmd_recon_dir.go's
	// captureStdout), and any of our own code that read os.Stdout directly
	// at the wrong moment would silently write into recon's pipe instead of
	// the terminal - confirmed with -race (a real, not theoretical, data
	// race on os.Stdout) after it explained an otherwise inexplicable "the
	// image never appears, but nothing errors" symptom: the Transmit/Place
	// setup bytes went into recon's capture pipe, never reaching the
	// terminal, while m.previewPlaceholder still got set - placeholder
	// glyphs with no registered image behind them render as nothing.
	// newBrowseModel runs before tea.NewProgram(m).Run() ever starts the
	// recon queue's worker goroutine (Init does that, not newBrowseModel),
	// so os.Stdout is still reliably the real terminal here.
	termOut *os.File
	status  string
	width   int
	height  int
}

func newBrowseModel(input string, skip []string, crawl bool) (*browseModel, error) {
	m := &browseModel{
		list:     list.New(nil, browseDelegate{}, 0, 0),
		preview:  viewport.New(),
		spin:     spinner.New(),
		imgReady: make(chan imageLoadMsg, 4),
		rq:       newReconQueue(),
		skip:     skip,
		termOut:  os.Stdout,
	}
	// Without this a long line just vanishes past the pane's width - no
	// scrollbar, no indicator it's cut off, and no keybinding here for
	// horizontal scroll either.
	m.preview.SoftWrap = true
	m.graphics = detectGraphics()
	m.rq.crawlOn, m.rq.skip = crawl, skip // before the first frame, which is where the crawl starts
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

	if infile.IsDir(input) {
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

// waitImage mirrors waitReady for imgReady - see its comment.
func waitImage(ch <-chan imageLoadMsg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

func (m *browseModel) Init() tea.Cmd {
	return tea.Batch(waitReady(m.rq.ready), waitImage(m.imgReady), m.spin.Tick, func() tea.Msg {
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
	case imageLoadMsg:
		// Dropped, bytes and all, if the selection moved on before this
		// landed - key is only ever set from startImageLoad/loadImage, not
		// user input, so there's no way to mistake a legitimately-retried
		// load for a stale one here.
		if sel, ok := m.selected(); ok {
			if k, ok := reconKey(sel); ok && k == msg.key {
				switch {
				case !msg.ok:
					m.preview.SetContent(m.fallbackPreview(sel))
				case msg.raw != "":
					m.previewImage = msg.raw
				default:
					// Setup (Transmit+Place) has no visual effect until the
					// Placeholder text below is actually rendered, so unlike
					// that text it doesn't need exact cell positioning - just
					// to arrive before it, which a direct write here (on
					// bubbletea's own single goroutine, same as every other
					// Update call) guarantees relative to the View() this
					// same message triggers.
					fmt.Fprint(m.termOut, string(msg.setup))
					m.previewPlaceholder = msg.placeholder
				}
			}
		}
		return m, waitImage(m.imgReady)
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

// padToWidth forces s to exactly w display columns: truncated if over
// (lipgloss's own Width() wraps instead of truncating, which is wrong for a
// single line that has to land at an exact terminal column or width), padded
// with trailing spaces if under (nothing downstream pads a bare string -
// that's what left ultraviolet's cell diff with stale trailing characters
// from a longer previous render, since it only rewrites cells a frame's
// content actually addresses).
func padToWidth(s string, w int) string {
	if sw := ansi.StringWidth(s); sw > w {
		return ansi.Truncate(s, w, "")
	} else if sw < w {
		return s + strings.Repeat(" ", w-sw)
	}
	return s
}

func (m *browseModel) View() tea.View {
	listW := m.width * 2 / 5
	rightW := m.width - listW - 1
	left := lipgloss.NewStyle().Width(listW).Render(m.list.View())

	// m.preview (a viewport) pads itself to its configured height, so the
	// plain-text branch's JoinHorizontal always gets exactly bodyHeight
	// lines from both sides - but m.list.View() only returns as many lines
	// as there are visible items, which can be far fewer than the pane
	// height in a short directory. Ultraviolet never clears a row a frame's
	// content doesn't mention, so confirmed live: a short list left dozens
	// of rows below it holding whatever a previous, longer frame had drawn
	// there. Both image paths below need this; the plain-text one doesn't,
	// because the viewport already pads itself.
	padLeftLines := func() []string {
		leftLines := strings.Split(left, "\n")
		if bodyHeight := m.height - 2; len(leftLines) < bodyHeight {
			blank := strings.Repeat(" ", listW)
			for len(leftLines) < bodyHeight {
				leftLines = append(leftLines, blank)
			}
		}
		return leftLines
	}

	var body string
	switch {
	case m.previewPlaceholder != "":
		// Kitty/Ghostty: m.previewPlaceholder is ordinary text (Unicode
		// placeholder glyphs, one per cell the image covers) built by
		// imagePreview - not a raw escape sequence. It goes through the
		// same per-line join as the plain-text case conceptually, just
		// without lipgloss's Width() (whose overlong-line wrapping, and
		// general unfamiliarity with grapheme-cluster-plus-SGR content
		// like this, isn't worth risking on it) - a manual join is enough
		// since every placeholder line is already exactly cols columns.
		leftLines := padLeftLines()
		phLines := strings.Split(m.previewPlaceholder, "\n")
		var b strings.Builder
		for i, line := range leftLines {
			if i > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(padToWidth(line, listW))
			b.WriteByte(' ')
			if i < len(phLines) {
				b.WriteString(phLines[i])
			}
		}
		body = b.String()
	case m.previewImage != "":
		// iTerm2 only (see imagePreview): a raw escape sequence that has
		// to ride on an actual cell, since iTerm2 has no placeholder-text
		// equivalent of Kitty's virtual placements. bubbletea's
		// cell-buffer renderer (ultraviolet) drops any CSI (so a
		// manually-emitted CUP) and ESC-Fp/Fs sequence
		// (SaveCursor/RestoreCursor) found in View content - only a
		// terminated APC/DCS/SOS/PM sequence survives, replayed against
		// whichever cell it sits at in the text stream. So the image
		// can't be positioned with cursor-movement escapes appended
		// after the fact; its bytes have to sit literally at the right
		// pane's top-left character in the content string.
		// lipgloss.JoinHorizontal measures/pads by display width and
		// mangles the raw escape bytes, so this bypasses it too.
		leftLines := padLeftLines()
		pad := strings.Repeat(" ", rightW)
		var b strings.Builder
		for i, line := range leftLines {
			if i > 0 {
				b.WriteByte('\n')
			}
			if i == 0 {
				line = padToWidth(line, listW)
			}
			b.WriteString(line)
			b.WriteByte(' ')
			if i == 0 {
				b.WriteString(m.previewImage)
			}
			b.WriteString(pad)
		}
		body = b.String()
	default:
		right := lipgloss.NewStyle().Width(rightW).Render(m.preview.View())
		body = lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	}

	status := m.status
	if name, ok := m.rq.inflightDisplay(); ok {
		status = m.spin.View() + " reconning " + name + "..."
	} else if status == "" {
		status = strings.Join(m.breadcrumb(), " / ")
	}

	// Padded to the full terminal width rather than left as whatever length
	// their own text happens to be: both vary between frames (digit counts
	// in the progress fractions, breadcrumb/status text length), and
	// ultraviolet only rewrites cells a frame's content actually addresses -
	// a shorter line doesn't erase what a longer one left in the cells past
	// its own end. Confirmed live via a raw pty capture: a progress line's
	// tail from an earlier, longer render stuck around, concatenated with
	// the new one, read back as "...this page ... overall page ... " with a
	// second progress bar's characters trailing off it. This was the
	// general-purpose version of every "stale content left on screen"
	// symptom chased through this file - not specific to images, lists, or
	// any particular code path, just two footer lines nothing ever padded.
	content := body + "\n" + padToWidth(m.progressLine(), m.width) + "\n" + padToWidth(cLabel(status), m.width)
	v := tea.NewView(content)
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
			m.rq.enqueueFront(reconJob{key: key, name: e.name, osPath: e.osPath, node: e.node})
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
	wasParent, _ := items[idx].(browseEntry)
	m.list.Select(idx)
	m.onSelectionChanged()
	if already || wasParent.isParent {
		m.descend() // a click on ".." activates immediately - a real back button, not "select then click again"
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
	// Cleared up front, not just in the branches that don't use it: every
	// return path below is "not showing an image", and View() draws
	// m.previewImage/m.previewPlaceholder on top of whatever's there
	// whenever either is non-empty, so a stale one has to be cleared
	// explicitly rather than just left unset by the branch that would
	// otherwise set it.
	m.previewImage = ""
	m.previewPlaceholder = ""
	e, ok := m.selected()
	if !ok {
		m.preview.SetContent("")
		return
	}
	// An image renders inline via the terminal's own graphics protocol, if
	// one was detected - if not, startImageLoad says so immediately and
	// this falls through to the plain size/type/recon preview below, same
	// as any other unrecognized format. If it does start, the actual read
	// and decode happen on a background goroutine (see startImageLoad's
	// comment on why) and land later as an imageLoadMsg in Update, which
	// calls fallbackPreview itself on failure - so a failed load's
	// fallback isn't duplicated here.
	//
	// m.previewImage (iTerm2) does NOT go through m.preview (a plain text
	// viewport) or lipgloss.JoinHorizontal in View(): confirmed live that
	// neither treats an OSC/APC graphics sequence as the atomic zero-width
	// unit it is - SoftWrap's line-wrapping and JoinHorizontal's
	// side-by-side width measurement both corrupted it before it reached
	// the terminal. m.previewPlaceholder (Kitty/Ghostty) is ordinary text
	// and does go through the normal join, just not lipgloss's Width() -
	// see View().
	if !e.dir && e.isImage {
		if m.startImageLoad(e) {
			m.preview.SetContent(cHdr(e.name) + "\n\nloading image...")
			return
		}
	}
	m.preview.SetContent(m.fallbackPreview(e))
}

// fallbackPreview is shown for anything not handled above: a text file
// (isText) previews as itself immediately, rather than waiting on or being
// evicted by a cached recon result - it's still reconned in the background
// like everything else (enqueueAll doesn't check isText), and textPreview
// appends that once it lands rather than replacing the content with it -
// "text can match and be read" means both, not either. Otherwise the cached
// recon report if the background queue has already reached it, or cheap,
// always-available info (size, type label) plus a note that it's running -
// highlighting it already put it at the front of the queue.
func (m *browseModel) fallbackPreview(e browseEntry) string {
	if !e.dir && e.isText {
		if out, ok := m.textPreview(e); ok {
			return out
		}
	}
	if key, ok := reconKey(e); ok {
		if out, ok := m.rq.get(key); ok {
			return out
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", cHdr(e.name))
	switch {
	case e.isParent:
		fmt.Fprintln(&b, "enter, or click, to go up one level")
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
		if e.node != nil && e.node.RandomAccess() {
			fmt.Fprintln(&b, "reconning in the background; x extracts")
		} else {
			fmt.Fprintln(&b, "reconning in the background (spooled to a temp file); x extracts")
		}
	}
	return b.String()
}

// graphicsProtocol is which inline-image escape-sequence dialect, if any,
// the terminal is believed to understand.
type graphicsProtocol int

const (
	graphicsNone graphicsProtocol = iota
	graphicsKitty
	graphicsITerm2
)

// detectGraphics guesses the terminal's inline-image protocol from
// well-known environment variables. There's no reliable cross-terminal
// capability query for this (unlike color profile, which bubbletea can
// actually ask the terminal about) - every terminal-image tool (chafa, viu,
// timg, yazi) resorts to the same env-var sniffing. Not a guarantee in
// either direction: a detected protocol can still be unsupported (TERM
// overridden, a multiplexer in between that doesn't pass the sequences
// through) and a real one can go undetected (an env var this doesn't know
// about yet) - unrecognized falls back to the plain text/recon preview,
// never a guess that might print raw escape garbage to the screen.
func detectGraphics() graphicsProtocol {
	switch {
	case os.Getenv("KITTY_WINDOW_ID") != "", os.Getenv("TERM") == "xterm-kitty":
		return graphicsKitty
	case os.Getenv("TERM_PROGRAM") == "ghostty", os.Getenv("TERM_PROGRAM") == "WezTerm":
		return graphicsKitty
	case os.Getenv("TERM_PROGRAM") == "vscode":
		// Shipped (microsoft/vscode#297073, closed passing on all three
		// platforms as of February 2026) but opt-in behind
		// terminal.integrated.enableImages - if that setting is off,
		// nothing renders, the same failure mode as not detecting the
		// terminal at all, not a crash or garbled screen.
		return graphicsKitty
	case os.Getenv("TERM_PROGRAM") == "iTerm.app":
		return graphicsITerm2
	default:
		return graphicsNone
	}
}

// maxImagePreviewBytes bounds what imagePreview will read and inline: a
// mislabeled multi-GB file that happens to pass looksLikeImage's magic-byte
// check (vanishingly unlikely for real JPEG/PNG magic, but not impossible)
// shouldn't get fully buffered into memory on the strength of that alone.
const maxImagePreviewBytes = 20 << 20

// imageLoadMsg carries the result of a background image load (see
// startImageLoad/loadImage), tagged with the entry's reconKey so Update can
// drop a result that arrives after the selection has already moved on,
// rather than misapplying it to whatever's now highlighted.
type imageLoadMsg struct {
	key         string
	ok          bool
	raw         string // iTerm2: the full escape sequence
	setup       []byte // Kitty: Delete(oldID)+TransmitPNG(id)+Place(id), written to the terminal when applied
	placeholder string // Kitty: ordinary placeholder-glyph text, see View()
}

// startImageLoad kicks off e's image load on a background goroutine if e
// looks like an image this terminal can preview inline; ok is false when
// there's nothing to load (no graphics protocol detected, dimensions not
// known yet, or the image is too large to address with Kitty's placeholder
// diacritics). The result arrives later as an imageLoadMsg.
//
// The read + JPEG decode + PNG re-encode + base64 used to run synchronously
// here, inside Update - fine most of the time, but a carve.Node read shares
// whatever decompression/container machinery the background recon queue is
// also using, and a slow read stalled Update (so every keypress, not just
// this preview) until it finished. Only the cheap, fast checks happen
// synchronously now; the slow part is loadImage, on its own goroutine.
func (m *browseModel) startImageLoad(e browseEntry) bool {
	if m.graphics == graphicsNone {
		return false
	}
	cols := m.width - m.listWidth() - 1
	rows := m.height - 2
	if cols <= 0 || rows <= 0 {
		// newBrowseModel's initial pushDirFrame/pushNodeFrame calls
		// showPreview before tea.NewProgram(m).Run() has ever delivered a
		// WindowSizeMsg, so m.width/m.height are still their zero-value
		// defaults the first time this runs - confirmed live (raw pty
		// capture): that produced a=T,c=-1,r=-2, a garbage-sized Kitty
		// placement sent before any real layout exists, which visibly
		// corrupted everything rendered after it even once the next
		// showPreview (from the real WindowSizeMsg's layout()) sent the
		// correctly-sized one. Skipping here until real dimensions are
		// known - layout() calls showPreview again right after SetSize, so
		// this reaches the image within the same startup, just not before
		// bubbletea has told us how big the screen actually is.
		return false
	}
	key, ok := reconKey(e)
	if !ok {
		return false
	}
	graphics := m.graphics
	var oldID, newID uint32
	if graphics == graphicsKitty {
		if cols > kitty.MaxSpan || rows > kitty.MaxSpan {
			return false
		}
		// Allocated synchronously, not inside the goroutine: Update runs
		// on one goroutine with no concurrent caller, so this is race-free
		// here in a way it wouldn't be if two in-flight loads both touched
		// m.lastKittyID from their own goroutines.
		oldID = m.lastKittyID
		m.lastKittyID++
		newID = m.lastKittyID
	}
	ch := m.imgReady
	// Paused for the duration of the read+decode+encode below, not just the
	// read: recon's own job on the same container is the contention, and all
	// of this (not just readImageBytes) can block behind a lock held across
	// a slow decompression read.
	m.rq.pause()
	go func() {
		defer m.rq.resume()
		ch <- loadImage(e, key, graphics, oldID, newID, cols, rows)
	}()
	return true
}

// loadImage does the actual read/decode/encode work for startImageLoad, on
// its own goroutine - e, cols, rows, and the ids are all copied in by value
// when the goroutine is spawned, so this touches no browseModel state.
func loadImage(e browseEntry, key string, graphics graphicsProtocol, oldID, newID uint32, cols, rows int) imageLoadMsg {
	raw, truncated, err := readImageBytes(e, maxImagePreviewBytes)
	if err != nil || truncated {
		return imageLoadMsg{key: key}
	}
	switch graphics {
	case graphicsITerm2:
		f := iterm2.File{
			Name:    e.name,
			Size:    int64(len(raw)),
			Width:   iterm2.Cells(cols),
			Height:  iterm2.Cells(rows),
			Inline:  true,
			Content: []byte(base64.StdEncoding.EncodeToString(raw)),
		}
		return imageLoadMsg{key: key, ok: true, raw: ansi.ITerm2(f)}
	case graphicsKitty:
		// A JPEG passed as-is is accepted by some Kitty implementations'
		// lenient decoders and rejected by others, so it's decoded and
		// re-encoded to PNG (kitty.TransmitPNG does the encoding) rather
		// than relied on either way.
		img, _, err := image.Decode(bytes.NewReader(raw))
		if err != nil {
			return imageLoadMsg{key: key}
		}
		debugImagePreview(e.name, len(raw), img.Bounds(), cols, rows)
		// A fixed image id (delete-then-retransmit under the same
		// identity every time the selection changed) was tried first and
		// mostly worked, but left an intermittent, non-deterministic
		// "image overlays the list" that survived verifying every other
		// input byte-for-byte correct across dozens of captures. Moved on
		// to this library's Unicode-placeholder approach instead of
		// chasing that further: the image position now rides on ordinary
		// text cells (m.previewPlaceholder, see View()) that ultraviolet
		// diffs and positions the same as any other content, rather than
		// on the raw-escape passthrough mechanism that every other fix
		// this session was working around the edges of. A fresh id per
		// image is kept anyway, deleting the specific previous one -
		// cheap, and avoids whatever a fixed id did or didn't contribute
		// to the old symptom.
		var setup bytes.Buffer
		if oldID != 0 {
			setup.Write(kitty.Delete(oldID))
		}
		tx, err := kitty.TransmitPNG(newID, img)
		if err != nil {
			return imageLoadMsg{key: key}
		}
		setup.Write(tx)
		pl, err := kitty.Place(newID, rows, cols)
		if err != nil {
			return imageLoadMsg{key: key}
		}
		setup.Write(pl)
		ph, err := kitty.Placeholder(newID, rows, cols)
		if err != nil {
			return imageLoadMsg{key: key}
		}
		return imageLoadMsg{key: key, ok: true, setup: setup.Bytes(), placeholder: ph}
	default:
		return imageLoadMsg{key: key}
	}
}

// readImageBytes reads up to capBytes+1 of e's content to detect whether it
// exceeds the cap.
func readImageBytes(e browseEntry, capBytes int64) (data []byte, truncated bool, err error) {
	return analysis.ReadEntry(e.core(), capBytes)
}

// debugImagePreview appends one diagnostic line per image render to the file
// named by UNBRICK_BROWSE_IMGDEBUG, when set - a no-op otherwise. Added to
// chase an intermittent "image overlays the list" bug that varies by file
// despite identical cols/rows requested, where a screenshot alone can't say
// whether the decoded image's actual pixel bounds, not just its filename,
// line up with what was asked for.
func debugImagePreview(name string, rawLen int, bounds image.Rectangle, cols, rows int) {
	path := os.Getenv("UNBRICK_BROWSE_IMGDEBUG")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s raw=%dB decodedBounds=%v requestedCols=%d requestedRows=%d\n",
		name, rawLen, bounds, cols, rows)
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

// maxPreemptiveRecon bounds how many of a frame's entries enqueueAll queues
// up front. A directory of firmware files or a tar's members is dozens to a
// few hundred - fine to recon all of in the background. A filesystem (an
// ext4 image can list thousands of files) is a different scale: queuing
// every one of them, each spooled to a temp file and fully reconned, for
// files nobody's looked at yet, is what "takes forever" when you open one.
// Anything past this cap just isn't preemptively queued; onSelectionChanged
// still reaches it the moment it's highlighted, via enqueueFront rather than
// bump (which only works on something already in the queue).
const maxPreemptiveRecon = 300

// enqueueAll preemptively queues a freshly built frame's entries, in list
// order up to maxPreemptiveRecon, then bumps whichever one ends up selected
// (the first one, right after ResetSelected) to the front — so it, at
// least, starts immediately rather than waiting behind everything else.
func (m *browseModel) enqueueAll(items []list.Item) {
	queued := 0
	for _, it := range items {
		if queued >= maxPreemptiveRecon {
			break // a filesystem with thousands of members (an ext4 image) would otherwise queue all of them, each spooled to a temp file and fully reconned, for files nobody's looked at yet - highlighting one beyond this cap still reaches the front via onSelectionChanged's enqueueFront, same as any bumped entry
		}
		e, ok := it.(browseEntry)
		if !ok {
			continue
		}
		key, ok := reconKey(e)
		if !ok {
			continue
		}
		m.rq.enqueue(reconJob{key: key, name: e.name, osPath: e.osPath, node: e.node})
		queued++
	}
	// What is on screen is where the crawl starts: it lists the containers and
	// directories here, then those inside them, whenever nothing else is waiting.
	for _, it := range items {
		if e, ok := it.(browseEntry); ok && !e.isParent && (e.dir || e.isContainer || e.osPath != "" && !e.isText && !e.isImage) {
			m.rq.addCrawl(e.core())
		}
	}
	if e, ok := m.selected(); ok {
		if key, ok := reconKey(e); ok {
			m.rq.bump(key)
		}
	}
}

// pushDirFrame lists an OS directory's entries as the new top frame.
func (m *browseModel) pushDirFrame(dir string) error {
	l, err := analysis.ListDir(dir, m.skip)
	if err != nil {
		return err
	}
	m.pushLevel(l)
	return nil
}

// pushNodeFrame lists a carve.Node's children as the new top frame.
func (m *browseModel) pushNodeFrame(n *carve.Node) error {
	l, err := analysis.ListNode(n)
	if err != nil {
		return err
	}
	m.pushLevel(l)
	return nil
}

// pushLevel makes a listed level (analysis.ListDir, ListNode, Open) the new top
// frame.
func (m *browseModel) pushLevel(l *analysis.BrowseLevel) {
	items := make([]list.Item, 0, len(l.Entries))
	for _, e := range l.Entries {
		items = append(items, entryOf(e))
	}
	m.frames = append(m.frames, browseFrame{title: l.Title, level: l})
	m.finishFrame(items)
}

// entryOf is a listed entry as the list holds it.
func entryOf(e analysis.BrowseEntry) browseEntry {
	return browseEntry{name: e.Name, size: e.Size, label: e.Label, dir: e.Dir, isContainer: e.Container,
		isText: e.Text, isImage: e.Image, osPath: e.OSPath, node: e.Node}
}

// core is the entry as the analysis package knows it.
func (e browseEntry) core() analysis.BrowseEntry {
	return analysis.BrowseEntry{Name: e.name, Size: e.size, Label: e.label, Dir: e.dir, Container: e.isContainer,
		Text: e.isText, Image: e.isImage, OSPath: e.osPath, Node: e.node}
}

// finishFrame prepends the synthetic ".." row (every frame but the root one
// gets a mouse-clickable, enter-able equivalent of backspace/h/left, which
// otherwise have no on-screen representation to click at all), then applies
// the resulting list: selecting the first real entry rather than ".." itself
// when there is one, so landing in a freshly opened directory or container
// doesn't put the cursor on the one entry that leaves it again.
func (m *browseModel) finishFrame(items []list.Item) {
	hasParent := len(m.frames) > 1 // the frame for this listing was already appended by the caller
	if hasParent {
		items = append([]list.Item{parentEntry}, items...)
	}
	m.list.SetItems(items)
	m.list.ResetSelected()
	if hasParent && len(items) > 1 {
		m.list.Select(1)
	}
	m.enqueueAll(items)
	m.showPreview()
}

// current is the frame browse is showing the contents of.
func (m *browseModel) current() browseFrame { return m.frames[len(m.frames)-1] }

func (m *browseModel) descend() {
	e, ok := m.selected()
	if !ok {
		return
	}
	if e.isParent {
		m.ascend()
		return
	}
	// Remember where we were in this frame so ascend can put the cursor back
	// on the entry we came from, instead of always landing on the first item.
	if len(m.frames) > 0 {
		m.frames[len(m.frames)-1].selected = m.list.Index()
	}
	l, err := analysis.Open(e.core(), m.skip)
	switch {
	case err != nil && e.dir:
		m.setStatus(err.Error())
	case err != nil:
		m.setStatus(e.name + ": " + err.Error())
	default:
		m.pushLevel(l)
	}
}

func (m *browseModel) ascend() {
	if len(m.frames) <= 1 {
		return
	}
	m.frames = m.frames[:len(m.frames)-1]
	f := m.current() // a copy: the frame is popped and re-pushed below, but f.selected survives in this local copy
	l, err := f.level.Refresh(m.skip)
	if err != nil {
		m.setStatus(err.Error())
		return
	}
	m.frames = m.frames[:len(m.frames)-1]
	m.pushLevel(l)
	if f.selected >= 0 && f.selected < len(m.list.Items()) {
		m.list.Select(f.selected)
		m.onSelectionChanged()
	}
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
//
// Below those is the crawl: with it on, the queue goes on by itself, listing the
// containers and directories it has seen (starting from what is on screen) and
// queueing their entries too, to any depth, at the lowest priority. It lists
// and recons only when nothing else is waiting or running, and anything the
// user navigates to is promoted out of it, so navigating always comes first. A
// job already running is not interrupted (recon cannot be cancelled): it is
// what finishes before the next thing you asked for.
type reconQueue struct {
	mu           sync.Mutex
	cond         *sync.Cond
	pending      *cl.List               // of reconJob, front = next to run
	byKey        map[string]*cl.Element // pending[key]'s element, for O(1) bump - with pending a slice, bump had to linear-scan it (then shift up to N elements) on every single highlight change; for a few thousand entries (an ext4 with ~2000 files) that's real, felt lag on every j/k, not a one-off cost
	low          *cl.List               // of reconJob: what the crawl found, run when pending is empty
	lowByKey     map[string]*cl.Element
	inflightKey  string
	inflightName string
	cache        map[string]string
	seen         map[string]bool // every key ever enqueued, whether done, pending, or in flight - stats()'s total
	ready        chan reconReadyMsg
	startOnce    sync.Once
	pauseCount   int // see pause/resume

	crawlOn    bool
	crawlTodo  []analysis.BrowseEntry // containers and directories to list, in the order seen
	crawlKnown map[string]bool        // keys ever added to crawlTodo
	crawlLists int                    // how many it has listed
	skip       []string               // --skip, for the directory listings
}

// Bounds on the crawl: a filesystem image lists thousands of files and a
// directory tree more; the crawl takes the first of each level and stops after
// a number of listings, so it cannot run for ever on a large input.
const (
	crawlPerLevel = 300
	crawlMaxLists = 3000
)

// newReconQueue only allocates - start() launches the worker. A job's work
// (runReconJob) swaps the global os.Stdout to capture recon's printed report,
// and bubbletea's Program.Run reads that same global to find the terminal's
// real fd during its own startup; starting the worker any earlier races that
// startup (confirmed with -race: the worker's first job could run, and swap
// os.Stdout, before Run ever gets to look at it). newBrowseModel runs before
// Run is called, so it only builds the queue; Init - which bubbletea invokes
// after the terminal is set up - starts it.
func newReconQueue() *reconQueue {
	q := &reconQueue{
		pending:    cl.New(),
		byKey:      map[string]*cl.Element{},
		low:        cl.New(),
		lowByKey:   map[string]*cl.Element{},
		cache:      map[string]string{},
		seen:       map[string]bool{},
		crawlKnown: map[string]bool{},
		ready:      make(chan reconReadyMsg, 32),
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *reconQueue) start() {
	q.startOnce.Do(func() {
		go q.run()
		if q.crawlOn {
			go q.crawl()
		}
	})
}

func (q *reconQueue) run() {
	for {
		job := q.next()
		out := runReconJob(job)
		q.mu.Lock()
		q.cache[job.key] = out
		q.inflightKey, q.inflightName = "", ""
		q.mu.Unlock()
		q.cond.Broadcast() // the crawl waits for the queue to go idle
		q.ready <- reconReadyMsg{key: job.key, name: job.name}
	}
}

// next blocks until a job is pending (or the crawl has one) and the queue isn't
// paused, then claims it.
func (q *reconQueue) next() reconJob {
	q.mu.Lock()
	defer q.mu.Unlock()
	for (q.pending.Len() == 0 && q.low.Len() == 0) || q.pauseCount > 0 {
		q.cond.Wait()
	}
	var job reconJob
	if front := q.pending.Front(); front != nil {
		job = front.Value.(reconJob)
		q.pending.Remove(front)
		delete(q.byKey, job.key)
	} else {
		front = q.low.Front()
		job = front.Value.(reconJob)
		q.low.Remove(front)
		delete(q.lowByKey, job.key)
	}
	q.inflightKey, q.inflightName = job.key, job.name
	return job
}

// pause keeps the worker from claiming its next job until every matching
// resume call has happened - a counter, not a bool, since more than one
// image load can be in flight at once (rapid navigation) and the worker
// shouldn't resume until all of them are done. Used while loading an image
// preview: reading a carve.Node shares whatever decompression/container
// machinery a recon job on the same container is also using, and starting a
// new multi-second recon job right as an image load begins is exactly the
// contention that made "took ages" worse than it needed to be. This can't
// interrupt a job already in flight when the image load starts - only stop a
// new one from being picked up - but that's still the common case (recon
// catching up between jobs far more often than it's mid-job).
func (q *reconQueue) pause() {
	q.mu.Lock()
	q.pauseCount++
	q.mu.Unlock()
}

// resume reverses one pause call; see its comment.
func (q *reconQueue) resume() {
	q.mu.Lock()
	q.pauseCount--
	q.mu.Unlock()
	q.cond.Broadcast()
}

// promote takes a job the crawl queued out of the low queue, if it is there.
// Caller holds mu.
func (q *reconQueue) promote(key string) (reconJob, bool) {
	elem, ok := q.lowByKey[key]
	if !ok {
		return reconJob{}, false
	}
	job := elem.Value.(reconJob)
	q.low.Remove(elem)
	delete(q.lowByKey, key)
	return job, true
}

// enqueue appends job once per key, ever - a frame revisited later (ascend
// back into it) calls this again for the same entries, and seen is what
// keeps that from re-running or re-counting work already done. One the crawl
// had already queued is promoted to the back of the real queue: it was
// navigated to.
func (q *reconQueue) enqueue(job reconJob) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.seen[job.key] {
		if j, ok := q.promote(job.key); ok {
			q.byKey[j.key] = q.pending.PushBack(j)
			q.cond.Broadcast()
		}
		return
	}
	q.seen[job.key] = true
	q.byKey[job.key] = q.pending.PushBack(job)
	q.cond.Broadcast()
}

// bump moves key to the front of the queue if it's waiting there, whether in the
// real queue or the crawl's; a no-op if it's already done, already in flight, or
// not queued at all (not every list entry is reconnable).
func (q *reconQueue) bump(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if elem, ok := q.byKey[key]; ok {
		q.pending.MoveToFront(elem)
		return
	}
	if j, ok := q.promote(key); ok {
		q.byKey[j.key] = q.pending.PushFront(j)
		q.cond.Broadcast()
	}
}

// enqueueFront is bump, but for an entry that may never have been queued at
// all (enqueueAll's maxPreemptiveRecon cap skips entries past it) - it
// queues job at the front if this is the first time job.key has been seen,
// same as bump if it's already pending, and does nothing if it's done or
// in flight already. The single highlight-driven path for every entry,
// capped or not.
func (q *reconQueue) enqueueFront(job reconJob) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if elem, ok := q.byKey[job.key]; ok {
		q.pending.MoveToFront(elem)
		return
	}
	if j, ok := q.promote(job.key); ok {
		q.byKey[j.key] = q.pending.PushFront(j)
		q.cond.Broadcast()
		return
	}
	if q.seen[job.key] {
		return
	}
	q.seen[job.key] = true
	q.byKey[job.key] = q.pending.PushFront(job)
	q.cond.Broadcast()
}

// enqueueLow queues a job at the lowest priority, once per key.
func (q *reconQueue) enqueueLow(job reconJob) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.seen[job.key] {
		return
	}
	q.seen[job.key] = true
	q.lowByKey[job.key] = q.low.PushBack(job)
	q.cond.Broadcast()
}

// addCrawl notes a container or directory for the crawl to list, once.
func (q *reconQueue) addCrawl(e analysis.BrowseEntry) {
	key := e.Key()
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.crawlOn || q.crawlKnown[key] {
		return
	}
	q.crawlKnown[key] = true
	q.crawlTodo = append(q.crawlTodo, e)
	q.cond.Broadcast()
}

// idleLocked says nothing is queued, running or held back. Caller holds mu.
func (q *reconQueue) idleLocked() bool {
	return q.pending.Len() == 0 && q.low.Len() == 0 && q.inflightKey == "" && q.pauseCount == 0
}

// crawl lists what it has noted, first seen first (so a level before the
// levels below it), one listing at a time and only when the queue is idle: the
// entries it finds are queued low, to be reconned the same way, and the
// containers among them noted in turn.
func (q *reconQueue) crawl() {
	for {
		q.mu.Lock()
		for len(q.crawlTodo) == 0 || !q.idleLocked() || q.crawlLists >= crawlMaxLists {
			q.cond.Wait()
		}
		e := q.crawlTodo[0]
		q.crawlTodo = q.crawlTodo[1:]
		q.crawlLists++
		q.mu.Unlock()

		level, err := analysis.Open(e, q.skip)
		if err != nil {
			continue
		}
		for i, c := range level.Entries {
			if i >= crawlPerLevel {
				break
			}
			if key, ok := reconKey(entryOf(c)); ok {
				q.enqueueLow(reconJob{key: key, name: c.Name, osPath: c.OSPath, node: c.Node})
			}
			if c.Dir || c.Container || c.Openable {
				q.addCrawl(c)
			}
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
		if job.node.RandomAccess() {
			// A member that reads at random is recon'd where it is, as a virtual
			// input: nothing is written to disk, however large (a decrypted
			// 859 MiB OTA zip would otherwise be copied out in full first).
			if ra, err := job.node.ReaderAt(); err == nil {
				p, release := infile.RegisterVirtual(job.node.Name, ra, job.node.Size, "")
				defer release()
				path = p
			}
		}
		if path == "" { // one that can only be streamed has to be written out to be read at random
			tmp, cleanup, err := spoolNodeToTemp(job.node)
			if err != nil {
				return cWarn("[!] spooling for recon: " + err.Error())
			}
			defer cleanup()
			path = tmp
		}
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

// prettyPrint, readForPreview and the content gates are the analysis package's,
// shared with the web browser.
func prettyPrint(name string, content []byte) ([]byte, bool) {
	return analysis.PrettyPrint(name, content)
}

// textPreviewCap bounds how much of a text file showPreview reads: enough
// for a real look at it, not so much that a mislabeled multi-GB file (text
// detection is a heuristic on the first 8KB, not a guarantee) stalls the UI.
const textPreviewCap = analysis.PreviewCap

func readForPreview(e browseEntry) (content []byte, truncated bool, err error) {
	return analysis.ReadEntry(e.core(), textPreviewCap)
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

func fileHeadLabel(path string) (label string, isText, isImage bool) {
	return analysis.FileHeadLabel(path)
}

func looksLikeImage(head []byte) bool { return analysis.LooksLikeImage(head) }

func looksLikeText(name string, head []byte) bool { return analysis.LooksLikeText(name, head) }
