package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// browse is the one TUI in go-unbrick: everything else (ls, tree, extract,
// recon) is a flat command meant for scripts and pipes, and stays that way.
// This is the file-manager-style front end over the same primitives: a
// directory on disk, and anything carve can open inside a file.
func newBrowseCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "browse <file | dir | url>",
		Short: "interactively navigate a directory or anything carve can open inside a file",
		Long: `browse is go-unbrick's one TUI: a file-manager-style view over a local
directory, or over anything carve can open inside a file (archive members,
payload partitions, filesystem files, boot image sections, ...).

Every reconnable entry in the current list recons itself in the background,
one at a time, lowest-index first; highlighting an entry jumps its recon to
the front of that queue, so the one you're looking at finishes soonest and
the preview pane fills in with the full report on its own, not just on 'r'.

  enter / l / →     descend into the selected directory or container
  backspace/h/←     go back up one level
  r                 jump the selected entry to the front of the recon queue
                     and wait for it (a package member is spooled to a temp
                     file first; most entries are already done by the time
                     you look, from the background queue above)
  x                 extract the selected entry to the current directory
  /                 filter the current list
  click / wheel     select, activate, or scroll with the mouse
  q, ctrl+c         quit

There is no flat/non-interactive mode for this command; it requires a real
terminal. Use ls/tree/recon/extract directly for scripting or piping.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isInteractive() {
				return fmt.Errorf("browse needs an interactive terminal (stdin and stdout); use ls/tree/recon/extract instead")
			}
			m, err := newBrowseModel(args[0])
			if err != nil {
				return err
			}
			_, err = tea.NewProgram(m).Run()
			return err
		},
	}
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
	title string
	osDir string
	node  *carve.Node
}

type browseModel struct {
	frames  []browseFrame
	list    list.Model
	preview viewport.Model
	spin    spinner.Model
	rq      *reconQueue
	busy    string // display name of the entry 'r' is actively waiting on, "" when idle
	busyKey string
	status  string
	width   int
	height  int
}

func newBrowseModel(input string) (*browseModel, error) {
	m := &browseModel{
		list:    list.New(nil, browseDelegate{}, 0, 0),
		preview: viewport.New(),
		spin:    spinner.New(),
		rq:      newReconQueue(),
	}
	// This isn't list.DefaultDelegate's two-line card view, and the
	// breadcrumb/status line below the panes already says where we are and
	// what the last action did — the list's own title/status/pagination/help
	// chrome would just repeat that in a second place.
	m.list.SetShowTitle(false)
	m.list.SetShowStatusBar(false)
	m.list.SetShowPagination(false)
	m.list.SetShowHelp(false)

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
	return tea.Batch(waitReady(m.rq.ready), func() tea.Msg {
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
		if m.busy == "" {
			return m, nil // nothing being actively waited on; stop the chain
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case reconReadyMsg:
		if m.busyKey == msg.key {
			m.busy, m.busyKey = "", ""
			if out, ok := m.rq.get(msg.key); ok {
				m.preview.SetContent(out)
				m.status = "recon: " + msg.name
			}
		} else if sel, ok := m.selected(); ok {
			if k, ok := reconKey(sel); ok && k == msg.key {
				m.showPreview() // picks up the result that just landed in the cache
			}
		}
		return m, waitReady(m.rq.ready)
	case tea.KeyPressMsg:
		switch msg.Keystroke() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter", "l", "right":
			m.descend()
			return m, nil
		case "backspace", "h", "left":
			m.ascend()
			return m, nil
		case "r":
			return m, m.startRecon()
		case "x":
			m.extract()
			return m, nil
		}
	case tea.MouseClickMsg:
		m.handleClick(msg.Mouse())
		return m, nil
	case tea.MouseWheelMsg:
		m.handleWheel(msg.Mouse())
		return m, nil
	}
	var cmd tea.Cmd
	before := m.list.Index()
	m.list, cmd = m.list.Update(msg)
	if m.list.Index() != before {
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
	switch {
	case m.busy != "":
		status = m.spin.View() + " reconning " + m.busy + "..."
	case status == "":
		status = strings.Join(m.breadcrumb(), " / ")
	}
	v := tea.NewView(body + "\n" + cLabel(status))
	v.MouseMode = tea.MouseModeCellMotion
	return v
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
	h := m.height - 2 // status line + a little breathing room
	if h < 1 {
		h = 1
	}
	m.list.SetSize(listW, h)
	m.preview.SetWidth(m.width - listW - 1)
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
// it's queued. A recon 'r' is actively waiting on owns the pane until it
// reports back.
func (m *browseModel) showPreview() {
	if m.busy != "" {
		return
	}
	m.status = ""
	e, ok := m.selected()
	if !ok {
		m.preview.SetContent("")
		return
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
		fmt.Fprintln(&b, "\nrecon queued in the background; r to jump the queue")
	default:
		fmt.Fprintf(&b, "%s\n%s\n", humanBytes(e.size), e.label)
		if e.isContainer {
			fmt.Fprintln(&b, "\npress enter to open")
		}
		fmt.Fprintln(&b, "recon queued in the background (spooled to a temp file); r to jump the queue, x to extract")
	}
	m.preview.SetContent(b.String())
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
		size := int64(-1)
		if fi, err := d.Info(); err == nil {
			size = fi.Size()
		}
		items = append(items, browseEntry{name: d.Name(), size: size, label: fileHeadLabel(full), osPath: full})
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
		items = append(items, browseEntry{name: k.Name, size: k.Size, label: label, isContainer: isContainer, node: k})
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
	f := m.current()
	switch {
	case f.node != nil:
		if err := m.rebuildNodeFrame(f.node); err != nil {
			m.setStatus(err.Error())
		}
	default:
		if err := m.rebuildDirFrame(f.osDir); err != nil {
			m.setStatus(err.Error())
		}
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

// startRecon handles 'r': if the background queue already finished this
// entry, show it immediately — no need to wait on anything. Otherwise jump
// it to the front of the queue (ahead of whatever's merely queued; the job
// already in flight, if any, still finishes first) and wait, with the
// spinner in View animating via spinner.TickMsg until reconReadyMsg matches.
func (m *browseModel) startRecon() tea.Cmd {
	e, ok := m.selected()
	if !ok || e.dir {
		m.setStatus("recon needs a file, not a directory")
		return nil
	}
	key, ok := reconKey(e)
	if !ok {
		m.setStatus("nothing to recon here")
		return nil
	}
	if out, ok := m.rq.get(key); ok {
		m.preview.SetContent(out)
		m.status = "recon: " + e.name
		return nil
	}
	if m.busy != "" {
		return nil // already actively waiting on one
	}
	m.rq.bump(key)
	m.busy, m.busyKey = e.name, key
	return m.spin.Tick
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
	mu        sync.Mutex
	cond      *sync.Cond
	pending   []reconJob
	inflight  string
	cache     map[string]string
	ready     chan reconReadyMsg
	startOnce sync.Once
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
	q := &reconQueue{cache: map[string]string{}, ready: make(chan reconReadyMsg, 32)}
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
		q.inflight = ""
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
	q.inflight = job.key
	return job
}

func (q *reconQueue) enqueue(job reconJob) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, done := q.cache[job.key]; done || q.inflight == job.key {
		return
	}
	for _, p := range q.pending {
		if p.key == job.key {
			return
		}
	}
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

// runReconJob is the actual work a queue worker (or a direct 'r' wait) does:
// a package member (node set) has no path recon's own machinery can open, so
// it's spooled to a temp file first, under its own base name (some recon
// checks match a known filename, e.g. "micom_sw.bin" - a random temp name
// would silently skip those) — the same bytes 'x' would extract.
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

// fileHeadLabel reads just enough of a plain OS file to type-label it, the
// way recon and ls already do — cheap even for a multi-GB file.
func fileHeadLabel(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	head := make([]byte, 8192)
	n, _ := f.Read(head)
	return typeLabel(filepath.Base(path), head[:n])
}
