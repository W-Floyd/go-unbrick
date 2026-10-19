package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"charm.land/bubbles/v2/list"
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

  enter / l / →   descend into the selected directory or container
  backspace/h/←   go back up one level
  r               recon the selected file (same report as 'unbrick recon') —
                  only on a real file on disk, not a package member
  x               extract the selected entry to the current directory
  /               filter the current list
  q, ctrl+c       quit

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
// bubbletea needs to read key events from one and draw to the other.
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
func (e browseEntry) Title() string       { return e.name }
func (e browseEntry) Description() string {
	switch {
	case e.dir:
		return "directory"
	case e.size < 0:
		return e.label
	default:
		return humanBytes(e.size) + "  " + e.label
	}
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
	status  string
	width   int
	height  int
}

func newBrowseModel(input string) (*browseModel, error) {
	m := &browseModel{
		list:    list.New(nil, list.NewDefaultDelegate(), 0, 0),
		preview: viewport.New(),
	}
	m.list.Title = "browse"
	m.list.SetShowHelp(true)

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

func (m *browseModel) Init() tea.Cmd { return nil }

func (m *browseModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
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
			m.recon()
			return m, nil
		case "x":
			m.extract()
			return m, nil
		}
	}
	var cmd tea.Cmd
	before := m.list.Index()
	m.list, cmd = m.list.Update(msg)
	if m.list.Index() != before {
		m.showPreview()
	}
	return m, cmd
}

func (m *browseModel) View() tea.View {
	listW := m.width * 2 / 5
	left := lipgloss.NewStyle().Width(listW).Render(m.list.View())
	right := lipgloss.NewStyle().Width(m.width - listW - 1).Render(m.preview.View())
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	status := m.status
	if status == "" {
		status = strings.Join(m.breadcrumb(), " / ")
	}
	return tea.NewView(body + "\n" + cLabel(status))
}

func (m *browseModel) breadcrumb() []string {
	out := make([]string, len(m.frames))
	for i, f := range m.frames {
		out[i] = f.title
	}
	return out
}

func (m *browseModel) layout() {
	listW := m.width * 2 / 5
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

// showPreview sets the preview pane to cheap, always-available info about the
// highlighted entry — never a full recon (that's 'r', on request: it can mean
// hashing a multi-GB file).
func (m *browseModel) showPreview() {
	m.status = ""
	e, ok := m.selected()
	if !ok {
		m.preview.SetContent("")
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", cHdr(e.name))
	switch {
	case e.dir:
		fmt.Fprintln(&b, "directory")
	case e.osPath != "":
		fmt.Fprintf(&b, "%s\n%s\n", humanBytes(e.size), e.label)
		fmt.Fprintln(&b, "\npress r to recon, enter to open as a container")
	default:
		fmt.Fprintf(&b, "%s\n%s\n", humanBytes(e.size), e.label)
		if e.isContainer {
			fmt.Fprintln(&b, "\npress enter to open")
		}
		fmt.Fprintln(&b, "press x to extract")
	}
	m.preview.SetContent(b.String())
}

func (m *browseModel) setStatus(s string) { m.status = s }

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
	m.list.Title = dir
	m.list.SetItems(items)
	m.list.ResetSelected()
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
	m.list.Title = title
	m.list.SetItems(items)
	m.list.ResetSelected()
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

// recon reports the selected entry the same way 'unbrick recon' would — only
// meaningful for a real file on disk, since recon's own machinery (fact
// resolution, package learning) is built around a path, not a carve.Node a
// few containers deep.
func (m *browseModel) recon() {
	e, ok := m.selected()
	if !ok || e.osPath == "" || e.dir {
		m.setStatus("recon only works on a file on disk, not a directory or a package member")
		return
	}
	// recon's progress spinner/bar writes straight to os.Stderr assuming it
	// owns the terminal; browse already does, via bubbletea's alt screen, so
	// suppress it for the duration or its redraws corrupt the TUI.
	prevTTY := stderrIsTTY
	stderrIsTTY = false
	out, rerr := captureStdout(func() error { return runFileRecon(e.osPath) })
	stderrIsTTY = prevTTY
	if rerr != nil {
		out += "\n" + cWarn("[!] "+rerr.Error())
	}
	m.preview.SetContent(out)
	m.status = "recon: " + e.name
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
