package analysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// Browsing: a directory on disk (local or ssh://), or anything carve can open
// inside a file (archive members, partitions, filesystem files, boot image
// sections), navigated a level at a time. The terminal browser and the web page
// both call these.

// SkipFilter is how a host drops files from directory listings (recon's --skip):
// it gets the full paths of a directory's files and returns the ones to keep.
// The default keeps them all.
var SkipFilter = func(paths []string, skip []string) []string { return paths }

// BrowseEntry is one row of a level.
type BrowseEntry struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"` // -1 unknown (a directory)
	Label     string `json:"label"`
	Dir       bool   `json:"dir"`
	Container bool   `json:"container"` // carve recognises it: it can be gone into
	Text      bool   `json:"text"`      // previewed as text
	Image     bool   `json:"image"`     // a raster image a viewer can show
	// Openable says there is somewhere to try going: a directory, a container, or a
	// file on disk, which is opened (and may turn out to be nothing) when asked.
	Openable bool `json:"openable"`

	OSPath string      `json:"-"` // a file or directory on disk (or ssh://)
	Node   *carve.Node `json:"-"` // a member of a container
}

// Key identifies the entry among its level's: two members can share a name, the
// node cannot.
func (e BrowseEntry) Key() string {
	switch {
	case e.OSPath != "":
		return "os:" + e.OSPath
	case e.Node != nil:
		return fmt.Sprintf("node:%p", e.Node)
	}
	return "name:" + e.Name
}

// BrowseLevel is a directory or a container, listed.
type BrowseLevel struct {
	Title   string
	Dir     string      // set for a directory on disk
	Node    *carve.Node // set for a container
	Entries []BrowseEntry
}

// ListDir lists a directory on disk: directories, then files with their type
// labels, hidden entries left out and skip applied.
func ListDir(dir string, skip []string) (*BrowseLevel, error) {
	des, err := infile.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })
	var filePaths []string
	for _, d := range des {
		if !d.IsDir() {
			filePaths = append(filePaths, infile.Join(dir, d.Name()))
		}
	}
	keep := map[string]bool{}
	for _, p := range SkipFilter(filePaths, skip) {
		keep[p] = true
	}
	l := &BrowseLevel{Title: filepath.Base(dir), Dir: dir}
	for _, d := range des {
		if d.Name() != "." && strings.HasPrefix(d.Name(), ".") {
			continue
		}
		full := infile.Join(dir, d.Name())
		if d.IsDir() {
			l.Entries = append(l.Entries, BrowseEntry{Name: d.Name(), Size: -1, Dir: true, Openable: true, OSPath: full})
			continue
		}
		if !keep[full] {
			continue
		}
		size := int64(-1)
		if fi, err := d.Info(); err == nil {
			size = fi.Size()
		}
		label, isText, isImage := FileHeadLabel(full)
		l.Entries = append(l.Entries, BrowseEntry{Name: d.Name(), Size: size, Label: label, Text: isText, Image: isImage,
			Openable: !isText && !isImage, OSPath: full})
	}
	return l, nil
}

// ListNode lists the members of a container.
func ListNode(n *carve.Node) (*BrowseLevel, error) {
	_, kids, err := n.Children()
	if err != nil {
		return nil, err
	}
	title := n.Name
	if title == "" {
		title = "/"
	}
	l := &BrowseLevel{Title: title, Node: n}
	for _, k := range kids {
		label := TypeLabel(k.Name, k.Head())
		isContainer := false
		if sub, ok := carve.Format(k); ok {
			label, isContainer = sub.Kind, true
		}
		l.Entries = append(l.Entries, BrowseEntry{Name: k.Name, Size: k.Size, Label: label, Container: isContainer,
			Text: LooksLikeText(k.Name, k.Head()), Image: LooksLikeImage(k.Head()), Openable: isContainer, Node: k})
	}
	return l, nil
}

// ErrNotContainer is the answer for opening something carve does not open.
var ErrNotContainer = errors.New("not a container")

// Open is the level inside an entry: a directory listed, a file on disk opened
// through carve, or a container's members.
func Open(e BrowseEntry, skip []string) (*BrowseLevel, error) {
	switch {
	case e.Dir:
		return ListDir(e.OSPath, skip)
	case e.OSPath != "":
		root, err := OpenRoot(e.OSPath)
		if err != nil {
			return nil, err
		}
		return ListNode(root)
	case e.Node != nil && e.Container:
		return ListNode(e.Node)
	}
	return nil, fmt.Errorf("%s: %w (%s)", e.Name, ErrNotContainer, e.Label)
}

// Refresh lists a level again.
func (l *BrowseLevel) Refresh(skip []string) (*BrowseLevel, error) {
	if l.Node != nil {
		return ListNode(l.Node)
	}
	return ListDir(l.Dir, skip)
}

// OpenInput is the top level of an input: a directory, or the members of whatever
// carve opens it as.
func OpenInput(input string, skip []string) (*BrowseLevel, error) {
	if infile.IsDir(input) {
		return ListDir(input, skip)
	}
	root, err := OpenRoot(input)
	if err != nil {
		return nil, err
	}
	return ListNode(root)
}

// PreviewCap bounds how much of a file ReadEntry reads for a preview.
const PreviewCap = 256 << 10

// ReadEntry reads up to limit bytes of an entry, from disk or from its node.
func ReadEntry(e BrowseEntry, limit int64) (data []byte, truncated bool, err error) {
	var r io.ReadCloser
	switch {
	case e.OSPath != "":
		r, err = infile.Open(e.OSPath)
	case e.Node != nil:
		r, err = e.Node.Reader()
	default:
		return nil, false, fmt.Errorf("%s has no readable content", e.Name)
	}
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	data, err = io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// OpenEntryReader streams an entry's whole content.
func OpenEntryReader(e BrowseEntry) (io.ReadCloser, error) {
	switch {
	case e.OSPath != "" && !e.Dir:
		return infile.Open(e.OSPath)
	case e.Node != nil:
		return e.Node.Reader()
	}
	return nil, fmt.Errorf("%s has no readable content", e.Name)
}

// PrettyPrint reformats content for a format it knows how to, by extension first
// and then by sniffing the content itself (a renamed or extensionless .json still
// opens brace-first). ok is false for anything else.
func PrettyPrint(name string, content []byte) ([]byte, bool) {
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

// FileHeadLabel reads just enough of a plain file to type-label it, the way recon
// and ls do: cheap even for a multi-GB file.
func FileHeadLabel(path string) (label string, isText, isImage bool) {
	f, err := infile.Open(path)
	if err != nil {
		return "unknown", false, false
	}
	defer f.Close()
	head := make([]byte, 8192)
	n, _ := f.Read(head)
	head = head[:n]
	return TypeLabel(filepath.Base(path), head), LooksLikeText(path, head), LooksLikeImage(head)
}

// LooksLikeImage is the Image gate: a real decodable raster format (JPEG, PNG), by
// content, not extension.
func LooksLikeImage(head []byte) bool {
	switch filetype.Detect(head) {
	case filetype.JPEG, filetype.PNG:
		return true
	}
	return false
}

// textExts names extensions worth previewing as text even when the content check
// says no: a real .ini/.log can have one stray control byte, and the name says
// "text" more reliably than a scan of the head can refute.
var textExts = map[string]bool{
	".txt": true, ".ini": true, ".cfg": true, ".conf": true, ".config": true,
	".log": true, ".json": true, ".xml": true, ".yaml": true, ".yml": true,
	".md": true, ".markdown": true, ".csv": true, ".tsv": true, ".properties": true,
	".rc": true, ".env": true, ".sh": true, ".bash": true, ".inf": true,
}

// LooksLikeText is the Text gate shared by files on disk and members: a content
// check first, a known text extension as a fallback.
func LooksLikeText(name string, head []byte) bool {
	if ok, _ := filetype.Text(head); ok {
		return true
	}
	return textExts[strings.ToLower(filepath.Ext(name))]
}

// ---- addressing levels by path, for a front end that keeps no state of its own ----

// Browser is an input being browsed, with its levels reachable by a path of entry
// names from the top. Levels are listed on first use and kept.
type Browser struct {
	skip []string
	root *BrowseLevel

	lc levelCache[*BrowseLevel]
}

// NewBrowser opens an input for browsing.
func NewBrowser(input string, skip []string) (*Browser, error) {
	root, err := OpenInput(input, skip)
	if err != nil {
		return nil, err
	}
	return &Browser{skip: skip, root: root}, nil
}

// LevelAt is the level at a path of entry names. Entry names that are directories
// or containers are as listed ("sub", "pkg.tar").
func (b *Browser) LevelAt(path []string) (*BrowseLevel, error) {
	return b.lc.at(b.root, path, func(cur *BrowseLevel, name string) (*BrowseLevel, error) {
		e, ok := cur.Find(name)
		if !ok {
			return nil, ErrNoSuchEntry
		}
		return Open(e, b.skip)
	})
}

// Find is the entry called name in the level.
func (l *BrowseLevel) Find(name string) (BrowseEntry, bool) {
	for _, e := range l.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return BrowseEntry{}, false
}
