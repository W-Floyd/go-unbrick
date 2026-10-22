package analysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/androidkeys"
	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/pemfile"
	"github.com/W-Floyd/go-unbrick/internal/progress"
)

// Browsing: a directory on disk (local or ssh://), or anything carve can open
// inside a file (archive members, partitions, filesystem files, boot image
// sections), navigated a level at a time. The terminal browser and the web page
// both call these.

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

	Path   string      `json:"-"` // from the input's root, through nested containers (see Place)
	OSPath string      `json:"-"` // a file or directory on disk (or ssh://)
	Node   *carve.Node `json:"-"` // a member of a container
	Group  *Group      `json:"-"` // a directory implied by a container's member names
}

// Key identifies the entry among its level's: two members can share a name, the
// node cannot.
func (e BrowseEntry) Key() string {
	switch {
	case e.Group != nil:
		return fmt.Sprintf("group:%p:%s", e.Group.Container, e.Group.Prefix)
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
	Path    string      // of the level from the input's root, with a trailing slash ("" at the top)
	Dir     string      // set for a directory on disk
	Node    *carve.Node // set for a container
	Entries []BrowseEntry

	group *Group // the directory of a container's members this level lists
}

// ListDir lists a directory on disk: directories, then files with their type
// labels, hidden entries left out and skip applied.
func ListDir(dir string, skip []string) (*BrowseLevel, error) {
	des, err := infile.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })
	l := &BrowseLevel{Title: filepath.Base(dir), Dir: dir}
	probes := 0
	for _, d := range des {
		if d.Name() != "." && strings.HasPrefix(d.Name(), ".") {
			continue
		}
		full := infile.Join(dir, d.Name())
		if d.IsDir() {
			l.Entries = append(l.Entries, BrowseEntry{Name: d.Name(), Size: -1, Dir: true, Openable: true, OSPath: full})
			continue
		}
		size := int64(-1)
		if fi, err := d.Info(); err == nil {
			size = fi.Size()
		}
		label, isText, isImage := FileHeadLabel(full)
		if label == string(filetype.Unknown) && probes < deepProbesPerLevel {
			head, _ := fileHead(full)
			l2, probed := deepLabel(size, head, func() ([]byte, error) { return infile.ReadFile(full) })
			if probed {
				probes++
			}
			if l2 != "" {
				label = l2
			}
		}
		l.Entries = append(l.Entries, BrowseEntry{Name: d.Name(), Size: size, Label: label, Text: isText, Image: isImage,
			Openable: !isText && !isImage, OSPath: full})
	}
	return l, nil
}

// headCacheMax is the listing size above which member heads are not kept.
const headCacheMax = 5000

// progressMin is the number of files in a level above which listing it is reported.
const progressMin = 500

// Group is a directory a container's members imply by their slash-separated
// names: the members under it, and the prefix that names it.
type Group struct {
	Container *carve.Node
	Kids      []*carve.Node
	Prefix    string // "" for the container itself, else "dir/sub/"
}

// ListNode lists the members of a container, folding names with slashes into
// directories so a tree of thousands of files is browsed a level at a time.
func ListNode(n *carve.Node) (*BrowseLevel, error) {
	_, kids, err := n.Children()
	if err != nil {
		return nil, err
	}
	return ListGroup(Group{Container: n, Kids: kids}), nil
}

// ListGroup lists one directory level of a container's members.
func ListGroup(g Group) *BrowseLevel {
	title := strings.TrimSuffix(g.Prefix, "/")
	if i := strings.LastIndexByte(title, '/'); i >= 0 {
		title = title[i+1:]
	}
	if title == "" {
		title = g.Container.Name
	}
	if title == "" {
		title = "/"
	}
	l := &BrowseLevel{Title: title, Node: g.Container, group: &g}
	var dirs []string
	byDir := map[string][]*carve.Node{}
	var files []*carve.Node
	for _, k := range g.Kids {
		rel := strings.TrimPrefix(k.Name, g.Prefix)
		if seg, _, nested := strings.Cut(rel, "/"); nested && seg != "" {
			if _, seen := byDir[seg]; !seen {
				dirs = append(dirs, seg)
			}
			byDir[seg] = append(byDir[seg], k)
			continue
		}
		files = append(files, k)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		sub := Group{Container: g.Container, Kids: byDir[d], Prefix: g.Prefix + d + "/"}
		l.Entries = append(l.Entries, BrowseEntry{Name: d, Size: -1, Dir: true, Openable: true, Group: &sub})
	}
	// Each node caches its head (up to 64 KiB); across a source tree's hundreds of
	// thousands of members that is gigabytes, for a label read once.
	dropHeads := len(files) > headCacheMax
	probes := 0
	var task *progress.Task
	if len(files) > progressMin {
		task = progress.Begin("listing "+title, int64(len(files)))
		defer task.End()
	}
	for _, k := range files {
		if task != nil {
			task.Add(1)
		}
		name := strings.TrimPrefix(k.Name, g.Prefix)
		label := TypeLabel(k.Name, k.Head())
		if label == string(filetype.Unknown) && probes < deepProbesPerLevel {
			l2, probed := deepLabel(k.Size, k.Head(), k.Bytes)
			if probed {
				probes++
			}
			if l2 != "" {
				label = l2
			}
		}
		isContainer := false
		if sub, ok := carve.Format(k); ok {
			label, isContainer = sub.Kind, true
		}
		l.Entries = append(l.Entries, BrowseEntry{Name: name, Size: k.Size, Label: label, Container: isContainer,
			Text: LooksLikeText(k.Name, k.Head()), Image: LooksLikeImage(k.Head()), Openable: isContainer, Node: k})
		if dropHeads {
			k.DropHead()
		}
	}
	return l
}

// ErrNotContainer is the answer for opening something carve does not open.
var ErrNotContainer = errors.New("not a container")

// Open is the level inside an entry: a directory listed, a file on disk opened
// through carve, or a container's members.
func Open(e BrowseEntry, skip []string) (*BrowseLevel, error) {
	l, err := openRaw(e, skip)
	if err != nil {
		return nil, err
	}
	l.place(e.Path+"/", skip)
	return l, nil
}

// openRaw is Open without the --match filter.
func openRaw(e BrowseEntry, skip []string) (*BrowseLevel, error) {
	switch {
	case e.Group != nil:
		return ListGroup(*e.Group), nil
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
	var n *BrowseLevel
	var err error
	switch {
	case l.group != nil:
		n = ListGroup(*l.group)
	case l.Node != nil:
		n, err = ListNode(l.Node)
	default:
		n, err = ListDir(l.Dir, skip)
	}
	if err != nil {
		return nil, err
	}
	n.place(l.Path, skip)
	return n, nil
}

// OpenInput is the top level of an input: a directory, or the members of whatever
// carve opens it as.
func OpenInput(input string, skip []string) (*BrowseLevel, error) {
	var l *BrowseLevel
	if infile.IsDir(input) {
		var err error
		if l, err = ListDir(input, skip); err != nil {
			return nil, err
		}
	} else {
		root, err := OpenRoot(input)
		if err != nil {
			return nil, err
		}
		if l, err = ListNode(root); err != nil {
			return nil, err
		}
	}
	l.place("", skip)
	return l, nil
}

// BrowseMatch, when set, limits listings to entries whose full path (from the
// input's root, through nested containers) matches, and to the directories and
// containers that hold one, opened down to BrowseDepth container levels to look.
var BrowseMatch *regexp.Regexp

// BrowseDepth is how many container levels BrowseMatch opens, the first included.
var BrowseDepth = 3

var holdsCache = struct {
	sync.Mutex
	m map[string]bool
}{m: map[string]bool{}}

// Place gives the level's entries their paths, under prefix ("" for the input's
// own level, else the path of what was opened and a slash), and applies
// BrowseMatch. A level made by ListDir, ListNode or ListGroup is placed before use.
func (l *BrowseLevel) Place(prefix string, skip []string) { l.place(prefix, skip) }

func (l *BrowseLevel) place(prefix string, skip []string) {
	l.setPaths(prefix)
	if len(skip) == 0 && BrowseMatch == nil {
		return
	}
	kept := l.Entries[:0]
	for _, e := range l.Entries {
		if SkipPath(skip, e.Path) {
			continue
		}
		if BrowseMatch != nil && !matchEntry(e, skip, BrowseDepth) {
			continue
		}
		kept = append(kept, e)
	}
	l.Entries = kept
}

func (l *BrowseLevel) setPaths(prefix string) {
	l.Path = prefix
	for i := range l.Entries {
		l.Entries[i].Path = prefix + l.Entries[i].Name
	}
}

// matchEntry reports whether an entry is, or holds, a BrowseMatch match, opening
// containers while depth allows. A file on disk that is not text or an image may
// be a container: it is tried.
func matchEntry(e BrowseEntry, skip []string, depth int) bool {
	if BrowseMatch.MatchString(e.Path) {
		return true
	}
	dir := e.Dir || e.Group != nil
	if !dir && (e.Text || e.Image || (e.OSPath == "" && !e.Container)) {
		return false
	}
	if !dir {
		if depth <= 0 {
			return false
		}
		depth-- // opening a container spends a level; a directory does not
	}
	key := fmt.Sprintf("%s@%d", e.Path, depth)
	holdsCache.Lock()
	v, ok := holdsCache.m[key]
	holdsCache.Unlock()
	if ok {
		return v
	}
	v = false
	if l, err := openRaw(e, skip); err == nil {
		l.setPaths(e.Path + "/")
		for _, c := range l.Entries {
			if !SkipPath(skip, c.Path) && matchEntry(c, skip, depth) {
				v = true
				break
			}
		}
	}
	holdsCache.Lock()
	holdsCache.m[key] = v
	holdsCache.Unlock()
	return v
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
	head, err := fileHead(path)
	if err != nil {
		return "unknown", false, false
	}
	return TypeLabel(filepath.Base(path), head), LooksLikeText(path, head), LooksLikeImage(head)
}

// fileHead is the first 8 KiB of a plain file.
func fileHead(path string) ([]byte, error) {
	f, err := infile.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, 8192)
	n, _ := f.Read(head)
	return head[:n], nil
}

const (
	// deepProbeMax is the largest file a listing will read in full to label it.
	deepProbeMax = 64 << 20
	// deepProbesPerLevel bounds how many files one listing reads in full this way: a
	// directory of firmware images, most starting with ARM code, must not be read
	// whole to list it.
	deepProbesPerLevel = 8
)

// deepLabel names a file whose start does not say what it is, by reading all of it,
// for the kinds that carry nothing recognisable at the start: a raw ARM Linux
// kernel (padding after a few instructions; its banner is megabytes in). It reads
// only a file of a plausible size that starts like one, and probed says it did, so
// the caller can count the reads it makes.
func deepLabel(size int64, head []byte, read func() ([]byte, error)) (label string, probed bool) {
	if size <= 0 || size > deepProbeMax || !bootimg.StartsLikeARMKernel(head) {
		return "", false
	}
	data, err := read()
	if err != nil {
		return "", true
	}
	if bootimg.IsRawKernel(data) {
		return "ARM Linux kernel", true
	}
	return "", true
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
	if androidkeys.Is(head) || pemfile.Is(head) {
		return false // recon reads it as the keys or certificates it holds
	}
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
