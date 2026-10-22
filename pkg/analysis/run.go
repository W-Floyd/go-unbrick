package analysis

import (
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// A comparison of two inputs, as a front end uses it: Start one, then walk its
// Levels, list their Entries as they stand (while it is still running), and load
// the Detail of any Entry. Nothing here draws; the terminal UI, a web UI and an
// embedding tool all call it.
//
// One comparison runs at a time per process: the progress line, the hash cache's
// trust setting and the prefetch budget are process-wide.

// Config says what to compare and how.
type Config struct {
	A, B    string // the inputs: files, images, packages, directories, ssh:// URLs
	Depth   int    // container levels to descend into
	Verbose bool
	// Member compares the file at this path inside each input, not the inputs
	// as trees.
	Member string
	// Verify reads every member instead of trusting a vendor manifest's stated hash.
	Verify bool
	// Match limits the comparison to members whose full path from the inputs'
	// roots, through nested containers, matches; containers are opened to look.
	Match *regexp.Regexp
	// Workers is how many container pairs go deeper at once (default 2): foreground
	// work, what a front end is looking at, may use all of them; the background uses
	// all but one, so a front end asking for something finds a place free. On a
	// spinning disk, 1 stops them competing.
	Workers int
	// AutoDeepen is how many levels beyond Depth the background goes on its own, each
	// path as far as that and no further, nearest what the front end is looking at
	// first, whenever a worker is spare. 0 turns it off, and with it going deeper as a
	// front end focuses (Run.Focus); negative has no limit.
	AutoDeepen int
	// FetchAhead is the bytes of ssh:// data fetched ahead of the comparison: 0 keeps
	// the default (512 MiB), negative turns it off.
	FetchAhead int64
}

// Kind is what became of an entry between the two inputs.
type Kind rune

const (
	Changed        Kind = '~'
	Renamed        Kind = '>' // renamed or moved, content identical
	RenamedChanged Kind = '≈'
	Added          Kind = '+' // only in B
	Removed        Kind = '-' // only in A
	Same           Kind = '='
	Dir            Kind = '/' // a directory, made from the paths of entries
	Up             Kind = '↑' // ".." in a level that has one above
	MetaOnly       Kind = '≡' // a pair of tars or zips whose members are all the same but whose headers differ (times, owners)
	Note           Kind = 0   // a message, not a pair (an error from comparing)
)

var kindNames = map[Kind]string{
	Changed: "changed", Renamed: "renamed", RenamedChanged: "renamed-changed", Added: "added",
	Removed: "removed", Same: "unchanged", Dir: "dir", Up: "up", Note: "note", MetaOnly: "metadata-only",
}

func (k Kind) String() string { return kindNames[k] }

// MarshalText makes a Kind a word in JSON.
func (k Kind) MarshalText() ([]byte, error) { return []byte(kindNames[k]), nil }

// Label is what the kind means, for a title.
func (k Kind) Label() string {
	switch k {
	case Changed:
		return "changed"
	case Renamed:
		return "renamed, content identical"
	case RenamedChanged:
		return "renamed and changed"
	case Added:
		return "only in B"
	case Removed:
		return "only in A"
	case Same:
		return "unchanged"
	case MetaOnly:
		return "same members, headers differ"
	}
	return ""
}

// Run is a comparison, running in the background or done.
type Run struct {
	mu      sync.Mutex
	root    *treeDiffTally
	summary string
	err     error
	done    chan struct{} // closed when the comparison has finished, successfully or not

	depth int // container levels compared into: Config.Depth, and Deepen's
	// Going deeper (expand.go): worker places, how far the background goes, the line a
	// front end is looking at.
	workers      int
	auto         int
	sem          chan struct{}
	fgWait       atomic.Int32
	wake         chan struct{}
	closed       chan struct{}
	closing      atomic.Bool
	focus        *diffLine
	notContainer map[*diffLine]bool
	rootLevel    *Level
	lc           levelCache[*Level] // opened by LevelAt
}

func newRun() *Run {
	r := &Run{done: make(chan struct{}), wake: make(chan struct{}, 1), closed: make(chan struct{})}
	r.setWorkers(defaultWorkers)
	return r
}

// defaultWorkers is how many pairs go deeper at once: one for what a front end asks
// for, one for the background to use while it is idle.
const defaultWorkers = 2

func (r *Run) setWorkers(n int) {
	r.workers = max(n, 1)
	r.sem = make(chan struct{}, r.workers)
}

func (r *Run) setRoot(t *treeDiffTally) {
	r.mu.Lock()
	r.root = t
	r.mu.Unlock()
}

func (r *Run) fail(err error) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
}

func (r *Run) get() (*treeDiffTally, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.root, r.summary, r.err
}

// Start begins comparing in the background and returns at once.
func Start(cfg Config) *Run {
	apply(cfg)
	diffQuiet = true // the front end draws the progress itself
	r := newRun()
	r.depth = cfg.Depth
	if cfg.Workers > 0 {
		r.setWorkers(cfg.Workers)
	}
	r.auto = cfg.AutoDeepen
	if r.auto != 0 {
		r.startCrawl()
	}
	go func() {
		defer close(r.done)
		if cfg.Member != "" { // one file out of each, not the trees
			r.setRoot(r.pairRoot(cfg.A, cfg.B, cfg.Member))
			return
		}
		t, ok, err := diffTree(cfg.A, cfg.B, cfg.Depth, cfg.Verbose, r.setRoot)
		switch {
		case err != nil:
			r.fail(err)
		case ok:
			r.mu.Lock()
			r.summary = fmt.Sprintf("%d changed, %d added, %d removed, %d renamed, %d unchanged",
				t.changed, t.added, t.removed, t.renamed+t.similar, t.same) + t.metaNote()
			r.mu.Unlock()
		default:
			r.setRoot(r.pairRoot(cfg.A, cfg.B, ""))
		}
	}()
	return r
}

// pairRoot is the tree for one pair: two inputs that are not containers, or the
// member at member inside each.
func (r *Run) pairRoot(pathA, pathB, member string) *treeDiffTally {
	a, b, name, err := PairNodes(pathA, pathB, member)
	if err != nil {
		r.fail(err)
		return nil
	}
	root := &treeDiffTally{}
	root.lines = []*diffLine{(&diffLine{text: "  ~ " + name}).tag('~', name, a, b)}
	return root
}

// Done is closed when the comparison has finished, successfully or not.
func (r *Run) Done() <-chan struct{} { return r.done }

// Finished says whether the comparison has finished.
func (r *Run) Finished() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// Err is why the comparison failed, if it did.
func (r *Run) Err() error { _, _, err := r.get(); return err }

// Summary is the counts of what was found, once there are some.
func (r *Run) Summary() string { _, s, _ := r.get(); return s }

// Status is what the comparison is doing now, in a line, while it works.
func (r *Run) Status() string { return dprog.status() }

// PairNodes opens the two things to compare: each input as it is, or, with a
// member, the file at that path inside each (a directory, an archive, an image,
// as ls and extract take a path). name is what the pair is called.
func PairNodes(pathA, pathB, member string) (a, b *carve.Node, name string, err error) {
	if a, err = diffRoot(pathA); err != nil {
		return nil, nil, "", err
	}
	if b, err = diffRoot(pathB); err != nil {
		return nil, nil, "", err
	}
	name = infile.Base(pathA)
	if bn := infile.Base(pathB); bn != name {
		name += " -> " + bn
	}
	if member == "" {
		return a, b, name, nil
	}
	if a, err = a.Walk(member); err != nil {
		return nil, nil, "", fmt.Errorf("%s: %w", pathA, err)
	}
	if b, err = b.Walk(member); err != nil {
		return nil, nil, "", fmt.Errorf("%s: %w", pathB, err)
	}
	return a, b, member, nil
}

// ---- levels and entries ----

// Entry is one row of a Level: a pair of files, a directory made from their
// paths, or ".." back up. It is a copy, taken under the lock the comparison
// writes under, so it is safe to keep and compare.
type Entry struct {
	Name    string `json:"name"` // as listed in its level: "notes.txt", "sub/", "pkg.tar/" (it has something inside), ".."
	Path    string `json:"path"`
	Kind    Kind   `json:"kind"`
	Pending bool   `json:"pending"`           // its inside is still being compared
	HasKids bool   `json:"hasKids"`           // there is somewhere to go in: a directory, or a container with differences inside
	Summary string `json:"summary,omitempty"` // for a directory or container: what is under it
	// Compared says, for a container, that its members were compared: no differences
	// listed inside it means they are the same. Without it the depth ran out first, and
	// nothing is known of its members until they are listed (Open does).
	Compared bool   `json:"compared"`
	Text     string `json:"text,omitempty"` // for a note: the message
	SizeA    int64  `json:"sizeA"`          // -1 for a side with no file
	SizeB    int64  `json:"sizeB"`
	SizeNote string `json:"sizeNote,omitempty"` // the sizes as a row shows them: "1.0 KiB -> 2.0 KiB"

	src  *diffLine // identity only: the comparison still writes it
	a, b *carve.Node
}

// EntryKey is what an Entry is, comparable: an entry that has become something
// else (an added file found to be a rename, a container whose comparison
// finished) has a different key.
type EntryKey struct {
	src     *diffLine
	kind    Kind
	path    string
	a, b    *carve.Node
	pending bool
}

// Key identifies the entry as it stands.
func (e Entry) Key() EntryKey { return EntryKey{e.src, e.Kind, e.Path, e.a, e.b, e.Pending} }

// HasFiles says whether the entry has files to read: a pair, or one side.
func (e Entry) HasFiles() bool { return !e.Pending && (e.a != nil || e.b != nil) }

// Level is the entries of a directory or of a container, to go into and come back
// out of, as browse does.
type Level struct {
	title string
	// source is this level's lines, as the comparison has them now. Called under liveMu.
	source func(root *treeDiffTally) []*diffLine
	// strip is the path the level's lines carry in front of their own names (a
	// container's path, for what was found inside it); dir narrows the level to
	// one directory of it ("" or ending in /).
	strip, dir string
	busy       func() bool // for a level built as it is looked at: still being built
}

// Root is the top level: what differs between the two inputs.
func (r *Run) Root() *Level {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rootLevel == nil {
		r.rootLevel = &Level{source: func(root *treeDiffTally) []*diffLine {
			if root == nil {
				return nil
			}
			return root.lines
		}}
	}
	return r.rootLevel
}

// Title names the level.
func (l *Level) Title() string { return l.title }

// SetTitle names the root level.
func (l *Level) SetTitle(t string) { l.title = t }

// Busy says whether the level is still being listed (a container's members, listed
// when asked for).
func (l *Level) Busy() bool { return l.busy != nil && l.busy() }

// Entries lists the level as it stands now: directories first (made from the
// paths, as many levels deep as the paths go), then the entries in the order
// found, with ".." first when up is set. Safe to call while the comparison runs.
func (r *Run) Entries(l *Level, up bool) []Entry {
	root, _, _ := r.get()
	return snapshotLevel(root, l, up)
}

func lineKids(l *diffLine) []*diffLine {
	if l.subT != nil {
		return l.subT.lines
	}
	return l.sub
}

func sizeNote(kind Kind, a, b *carve.Node) string {
	switch {
	case kind == Added && b != nil:
		return size(b)
	case (kind == Removed || kind == Renamed || kind == Same) && a != nil:
		return size(a)
	case a != nil && b != nil:
		return size(a) + " -> " + size(b)
	}
	return ""
}

func nodeSize(n *carve.Node) int64 {
	if n == nil || n.IsDirNode() {
		return -1
	}
	return n.Size
}

func snapshotLevel(root *treeDiffTally, f *Level, up bool) []Entry {
	liveMu.Lock()
	defer liveMu.Unlock()
	var src []*diffLine
	if f.source != nil {
		src = f.source(root)
	}
	var leaves []Entry
	type agg struct {
		counts  map[Kind]int
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
				leaves = append(leaves, Entry{Name: strings.TrimSpace(l.text), Text: strings.TrimRight(l.text, " "), SizeA: -1, SizeB: -1})
			}
			continue
		}
		kind := Kind(l.kind)
		within := l.path
		renamed := kind == Renamed || kind == RenamedChanged // "old -> new": a name, not a path to split
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
				a = &agg{counts: map[Kind]int{}}
				dirs[name] = a
				dirNames = append(dirNames, name)
			}
			a.counts[kind]++
			a.pending = a.pending || l.subT != nil
			continue
		}
		// Something inside it to go into: lines that are still there (a comparison
		// that found nothing different leaves its dropped lines behind), or a
		// comparison still running.
		counts := map[Kind]int{}
		for _, k := range lineKids(l) {
			if !k.drop && k.path != "" {
				counts[Kind(k.kind)]++
			}
		}
		kids := l.subT != nil || len(counts) > 0
		name := rel
		if kids {
			name += "/"
		}
		e := Entry{Name: name, Path: l.path, Kind: kind, Pending: l.subT != nil, HasKids: kids,
			SizeA: nodeSize(l.a), SizeB: nodeSize(l.b), SizeNote: sizeNote(kind, l.a, l.b), Compared: l.compared, src: l, a: l.a, b: l.b}
		if kids { // what was found inside it, for its pane
			e.Summary = summarise(counts)
		}
		if kind == MetaOnly {
			e.Summary = l.meta
		}
		leaves = append(leaves, e)
	}
	sort.Strings(dirNames)
	var out []Entry
	if up {
		out = append(out, Entry{Name: "..", Kind: Up, SizeA: -1, SizeB: -1})
	}
	for _, name := range dirNames {
		a := dirs[name]
		out = append(out, Entry{Name: name, Kind: Dir, Path: f.dir + name, HasKids: true, Pending: a.pending, Summary: summarise(a.counts), SizeA: -1, SizeB: -1})
	}
	return append(out, leaves...)
}

var kindWords = []struct {
	kind Kind
	word string
}{{Changed, "changed"}, {Added, "added"}, {Removed, "removed"}, {Renamed, "renamed"}, {RenamedChanged, "renamed and changed"}, {Same, "unchanged"}, {MetaOnly, "metadata-only"}}

// summarise reads counts of lines by kind as "3 changed, 1 added".
func summarise(counts map[Kind]int) string {
	var parts []string
	for _, w := range kindWords {
		if n := counts[w.kind]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, w.word))
		}
	}
	return strings.Join(parts, ", ")
}

// ErrNoSuchEntry is the answer for a name a level does not have.
var ErrNoSuchEntry = errors.New("no such entry")

// ErrNothingInside is Open's answer for an entry with nowhere to go.
var ErrNothingInside = errors.New("nothing inside it differs")

// Open is the level inside an entry: a directory (the same lines, narrowed), a
// container with differences inside, or two containers with none, whose members
// are listed by comparing them now, in the background (the level fills in; see
// Level.Busy). An entry with nothing inside gives ErrNothingInside.
func (r *Run) Open(cur *Level, e Entry) (*Level, error) {
	if !e.HasKids && !e.ContainerPair() {
		return nil, ErrNothingInside
	}
	switch {
	case !e.HasKids: // two containers with nothing differing inside: list their members
		return r.membersLevel(e), nil
	case e.src == nil: // a directory made from the paths: the same lines, narrowed
		return &Level{title: strings.TrimSuffix(e.Name, "/"), source: cur.source, strip: cur.strip, dir: cur.dir + e.Name}, nil
	}
	l := e.src
	return &Level{title: path.Base(strings.TrimSuffix(e.Name, "/")), strip: l.path,
		source: func(*treeDiffTally) []*diffLine { return lineKids(l) }}, nil
}

// membersLevel is the level for two containers whose comparison found nothing
// different inside: their members, all unchanged, listed by comparing them now.
// It runs in the background and the level fills in as it goes. (Their digests
// were taken, or stated, when they were first compared, so it is mostly lookups.)
//
// When the pair is one the first pass stopped at (the depth ran out before its
// members were looked at), this is the comparison Expand would make, so it is
// recorded on the pair's line: going back out must say the members were compared,
// the run's counts must take them in, and nothing compares them a second time.
func (r *Run) membersLevel(e Entry) *Level {
	a, b := e.a, e.b
	t := &treeDiffTally{depth: 1, verbose: true, claimsA: subClaims(a, ""), claimsB: subClaims(b, "")}
	l := e.src
	if l != nil {
		t.base = l.base + l.path + "/"
	}
	record := l != nil && l.a != nil && l.b != nil && (l.kind == '~' || l.kind == '≈') && r.claimWith(l, t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := diffNodes(a, b, "", "", 1, true, t); err != nil {
			t.out("  (%v)", err)
			if record {
				live(func() { l.subT = nil }) // not compared after all: free to be tried again
			}
			return
		}
		t.pairRenames()
		if record {
			r.finishLine(l, t)
		}
	}()
	return &Level{
		title:  path.Base(strings.TrimSuffix(e.Name, "/")),
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

// ---- what an entry is ----

// ContainerPair says whether the entry is two containers, which are compared by
// their members: reading their raw bytes would show nothing of use. It never
// reads: a node whose head has not been read yet is not a container here, and
// NeedsProbe says so.
func (e Entry) ContainerPair() bool {
	if e.a == nil || e.b == nil {
		return false
	}
	ca, _ := e.a.IsContainerCached()
	cb, _ := e.b.IsContainerCached()
	return ca && cb
}

// NeedsProbe says whether telling if the entry is a container would read.
func (e Entry) NeedsProbe() bool {
	for _, n := range []*carve.Node{e.a, e.b} {
		if n != nil {
			if _, known := n.IsContainerCached(); !known {
				return true
			}
		}
	}
	return false
}

// Probe reads the heads of the entry's sides, so ContainerPair is then known.
func (e Entry) Probe() {
	isContainerNode(e.a)
	isContainerNode(e.b)
}

func isContainerNode(n *carve.Node) bool { return n != nil && n.IsContainer() }

// Title is the entry's kind in words, for a pane's title. A renamed container was
// found identical by comparing its members, not its bytes, which may differ (a
// tar's headers carry times), so "content identical" would be too much.
func (e Entry) Title() string {
	if e.Kind == Renamed && isContainerNode(e.a) {
		return "renamed, nothing inside it differs"
	}
	return e.Kind.Label()
}

// HeaderFormat says whether the entry is a pair of containers that keep a record
// per member which can be compared: a pair of tars, or of zips.
func (e Entry) HeaderFormat() bool {
	if e.a == nil || e.b == nil {
		return false
	}
	ka, kb := filetype.Detect(e.a.Head()), filetype.Detect(e.b.Head())
	return ka == kb && (ka == filetype.Tar || ka == filetype.Zip)
}

// Headers is how the member records of a pair of tars or zips compare.
type Headers struct {
	Err    string     `json:"err,omitempty"`
	Report MetaReport `json:"report"`
}

// ReadHeaders reads the headers of a pair of tars (or the directories of two
// zips): a read per member, not the members.
func (e Entry) ReadHeaders() *Headers { return readHeaders(e.a, e.b) }

func readHeaders(a, b *carve.Node) *Headers {
	read := func(n *carve.Node) ([]MetaEntry, error) {
		ra, err := n.ReaderAt()
		if err != nil {
			return nil, err
		}
		if filetype.Detect(n.Head()) == filetype.Zip {
			return ZipMeta(ra, n.Size)
		}
		return TarMeta(ra, n.Size)
	}
	ea, errA := read(a)
	eb, errB := read(b)
	if err := errors.Join(errA, errB); err != nil {
		return &Headers{Err: err.Error()}
	}
	return &Headers{Report: CompareMeta(ea, eb)}
}

// ---- reading an entry ----

// Pair is the bytes of the two sides of an entry, as far as they were read: the
// start of each, to a limit.
type Pair struct {
	a, b           []byte
	SizeA, SizeB   int64 // whole sizes; -1 for a side with no file
	TruncA, TruncB bool  // more of the file than was read
	Limit          int64
	Err            error
}

func readHead(n *carve.Node, limit int64, progress func(int64)) (data []byte, size int64, trunc bool, err error) {
	if n == nil || n.IsDirNode() {
		return nil, -1, false, nil
	}
	r, err := n.Reader()
	if err != nil {
		return nil, n.Size, false, err
	}
	defer r.Close()
	var src io.Reader = r
	if progress != nil {
		src = progressReader{r, progress}
	}
	data, err = io.ReadAll(io.LimitReader(src, limit+1))
	if int64(len(data)) > limit {
		data, trunc = data[:limit], true
	}
	return data, n.Size, trunc, err
}

// Load reads the first limit bytes of each side of an entry. It blocks on the
// read; call it off the viewer's goroutine.
func Load(e Entry, limit int64) *Pair { return LoadProgress(e, limit, nil) }

// LoadProgress is Load, calling progress with the bytes of each chunk as it is
// read, from the reading goroutine.
func LoadProgress(e Entry, limit int64, progress func(n int64)) *Pair {
	p := &Pair{Limit: limit}
	var errA, errB error
	p.a, p.SizeA, p.TruncA, errA = readHead(e.a, limit, progress)
	p.b, p.SizeB, p.TruncB, errB = readHead(e.b, limit, progress)
	if errA != nil {
		p.Err = errA
	} else {
		p.Err = errB
	}
	return p
}

// NewPair is a Pair from bytes in hand, for a caller with no Run.
func NewPair(a, b []byte) *Pair {
	return &Pair{a: a, b: b, SizeA: int64(len(a)), SizeB: int64(len(b)), Limit: int64(max(len(a), len(b)))}
}

// Bytes are the sides as read.
func (p *Pair) Bytes() (a, b []byte) { return p.a, p.b }

// OneSide is a file present on one side only: its start if it is text, else the
// strings in it.
type OneSide struct {
	Side    string   `json:"side"` // "A" or "B"
	Text    bool     `json:"text"`
	Lines   []string `json:"lines,omitempty"`
	Strings []string `json:"strings,omitempty"`
	More    bool     `json:"more"` // cut off at MaxOneSide
}

// MaxOneSide bounds the lines or strings listed for a file on one side.
const MaxOneSide = 200

// EntryDetail is what to show for an entry, as data.
type EntryDetail struct {
	Title     string   `json:"title"`
	Entry     Entry    `json:"entry"`
	A         Side     `json:"a"`
	B         Side     `json:"b"`
	Err       string   `json:"err,omitempty"` // reading failed
	Identical bool     `json:"identical"`     // the sides are known to be the same content
	Container bool     `json:"container"`     // two containers: Bytes is their overlap only
	OneSide   *OneSide `json:"oneSide,omitempty"`
	Bytes     *Detail  `json:"bytes,omitempty"`
}

// Detail analyses what was read for an entry. Pure.
func (p *Pair) Detail(e Entry, opts Options) *EntryDetail {
	o := opts
	if o.View == "" {
		o.View = ViewAuto
	}
	d := &EntryDetail{Title: e.Title(), Entry: e}
	d.A = Side{p.SizeA, len(p.a), p.TruncA}
	d.B = Side{p.SizeB, len(p.b), p.TruncB}
	if p.Err != nil {
		d.Err = p.Err.Error()
		return d
	}
	switch {
	case e.Kind == Same || (e.Kind == Renamed && e.a != nil && e.b != nil && !isContainerNode(e.a) && o.View == ViewAuto):
		d.Identical = true
		return d
	case e.a == nil || e.b == nil:
		d.OneSide = oneSide(e, p, opts.withDefaults().StringsMin)
		return d
	}
	cont := isContainerNode(e.a) && isContainerNode(e.b)
	d.Container = cont
	if cont && o.View == ViewAuto {
		o.View = ViewOverlap // a container's members are listed beside it; its bytes only overlap
	}
	d.Bytes = Analyse(p.a, p.b, p.SizeA, p.SizeB, o)
	if isContainerNode(e.a) {
		d.Bytes.Verdict = nil
	}
	return d
}

func oneSide(e Entry, p *Pair, min int) *OneSide {
	data, side := p.a, "A"
	if e.a == nil {
		data, side = p.b, "B"
	}
	o := &OneSide{Side: side, Text: IsText(data)}
	if o.Text {
		for i, ln := range strings.SplitAfter(string(data), "\n") {
			if i >= MaxOneSide {
				o.More = true
				break
			}
			if ln == "" {
				continue
			}
			o.Lines = append(o.Lines, strings.TrimRight(ln, "\r\n"))
		}
		return o
	}
	for i, s := range Strings(data, min) {
		if i >= MaxOneSide {
			o.More = true
			break
		}
		o.Strings = append(o.Strings, s)
	}
	return o
}

// ---- for tests and embedders with no inputs ----

// FakeLine is one entry of a Run made by NewFakeRun.
type FakeLine struct {
	Kind    Kind
	Path    string
	Pending bool       // its inside is still being compared
	Kids    []FakeLine // found inside it so far
}

// NewFakeRun is a run holding the given lines, finished or not, with no files
// behind them: for testing a front end against a comparison in any state.
func NewFakeRun(lines []FakeLine, finished bool) *Run {
	var build func([]FakeLine) []*diffLine
	build = func(fs []FakeLine) []*diffLine {
		var out []*diffLine
		for _, f := range fs {
			l := &diffLine{kind: rune(f.Kind), path: f.Path}
			switch {
			case f.Pending:
				l.subT = &treeDiffTally{lines: build(f.Kids)}
			case len(f.Kids) > 0:
				l.sub = build(f.Kids)
			}
			out = append(out, l)
		}
		return out
	}
	r := newRun()
	r.setRoot(&treeDiffTally{lines: build(lines)})
	if finished {
		close(r.done)
	}
	return r
}

// FakeFinish finishes a run made by NewFakeRun, as the comparison would: what was
// in progress is complete. With add, more lines have been found first.
func (r *Run) FakeFinish(add ...FakeLine) {
	root, _, _ := r.get()
	live(func() {
		for _, l := range root.lines {
			if l.subT != nil {
				l.sub, l.subT = l.subT.lines, nil
			}
		}
		for _, f := range add {
			root.lines = append(root.lines, &diffLine{kind: rune(f.Kind), path: f.Path})
		}
	})
	close(r.done)
}

func apply(cfg Config) {
	diffTrust = !cfg.Verify
	diffMatch = cfg.Match
	switch {
	case cfg.FetchAhead > 0:
		prefetchBudget = cfg.FetchAhead
	case cfg.FetchAhead < 0:
		prefetchBudget = 0
	}
}

// Print compares the inputs as containers and prints the report, as the diff
// command does. ok is false when either input is not a container.
func Print(cfg Config) (ok bool, err error) {
	apply(cfg)
	return diffContainers(cfg.A, cfg.B, cfg.Depth, cfg.Verbose)
}

// StartProfile has the next comparisons report where their time went.
func StartProfile() { startDiffProfile() }

// DefaultFetchAhead is the bytes of ssh:// data fetched ahead when Config.FetchAhead is 0.
const DefaultFetchAhead = 512 << 20

// PairEntry is the entry for one pair of nodes, as an input of Load and Pair.Detail
// when there is no Run: a changed pair called name.
func PairEntry(name string, a, b *carve.Node) Entry {
	return Entry{Name: name, Path: name, Kind: Changed, SizeA: nodeSize(a), SizeB: nodeSize(b), a: a, b: b}
}

// SetStepHook has f called as the comparison reaches each member: a test seam,
// to hold the comparison part-way and look at what it has found.
func SetStepHook(f func(path string)) { diffStep = f }

type progressReader struct {
	r  io.Reader
	fn func(int64)
}

func (p progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.fn(int64(n))
	}
	return n, err
}

// LoadSize is the bytes Load will read of an entry at most: what progress counts
// up to.
func LoadSize(e Entry, limit int64) int64 {
	n := int64(0)
	for _, s := range []int64{e.SizeA, e.SizeB} {
		if s > 0 {
			n += min(s, limit)
		}
	}
	return n
}

// OneSided is the file of an entry present on one side only, as a browse entry, so
// it can be previewed the way browse previews any file: as highlighted text, an
// image, or a download. ok is false for a pair, or an entry with no file.
func (e Entry) OneSided() (be BrowseEntry, ok bool) {
	n := e.a
	if (e.a == nil) == (e.b == nil) {
		return BrowseEntry{}, false
	}
	if n == nil {
		n = e.b
	}
	if n.IsDirNode() {
		return BrowseEntry{}, false
	}
	name := n.Name
	if i := strings.LastIndex(strings.TrimSuffix(name, "/"), "/"); i >= 0 {
		name = name[i+1:]
	}
	head := n.Head()
	return BrowseEntry{Name: name, Size: n.Size, Label: TypeLabel(n.Name, head), Text: LooksLikeText(n.Name, head),
		Image: LooksLikeImage(head), Node: n}, true
}
