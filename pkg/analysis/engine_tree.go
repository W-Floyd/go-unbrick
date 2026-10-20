package analysis

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/hashcache"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// diffContainers compares two inputs that are containers (archives, images
// with children, directories) member by member, descending into members that
// are containers on both sides. ok is false when either input is not a
// container, so the caller falls back to the signed-image comparison.
//
// A member gone from one place and new in another with the same bytes is
// reported as a rename (or move), wherever in the tree each sits.
func diffContainers(pathA, pathB string, depth int, verbose bool) (ok bool, err error) {
	t, ok, err := diffTree(pathA, pathB, depth, verbose, func(*treeDiffTally) {
		fmt.Printf("%s vs %s\n", infile.Base(pathA), infile.Base(pathB))
	})
	if !ok || err != nil {
		return ok, err
	}
	t.flush()
	fmt.Printf("%d changed, %d added, %d removed", t.changed, t.added, t.removed)
	if t.renamed > 0 {
		fmt.Printf(", %d renamed", t.renamed)
	}
	if t.similar > 0 {
		fmt.Printf(", %d renamed and changed", t.similar)
	}
	if t.metaOnly > 0 {
		fmt.Printf(", %d metadata-only", t.metaOnly)
	}
	fmt.Printf(", %d unchanged\n", t.same)
	if t.trusted > 0 {
		fmt.Printf("%d member(s) compared by stated hash (vendor manifest, zip directory, OTA manifest); --verify reads them\n", t.trusted)
	}
	return true, nil
}

// diffTree compares two inputs that are containers and returns the result as a
// tree of lines, unprinted. ok is false when either is not a container. opened
// is called once both are open and the comparison is about to begin, with the
// tree the comparison will fill in, for a caller that wants to say what is being
// compared before the wait, or to watch the tree grow (snapshotDiff).
func diffTree(pathA, pathB string, depth int, verbose bool, opened func(*treeDiffTally)) (tally *treeDiffTally, ok bool, err error) {
	dprog.start()
	defer dprog.finish()
	defer dprof.report()
	endList := dprof.phase("listing directories")
	a, err := diffRoot(pathA)
	if err != nil {
		return nil, false, nil
	}
	b, err := diffRoot(pathB)
	endList()
	if err != nil {
		return nil, false, nil
	}
	if !a.IsContainer() || !b.IsContainer() {
		return nil, false, nil
	}
	dprog.clear()
	t := &treeDiffTally{depth: depth, verbose: verbose}
	if opened != nil {
		opened(t)
	}
	if diffTrust {
		dprog.begin("reading manifests", "", 0)
		end := dprof.phase("reading manifests")
		t.claimsA, t.claimsB = manifestClaims(a), manifestClaims(b)
		end()
	}
	dprog.begin("comparing", "files", 0)
	t.pref = startPrefetch(a, b, "", t)
	defer t.pref.stop()
	end := dprof.phase("comparing members")
	err = diffNodes(a, b, "", "  ", depth, verbose, t)
	end()
	if err == nil {
		end = dprof.phase("matching renames")
		t.pairRenames()
		end()
		end = dprof.phase("matching similar")
		t.pairSimilar()
		end()
	}
	dprog.finish()
	if err != nil {
		return nil, true, err
	}
	return t, true, nil
}

// diffRoot opens an input to compare: a directory (local or ssh://) as a tree
// of its files, anything else through carve.
func diffRoot(p string) (*carve.Node, error) {
	if infile.IsDir(p) {
		return dirNode(p)
	}
	return OpenRoot(p)
}

// dirNode is a directory as a carve node, hidden entries left out as in a
// directory recon.
func dirNode(dir string) (*carve.Node, error) {
	dprog.at(dir, false)
	des, err := infile.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var kids []*carve.Node
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".") {
			continue
		}
		full := infile.Join(dir, d.Name())
		var k *carve.Node
		if d.IsDir() {
			k, err = dirNode(full)
		} else {
			// carveRoot, not carve.Open: it registers the vendor and
			// encrypted-member formats and loads --secrets.
			k, err = OpenRoot(full)
		}
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	return carve.Dir(infile.Base(dir), kids), nil
}

// diffEnt is a member present on one side only, kept until every level has
// been compared so a rename can be matched across directories.
type diffEnt struct {
	path   string
	node   *carve.Node
	line   *diffLine
	claims []vendor.FileClaim // stated hashes for its content, trusted ones
	done   bool               // paired as a rename or a similar member
}

type diffLine struct {
	text string
	drop bool
	sub  []*diffLine // what changed inside a similar pair, printed under it
	// subT is the comparison of the inside while it is still running, so a
	// viewer can show what it has found so far; sub replaces it when it is done.
	subT *treeDiffTally
	// compared says the members of a container line were compared, so that no
	// lines inside it means they are the same; without it they were not looked at
	// (the depth ran out).
	compared bool
	// level is how many levels of going deeper (see Run.Deepen) lie between the line and
	// the first pass: 0 for what the first pass found.
	level int
	// meta says, for a kind '≡' line, what differs in the headers: "mtime of 47 of 52 members".
	meta string

	// What the line is about, for a viewer that opens it: its kind ('~' changed,
	// '>' renamed, '≈' renamed and changed, '+' added, '-' removed, '=' same),
	// the path it is known by, and the node on each side (nil on the side it is
	// missing from).
	kind rune
	path string
	a, b *carve.Node
}

// tag records what a line is about. It returns l, to chain from out.
func (l *diffLine) tag(kind rune, path string, a, b *carve.Node) *diffLine {
	live(func() { l.kind, l.path, l.a, l.b = kind, path, a, b })
	return l
}

type treeDiffTally struct {
	changed, added, removed, same, renamed int
	trusted                                int // members settled by a manifest, unread
	similar                                int // renamed and changed
	metaOnly                               int // containers whose members are all the same and whose headers differ
	depth                                  int // container levels left to compare into
	verbose                                bool
	lines                                  []*diffLine
	gone, fresh                            []*diffEnt
	claimsA, claimsB                       claimSet
	pref                                   *prefetcher // fetching ahead of this comparison's members
}

// out queues a line; the report prints once renames are known.
func (t *treeDiffTally) out(format string, args ...any) *diffLine {
	l := &diffLine{text: fmt.Sprintf(format, args...)}
	live(func() { t.lines = append(t.lines, l) })
	return l
}

// diffStep, when set, is called as the comparison reaches each member. A test
// seam: it lets a test hold the comparison part-way and look at the tree.
var diffStep func(path string)

// liveMu orders every change to the tree of lines against a viewer reading it
// while the comparison is still running (snapshotDiff). The comparison is one
// goroutine and reads its own lines freely; what it writes, it writes under
// this, and a reader takes it to read. Held only for the write itself, never
// across I/O.
var liveMu sync.Mutex

func live(f func()) {
	liveMu.Lock()
	f()
	liveMu.Unlock()
}

func (t *treeDiffTally) flush() { printLines(t.lines) }

func printLines(ls []*diffLine) {
	for _, l := range ls {
		if !l.drop {
			fmt.Println(l.text)
			printLines(l.sub)
		}
	}
}

// pairRenames matches each removed member to an added one holding the same
// bytes. Sizes narrow the candidates, so only plausible pairs are hashed.
func (t *treeDiffTally) pairRenames() {
	bySize := map[int64][]*diffEnt{}
	for _, f := range t.fresh {
		if f.node.Size >= 0 {
			bySize[f.node.Size] = append(bySize[f.node.Size], f)
		}
	}
	byClaim := map[string][]*diffEnt{}
	for _, f := range t.fresh {
		for _, c := range f.claims {
			k := c.Algo + ":" + c.Sum
			byClaim[k] = append(byClaim[k], f)
		}
	}
	used := map[*diffEnt]bool{}
	paired := func(g, f *diffEnt) {
		used[f] = true
		g.done, f.done = true, true
		g.line.tag('>', g.path+" -> "+f.path, g.node, f.node)
		live(func() {
			g.line.text = fmt.Sprintf("  > %s -> %s  %s", g.path, f.path, size(g.node))
			f.line.drop = true
		})
		t.removed--
		t.added--
		t.renamed++
	}
	dprog.begin("matching renames", "removed files", len(t.gone))
	for i, g := range t.gone {
		dprog.at(g.path, i > 0)
		matched := false
		// Both sides' stated hashes name the content: no need to read either.
		for _, c := range g.claims {
			for _, f := range byClaim[c.Algo+":"+c.Sum] {
				if !used[f] {
					paired(g, f)
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if matched {
			continue
		}
		for _, f := range bySize[g.node.Size] {
			if g.node.Size < 0 || used[f] {
				continue
			}
			// Containers are matched by what is inside (pairSimilar), not by
			// hashing the whole of each.
			if t.depth > 1 && g.node.IsContainer() && f.node.IsContainer() {
				continue
			}
			if same, err := sameContent(g.node, f.node); err != nil || !same {
				continue
			}
			paired(g, f)
			break
		}
	}
	dprog.at("", len(t.gone) > 0)
}

// addOnly records a member present on one side only. A directory is listed as
// the files in it, so each can be matched to a rename elsewhere.
func (t *treeDiffTally) addOnly(n *carve.Node, path, indent string, isNew bool) {
	if n.IsDirNode() {
		_, kids, _ := n.Children()
		for _, k := range kids {
			t.addOnly(k, path+"/"+k.Name, indent, isNew)
		}
		return
	}
	e := &diffEnt{path: path, node: n}
	claims := t.claimsA
	if isNew {
		claims = t.claimsB
	}
	e.claims = claimsFor(claims, path, n)
	if isNew {
		t.added++
		e.line = t.out("%s+ %-48s %10s", indent, path, size(n)).tag('+', path, nil, n)
		t.fresh = append(t.fresh, e)
	} else {
		t.removed++
		e.line = t.out("%s- %-48s %10s", indent, path, size(n)).tag('-', path, n, nil)
		t.gone = append(t.gone, e)
	}
}

// diffNodes lists how b's children differ from a's: gone, new, or changed (a
// different size, or the same size with different bytes). Unchanged members
// are counted and, with verbose, listed. prefix is the path of a and b from
// the root, so a rename names where a member was and is.
func diffNodes(a, b *carve.Node, prefix, indent string, depth int, verbose bool, t *treeDiffTally) error {
	_, ak, err := a.Children()
	if err != nil {
		return err
	}
	_, bk, err := b.Children()
	if err != nil {
		return err
	}
	byA, byB := map[string]*carve.Node{}, map[string]*carve.Node{}
	names := map[string]bool{}
	// Members carve derives from others (a joined .mdt) would only repeat
	// their sources' changes.
	for _, k := range ak {
		if !strings.HasSuffix(k.Name, ".joined") {
			byA[k.Name], names[k.Name] = k, true
		}
	}
	for _, k := range bk {
		if !strings.HasSuffix(k.Name, ".joined") {
			byB[k.Name], names[k.Name] = k, true
		}
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	dprog.found(len(sorted))
	// Each member is counted done when the next begins, or after the last.
	defer func() { dprog.at("", len(sorted) > 0) }()
	for i, name := range sorted {
		x, y := byA[name], byB[name]
		path := prefix + name
		dprog.at(path, i > 0)
		t.pref.reached(path)
		if diffStep != nil {
			diffStep(path)
		}
		switch {
		case y == nil:
			t.addOnly(x, path, indent, false)
		case x == nil:
			t.addOnly(y, path, indent, true)
		default:
			var err error
			xd, yd := x.IsDirNode(), y.IsDirNode()
			if xd && yd {
				if err := diffNodes(x, y, path+"/", indent, depth, verbose, t); err != nil {
					t.out("%s? %-48s (%v)", indent, path, err)
				}
				continue
			}
			if xd != yd {
				t.addOnly(x, path, indent, false)
				t.addOnly(y, path, indent, true)
				continue
			}
			// Two containers are compared by what is inside, not by hashing
			// the whole of each: a vendor manifest naming both is the one
			// shortcut that reads less than that.
			settled, equal := t.claimState(x, y, path)
			// Settled-equal first: it spares looking at what either one is.
			if !(settled && equal) && depth > 1 && x.IsContainer() && y.IsContainer() {
				end := dprof.member("inside " + path)
				done := t.compareInside(x, y, path, indent, depth, verbose, settled)
				end()
				if done {
					continue
				}
			}
			var same bool
			end := dprof.member("compare " + path)
			same, err = t.compare(x, y, path)
			end()
			if err != nil {
				t.out("%s? %-48s (%v)", indent, path, err)
				continue
			}
			if same {
				t.same++
				if verbose {
					t.out("%s= %-48s %10s", indent, path, size(x)).tag('=', path, x, y)
				}
				continue
			}
			t.changed++
			ln := t.out("%s~ %-48s %10s -> %s", indent, path, size(x), size(y)).tag('~', path, x, y)
			if x.IsContainer() && y.IsContainer() && depth > 1 {
				if err := diffNodes(x, y, path+"/", indent+"    ", depth-1, verbose, t); err != nil {
					t.out("%s    (%v)", indent, err)
				} else {
					live(func() { ln.compared = true })
				}
			}
		}
	}
	return nil
}

func size(n *carve.Node) string {
	if n.Size < 0 {
		return "?"
	}
	return humanBytes(n.Size)
}

// sameContent reports whether two members hold the same bytes, reading as
// little as it can (see sameBytes).
func sameContent(a, b *carve.Node) (bool, error) { return sameBytes(a, b) }

// compare says whether two members at path hold the same bytes, reading as
// little as it can: sizes first; then, if a vendor manifest names either
// side's hash, that digest — both sides' claims need no read at all, and one
// side's means hashing only the other with the manifest's algorithm; else
// SHA-256 of both. Every digest goes through the cache.
func (t *treeDiffTally) compare(x, y *carve.Node, path string) (bool, error) {
	if x.Size >= 0 && y.Size >= 0 && x.Size != y.Size {
		return false, nil
	}
	if !diffTrust {
		return sameContent(x, y)
	}
	lx, ly := claimsFor(t.claimsA, path, x), claimsFor(t.claimsB, path, y)
	for _, c := range lx {
		hashcache.Put(cacheKey(x, c.Algo), x.Size, c.Sum, true)
	}
	for _, c := range ly {
		hashcache.Put(cacheKey(y, c.Algo), y.Size, c.Sum, true)
	}
	// Both sides state a hash in a common algorithm: nothing to read.
	if settled, equal := commonClaims(lx, ly); settled {
		t.trusted++
		return equal, nil
	}
	// One side states one: hash the other with the same algorithm.
	var from []vendor.FileClaim
	for _, cs := range [][]vendor.FileClaim{lx, ly} {
		for _, c := range cs {
			if vendor.HasherFor(c.Algo) != nil {
				from = append(from, c)
			}
		}
	}
	if len(from) == 0 {
		return sameContent(x, y)
	}
	algo := from[0].Algo
	sum := func(n *carve.Node, cs []vendor.FileClaim) (string, error) {
		for _, c := range cs {
			if c.Algo == algo {
				return c.Sum, nil
			}
		}
		return digestAs(n, algo)
	}
	sx, err := sum(x, lx)
	if err != nil {
		return false, err
	}
	sy, err := sum(y, ly)
	if err != nil {
		return false, err
	}
	t.trusted++
	return sx == sy, nil
}

func cacheKey(n *carve.Node, algo string) string {
	if n.ID() == "" {
		return ""
	}
	return n.ID() + "\x00" + algo
}

func digest(n *carve.Node) (string, error) { return digestAs(n, "sha256") }

// digestAs is n's digest under algo (see vendor.HasherFor), from the hash
// cache when this very content was digested on an earlier run, else read and
// recorded. A hash a manifest once claimed counts only while manifests are trusted.
func digestAs(n *carve.Node, algo string) (string, error) {
	key := cacheKey(n, algo)
	if sum, ok := hashcache.Get(key, n.Size, diffTrust); ok {
		return sum, nil
	}
	hash := vendor.HasherFor(algo)
	if hash == nil {
		return "", fmt.Errorf("no hash for %s", algo)
	}
	r, err := n.Reader()
	if err != nil {
		return "", err
	}
	defer r.Close()
	cr := &countReader{r: progReader{r}}
	sum, err := hash(cr)
	if err != nil {
		return "", err
	}
	hashcache.Put(key, cr.n, sum, false)
	return strings.ToLower(sum), nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}
