// Package srcdiff compares a vendor's source release against the upstream projects it
// was made from: which projects a release holds, and, for one of them, how its tree
// differs from upstream (files changed, added, declared in the vendor's notices or not).
// It is what `unbrick srcdiff` does, as a library: it returns data and prints nothing.
//
// Comparing reads from an upstream git host (a partial fetch into a cache) and needs the
// git binary, so a program that offers it to others decides who may start one.
package srcdiff

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/gitsrc"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	core "github.com/W-Floyd/go-unbrick/internal/srcdiff"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/srcident"
	"github.com/W-Floyd/go-unbrick/internal/upstreamsrc"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

const (
	// maxRead bounds a file read whole to count its changed lines.
	maxRead = 4 << 20
	// maxCounted is how many modified files get their changed lines counted; each needs
	// the upstream version of the file.
	maxCounted = 400
)

// Candidate is a project a release holds that the catalog knows an upstream for.
type Candidate struct {
	Root     string `json:"root"`    // the project's directory in the release
	Project  string `json:"project"` // the catalog's id for it
	Version  string `json:"version,omitempty"`
	Ref      string `json:"ref,omitempty"` // what to fetch upstream; "" when the release does not say
	Repo     string `json:"repo"`
	Evidence string `json:"evidence"`        // how it was identified
	Heavy    bool   `json:"heavy,omitempty"` // an upstream too big for a routine comparison
	// Nested says Root is a member of the release that is a zip of the project, not a
	// directory in it.
	Nested bool `json:"nested,omitempty"`
}

// Upstream is the value Compare takes for the candidate: the repository, at its ref.
func (c Candidate) Upstream() string {
	if c.Ref == "" {
		return c.Repo
	}
	return c.Repo + "#" + c.Ref
}

func loadCatalog(dir string) *catalog.Catalog {
	if files, _ := filepath.Glob(filepath.Join(dir, "*.yaml")); len(files) > 0 {
		if c, err := catalog.Load(dir); err == nil {
			return c
		}
	}
	c, _ := catalog.Default()
	return c
}

// Identify finds the projects an archive is made of, by the catalog's upstream rules
// (catalogDir "" is the default search). It reads only the version files and notices the
// rules ask for.
func Identify(input, catalogDir string) ([]Candidate, error) {
	found, nested, err := identify(input, catalogDir)
	if err != nil {
		return nil, err
	}
	var out []Candidate
	for _, c := range found {
		out = append(out, Candidate{Root: c.Root, Project: c.Rule.ID, Version: c.Version, Ref: c.Ref,
			Repo: c.Rule.Repo, Evidence: c.Evidence, Heavy: c.Rule.Heavy, Nested: nested[c.Root]})
	}
	return out, nil
}

// identify is Identify as the catalog's candidates, with the roots that are a member of the
// release (a zip holding the project) and not a directory in it.
func identify(input, catalogDir string) ([]srcident.Candidate, map[string]bool, error) {
	entries, closer, err := srcfile.Entries(input)
	if err != nil {
		return nil, nil, err
	}
	if closer == nil {
		return nil, nil, fmt.Errorf("%s is not an archive", infile.Base(input))
	}
	defer closer.Close()
	cat := loadCatalog(catalogDir)
	if cat == nil {
		return nil, nil, errors.New("no catalog of upstream projects was found")
	}
	byName := make(map[string]srcfile.Entry, len(entries))
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		byName[e.Name] = e
		names = append(names, e.Name)
	}
	// A project that is a zip of the release stands as a directory of that name, so the
	// catalog's rules, which are about directory names, see it; what is read from inside
	// it is read from the zip, opened when asked for.
	nested := nestedProjects(entries)
	for pseudo := range nested {
		if _, clash := byName[pseudo+"/"]; !clash {
			names = append(names, pseudo+"/.1", pseudo+"/.2", pseudo+"/.3")
		}
	}
	inner := map[string]*innerZip{}
	defer func() {
		for _, z := range inner {
			if z != nil {
				z.close()
			}
		}
	}()
	read := func(name string) []byte {
		if e, ok := byName[name]; ok {
			if e.Size > 1<<20 {
				return nil
			}
			rc, err := e.Open()
			if err != nil {
				return nil
			}
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			return b
		}
		if pseudo, rest, ok := strings.Cut(name, "/"); ok {
			if e, isNested := nested[pseudo]; isNested {
				z, opened := inner[pseudo]
				if !opened {
					z, _ = openInner(e)
					inner[pseudo] = z
				}
				if z != nil {
					return z.read(rest)
				}
			}
		}
		return nil
	}
	found := srcident.Find(names, read, cat.Upstreams())
	isNested := map[string]bool{}
	for i := range found {
		if e, ok := nested[found[i].Root]; ok {
			found[i].Root = e.Name
			isNested[e.Name] = true
		}
	}
	return found, isNested, nil
}

// FileChange is one file that differs from upstream.
type FileChange struct {
	Path    string `json:"path"`
	EOLOnly bool   `json:"eolOnly,omitempty"` // the same but for line endings
	Counted bool   `json:"counted"`           // Added and Removed are known (a text file, not too many)
	Added   int    `json:"added,omitempty"`
	Removed int    `json:"removed,omitempty"`
	// Declared says a notice in the release names the file as modified; nil when the
	// release has no notice for the tree that can say.
	Declared *bool `json:"declared,omitempty"`
}

// Report is how a tree differs from its upstream.
type Report struct {
	Label        string       `json:"label"`   // the tree's directory in the release
	Repo         string       `json:"repo"`    // upstream, without .git
	Ref          string       `json:"ref"`     // as asked for ("HEAD" when none)
	Commit       string       `json:"commit"`  // what Ref resolved to
	Aligned      string       `json:"aligned"` // where in upstream the tree's root was matched to
	Identical    int          `json:"identical"`
	UpstreamOnly int          `json:"upstreamOnly"` // upstream files the release does not ship
	Modified     []FileChange `json:"modified"`
	VendorOnly   []string     `json:"vendorOnly"` // in the release, not upstream
	// What the release's notices declare. Declared and Undeclared count the modified
	// files (not line-ending-only ones) the notices name and do not.
	DeclaredFiles     int      `json:"declaredFiles"`
	Undeclared        int      `json:"undeclared"`
	DeclaredUnchanged []string `json:"declaredUnchanged,omitempty"` // declared, but unchanged here
	// Imports names the notices that list the whole tree (an initial import): declared and
	// undeclared changes cannot be told apart then, and none is reported.
	Imports []string `json:"imports,omitempty"`
}

// Options tunes a comparison.
type Options struct {
	// UpstreamPath is the directory in upstream the tree corresponds to; "" finds it by
	// matching paths.
	UpstreamPath string
	// CacheDir is where upstream clones are kept; "" is a directory under the user cache.
	CacheDir string
	// AllowLocal lets the upstream be a file:// or ssh:// URL, which reads from this
	// machine or over its credentials: for tests and a caller that trusts who names it.
	// By default only http(s) and git:// URLs are fetched.
	AllowLocal bool
}

// Comparison is a finished comparison, kept open so its changed files can be diffed.
// Close it when done.
type Comparison struct {
	Report *Report

	byRel   map[string]srcfile.Entry
	res     core.Result
	snap    *upstreamsrc.Snapshot
	label   string
	ref     string
	closeIn func()

	mu    sync.Mutex
	names []string // roots registered for the diff
}

// Close lets go of the archive and the roots a diff registered.
func (c *Comparison) Close() {
	c.mu.Lock()
	names := c.names
	c.names = nil
	c.mu.Unlock()
	unregisterRoots(names)
	c.closeIn()
}

// allowed says a URL is one a visitor may have fetched: the network, not a path or a
// local transport.
func allowed(upstream string) (gitsrc.Source, error) {
	src, ok := gitsrc.Parse(upstream)
	if !ok {
		return src, fmt.Errorf("%q is not a git URL", upstream)
	}
	for _, p := range []string{"https://", "http://", "git://"} {
		if strings.HasPrefix(src.URL, p) {
			return src, nil
		}
	}
	return src, fmt.Errorf("%q is not an http(s) or git URL", upstream)
}

// treeFiles lists the files of the tree at root inside input, relative to root.
func treeFiles(input, root string) ([]core.File, map[string]srcfile.Entry, func(), error) {
	if infile.IsDir(input) {
		return nil, nil, nil, errors.New("srcdiff of a directory input is not supported; pass an archive")
	}
	entries, closer, err := srcfile.Entries(input)
	if err != nil {
		return nil, nil, nil, err
	}
	if closer == nil {
		return nil, nil, nil, fmt.Errorf("%s is not an archive", infile.Base(input))
	}
	// A root that is a member zip of the release: the tree is what is inside it.
	if root != "" && strings.HasSuffix(strings.ToLower(root), ".zip") {
		for _, e := range entries {
			if e.Name != root {
				continue
			}
			z, err := openInner(e)
			if err != nil {
				closer.Close()
				return nil, nil, nil, fmt.Errorf("%s: %w", root, err)
			}
			strip := ""
			if w := z.wrapper(); w != "" {
				strip = w + "/"
			}
			files, byRel := listTree(z.entries, strip)
			return files, byRel, func() { z.close(); closer.Close() }, nil
		}
	}
	prefix := ""
	if root != "" && root != "." {
		prefix = root + "/"
	}
	files, byRel := listTree(entries, prefix)
	return files, byRel, func() { closer.Close() }, nil
}

// listTree is the files of entries under prefix, named relative to it.
func listTree(entries []srcfile.Entry, prefix string) ([]core.File, map[string]srcfile.Entry) {
	var files []core.File
	byRel := map[string]srcfile.Entry{}
	for _, e := range entries {
		rel, ok := strings.CutPrefix(e.Name, prefix)
		if !ok || rel == "" || strings.HasSuffix(rel, "/") {
			continue
		}
		e := e
		byRel[rel] = e
		files = append(files, core.File{Path: rel, Size: int64(e.Size), Open: e.Open})
	}
	return files, byRel
}

func readCapped(f core.File) ([]byte, error) {
	if f.Size > maxRead {
		return nil, errors.New("too large")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// declaredPaths is the files the notices that go with the tree at root declare as
// modified. A notice goes with a tree when its name begins with the tree's top
// directory or contains the tree's own directory name, ignoring punctuation.
func declaredPaths(input, root string) (paths, imports []string) {
	norm := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	top, _, _ := strings.Cut(root, "/")
	topN, baseN := norm(top), norm(path.Base(root))
	entries, closer, err := srcfile.Entries(input)
	if err != nil || closer == nil {
		return nil, nil
	}
	defer closer.Close()
	for _, e := range entries {
		if !vendor.IsNoticeName(e.Name) {
			continue
		}
		n := norm(strings.TrimSuffix(e.Name, ".txt"))
		if !(topN != "" && strings.HasPrefix(n, topN)) && !(baseN != "" && strings.Contains(n, baseN)) {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		notice := vendor.ParseNotice(data)
		paths = append(paths, notice.Paths...)
		if notice.Import {
			imports = append(imports, strings.TrimSuffix(e.Name, ".txt"))
		}
	}
	return paths, imports
}

// isDeclared says a changed file is one a notice names: the same path, or one a suffix of
// the other (a notice may name it from a different root).
func isDeclared(p string, declared []string) bool {
	for _, d := range declared {
		if p == d || strings.HasSuffix(p, "/"+d) || strings.HasSuffix(d, "/"+p) {
			return true
		}
	}
	return false
}

// markLineEndings sets EOLOnly on the modified files that differ from upstream only in
// their line endings (an archive built on Windows). It fetches the differing files' blobs
// in one batch; if the server will not send blobs by id it stops there, and the files stay
// reported as modified, which is true.
func markLineEndings(res *core.Result, files []core.File, snap *upstreamsrc.Snapshot) {
	size := make(map[string]int64, len(res.Modified))
	byPath := make(map[string]core.File, len(files))
	for _, f := range files {
		size[f.Path] = f.Size
		byPath[f.Path] = f
	}
	var shas []string
	for _, m := range res.Modified {
		if size[m.Path] <= maxRead {
			shas = append(shas, m.UpstreamSHA)
		}
	}
	if len(shas) == 0 || snap.Prefetch("fetching changed files", shas) != nil {
		return
	}
	lf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	for i := range res.Modified {
		m := &res.Modified[i]
		up, ok := snap.BlobLocal(m.UpstreamSHA)
		if !ok {
			continue
		}
		local, err := readCapped(byPath[m.Path])
		if err != nil {
			continue
		}
		m.EOLOnly = bytes.Equal(lf(local), lf(up))
	}
}

// lineStats counts the lines a text file changed.
func lineStats(e srcfile.Entry, m core.Modified, snap *upstreamsrc.Snapshot) (added, removed int, ok bool) {
	if e.Open == nil {
		return 0, 0, false
	}
	local, err := readCapped(core.File{Size: int64(e.Size), Open: e.Open})
	if err != nil {
		return 0, 0, false
	}
	up, err := snap.Blob(m.UpstreamSHA)
	if err != nil || len(up) > maxRead || !analysis.IsText(local) || !analysis.IsText(up) {
		return 0, 0, false
	}
	_, st, _ := analysis.TextDiff(up, local, 2)
	return st.Added, st.Removed, true
}

func orHead(ref string) string {
	if ref == "" {
		return "HEAD"
	}
	return ref
}

// Compare compares the tree at root inside the archive input with the upstream git
// repository at upstream ("url" or "url#ref": a branch, tag or commit id), by git blob id:
// a file is unchanged when it hashes to what upstream has, so only differing files are
// read from upstream. It can take minutes the first time (the fetch, then reading every
// file of the tree).
func Compare(input, root, upstream string, o Options) (*Comparison, error) {
	var src gitsrc.Source
	var err error
	if o.AllowLocal {
		var ok bool
		if src, ok = gitsrc.Parse(upstream); !ok {
			err = fmt.Errorf("%q is not a git URL", upstream)
		}
	} else {
		src, err = allowed(upstream)
	}
	if err != nil {
		return nil, err
	}
	return compare(input, root, src, o)
}

func compare(input, root string, src gitsrc.Source, o Options) (*Comparison, error) {
	root = strings.Trim(root, "/")
	files, byRel, closeIn, err := treeFiles(input, root)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			closeIn()
		}
	}()
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no files under %q", infile.Base(input), root)
	}
	cache := o.CacheDir
	if cache == "" {
		if cache, err = gitsrc.DefaultCache(); err != nil {
			return nil, err
		}
	}
	label := root
	if label == "" {
		label = infile.Base(input)
	}
	snap, err := upstreamsrc.Open(src.URL, src.Ref, cache, nil)
	if err != nil {
		return nil, err
	}
	prefix := o.UpstreamPath
	if prefix != "" {
		prefix = strings.Trim(prefix, "/") + "/"
	} else {
		paths := make([]string, len(files))
		for i, f := range files {
			paths[i] = f.Path
		}
		prefix = core.Align(paths, snap.Files)
	}
	kept := files[:0]
	for _, f := range files {
		if !snap.Symlinks[prefix+f.Path] {
			kept = append(kept, f)
		}
	}
	files = kept
	res, err := core.Compare(files, snap.Files, prefix, nil)
	if err != nil {
		return nil, err
	}
	markLineEndings(&res, files, snap)
	declared, imports := declaredPaths(input, root)
	// A notice that lists the whole tree (an initial import) declares every file, so what
	// it declares cannot be told from what it changed.
	if len(imports) > 0 {
		declared = nil
	}

	rep := &Report{Label: label, Repo: strings.TrimSuffix(snap.URL, ".git"), Ref: orHead(snap.Ref),
		Commit: snap.Commit, Aligned: prefix, Identical: len(res.Identical), UpstreamOnly: len(res.UpstreamOnly),
		VendorOnly: res.VendorOnly, Imports: imports, DeclaredFiles: len(declared), Modified: []FileChange{}}
	if rep.VendorOnly == nil {
		rep.VendorOnly = []string{}
	}
	for i, m := range res.Modified {
		ch := FileChange{Path: m.Path, EOLOnly: m.EOLOnly}
		if !m.EOLOnly {
			if i < maxCounted {
				ch.Added, ch.Removed, ch.Counted = lineStats(byRel[m.Path], m, snap)
			}
			if len(declared) > 0 {
				d := isDeclared(m.Path, declared)
				ch.Declared = &d
				if !d {
					rep.Undeclared++
				}
			}
		}
		rep.Modified = append(rep.Modified, ch)
	}
	if len(declared) > 0 {
		changed := map[string]bool{}
		for _, m := range res.Modified {
			changed[m.Path] = true
		}
		for _, v := range res.VendorOnly {
			changed[v] = true
		}
		for _, d := range declared {
			found := false
			for p := range changed {
				if isDeclared(p, []string{d}) {
					found = true
					break
				}
			}
			if !found {
				rep.DeclaredUnchanged = append(rep.DeclaredUnchanged, d)
			}
		}
	}
	ok = true
	return &Comparison{Report: rep, byRel: byRel, res: res, snap: snap, label: label, ref: orHead(snap.Ref), closeIn: closeIn}, nil
}

// releaseIndex is the "0068_AVNT5W_" a release puts before a project's name: its index in
// the release and the product, which say nothing about the project.
var releaseIndex = regexp.MustCompile(`^\d{4}_[A-Za-z0-9]+_`)

// dirTree builds nested directory nodes from slash paths, so the diff browses folders and
// not a flat list of long names.
type dirTree struct {
	dirs  map[string]*dirTree
	files []*carve.Node
}

func (t *dirTree) add(p string, leaf func(name string) *carve.Node) {
	cur := t
	parts := strings.Split(p, "/")
	for _, d := range parts[:len(parts)-1] {
		if cur.dirs == nil {
			cur.dirs = map[string]*dirTree{}
		}
		if cur.dirs[d] == nil {
			cur.dirs[d] = &dirTree{}
		}
		cur = cur.dirs[d]
	}
	cur.files = append(cur.files, leaf(parts[len(parts)-1]))
}

func (t *dirTree) node(name string) *carve.Node {
	kids := append([]*carve.Node(nil), t.files...)
	names := make([]string, 0, len(t.dirs))
	for d := range t.dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		kids = append(kids, t.dirs[d].node(d))
	}
	return carve.Dir(name, kids)
}

// Changes is how many files a diff shows, and how many it leaves out.
type Changes struct {
	Shown   int // modified (not only in line endings) and vendor-only files
	EOLOnly int // differing only in line endings, not shown
}

// Diff sets up the interactive diff of what differs from upstream (upstream is the base,
// the release's tree the change) and returns the configuration to start it with
// (analysis.Start). The two sides are virtual inputs held until the comparison is closed.
func (c *Comparison) Diff() (analysis.Config, Changes, error) {
	va, up := &dirTree{}, &dirTree{}
	var ch Changes
	var shas []string
	for _, m := range c.res.Modified {
		if !m.EOLOnly {
			shas = append(shas, m.UpstreamSHA)
		}
	}
	sizes, err := c.snap.Sizes(shas)
	if err != nil {
		return analysis.Config{}, ch, err
	}
	leaf := func(rel string) func(string) *carve.Node {
		e := c.byRel[rel]
		return func(name string) *carve.Node { return carve.FromStream(name, int64(e.Size), e.Open) }
	}
	for _, m := range c.res.Modified {
		if m.EOLOnly {
			ch.EOLOnly++
			continue
		}
		ch.Shown++
		va.add(m.Path, leaf(m.Path))
		sha, snap := m.UpstreamSHA, c.snap
		up.add(m.Path, func(name string) *carve.Node {
			return carve.FromStream(name, sizes[sha], func() (io.ReadCloser, error) {
				b, err := snap.Blob(sha)
				if err != nil {
					return nil, err
				}
				return io.NopCloser(bytes.NewReader(b)), nil
			})
		})
	}
	for _, v := range c.res.VendorOnly {
		ch.Shown++
		va.add(v, leaf(v))
	}
	if ch.Shown == 0 {
		return analysis.Config{}, ch, errors.New("no differences from upstream to show")
	}
	base := releaseIndex.ReplaceAllString(path.Base(c.label), "")
	a, b := "upstream "+c.ref+" ("+base+")", "vendor "+base
	c.mu.Lock()
	// A fresh name each time keeps two diffs of one comparison apart.
	a, b = fmt.Sprintf("%s #%d", a, len(c.names)+1), fmt.Sprintf("%s #%d", b, len(c.names)+1)
	c.names = append(c.names, a, b)
	c.mu.Unlock()
	registerRoots(map[string]*carve.Node{a: up.node("upstream"), b: va.node("vendor")})
	return analysis.Config{A: a, B: b, Depth: 3, FetchAhead: -1, Workers: 2, AutoDeepen: 2}, ch, nil
}

var (
	rootsMu  sync.Mutex
	roots    = map[string]*carve.Node{}
	hookOnce sync.Once
)

// registerRoots has the diff engine open the named inputs as the given nodes.
func registerRoots(m map[string]*carve.Node) {
	hookOnce.Do(func() {
		prev := analysis.OpenRoot
		analysis.OpenRoot = func(input string) (*carve.Node, error) {
			rootsMu.Lock()
			n, ok := roots[input]
			rootsMu.Unlock()
			if ok {
				return n, nil
			}
			return prev(input)
		}
	})
	rootsMu.Lock()
	defer rootsMu.Unlock()
	for k, v := range m {
		roots[k] = v
	}
}

func unregisterRoots(names []string) {
	rootsMu.Lock()
	defer rootsMu.Unlock()
	for _, n := range names {
		delete(roots, n)
	}
}
