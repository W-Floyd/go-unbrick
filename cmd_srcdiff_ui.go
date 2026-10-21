package main

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/srcdiff"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/upstreamsrc"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// releaseIndex is the "0068_AVNT5W_" a release puts before a project's name: its
// index in the release and the product, which say nothing about the project.
var releaseIndex = regexp.MustCompile(`^\d{4}_[A-Za-z0-9]+_`)

// srcdiffTree is one compared project, kept for the interactive diff: the result
// of the comparison, and what is needed to read either side's files.
type srcdiffTree struct {
	label   string
	ref     string
	res     srcdiff.Result
	byRel   map[string]srcfile.Entry
	snap    *upstreamsrc.Snapshot
	prefix  string
	closeIn func()
}

// dirTree builds nested directory nodes from slash paths, so the diff browses
// folders and not a flat list of long names.
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

// deltaRoots are the two sides to compare: for every file that differs from
// upstream, the vendor's and upstream's versions, and for every file only the
// vendor has, the vendor's. Identical files are left out (their blob ids already
// say they match) and so are upstream files the vendor did not ship, which is not
// a change the vendor made. A project is a folder when there are several.
func deltaRoots(trees []*srcdiffTree) (vendor, upstream *carve.Node, changed, identical, eolOnly int, err error) {
	va, up := &dirTree{}, &dirTree{}
	many := len(trees) > 1
	used := map[string]int{}
	for _, t := range trees {
		identical += len(t.res.Identical)
		dir := ""
		if many {
			// The release names a project by its directory ("…/2" for an Android
			// snapshot): the project's own name is more use than the last segment.
			base := path.Base(t.label)
			if len(base) <= 2 {
				base = path.Base(path.Dir(t.label))
			}
			dir = releaseIndex.ReplaceAllString(base, "") + " " + t.ref
			if used[dir]++; used[dir] > 1 {
				dir = fmt.Sprintf("%s #%d", dir, used[dir])
			}
		}
		join := func(p string) string {
			if dir == "" {
				return p
			}
			return dir + "/" + p
		}
		// Upstream blobs for the modified files, fetched together.
		var shas []string
		for _, m := range t.res.Modified {
			if !m.EOLOnly {
				shas = append(shas, m.UpstreamSHA)
			}
		}
		sizes, serr := t.snap.Sizes(shas)
		if serr != nil {
			return nil, nil, 0, 0, 0, serr
		}
		leaf := func(rel string) func(string) *carve.Node {
			e := t.byRel[rel]
			return func(name string) *carve.Node {
				return carve.FromStream(name, int64(e.Size), e.Open)
			}
		}
		for _, m := range t.res.Modified {
			if m.EOLOnly {
				eolOnly++
				continue
			}
			changed++
			va.add(join(m.Path), leaf(m.Path))
			sha := m.UpstreamSHA
			snap := t.snap
			up.add(join(m.Path), func(name string) *carve.Node {
				return carve.FromStream(name, sizes[sha], func() (io.ReadCloser, error) {
					b, err := snap.Blob(sha)
					if err != nil {
						return nil, err
					}
					return io.NopCloser(bytes.NewReader(b)), nil
				})
			})
		}
		for _, v := range t.res.VendorOnly {
			changed++
			va.add(join(v), leaf(v))
		}
	}
	return va.node("vendor"), up.node("upstream"), changed, identical, eolOnly, nil
}

// withVirtualRoots has the diff engine open the named inputs as the given nodes.
func withVirtualRoots(roots map[string]*carve.Node) {
	prev := analysis.OpenRoot
	analysis.OpenRoot = func(input string) (*carve.Node, error) {
		if n, ok := roots[input]; ok {
			return n, nil
		}
		return prev(input)
	}
}

// runSrcdiffUI opens the interactive diff (terminal, or a web page when addr is
// set) on the differences the comparisons found.
func runSrcdiffUI(trees []*srcdiffTree, addr string) error {
	defer func() {
		for _, t := range trees {
			t.closeIn()
		}
	}()
	if len(trees) == 0 {
		fmt.Println("nothing to browse: no project was compared")
		return nil
	}
	vendor, upstream, changed, identical, eolOnly, err := deltaRoots(trees)
	if err != nil {
		return err
	}
	if changed == 0 {
		fmt.Printf("no differences from upstream (%d identical", identical)
		if eolOnly > 0 {
			fmt.Printf(", %d differ only in line endings", eolOnly)
		}
		fmt.Println(")")
		return nil
	}
	note := fmt.Sprintf("%d file(s) differ from upstream; %d identical not shown", changed, identical)
	if eolOnly > 0 {
		note += fmt.Sprintf("; %d differ only in line endings, not shown", eolOnly)
	}
	fmt.Println(note)

	// Upstream is the base and the vendor's tree the change, so what the vendor
	// added reads as added and a patch reads the way a patch does.
	a, b := "upstream", "vendor"
	if len(trees) == 1 {
		a, b = "upstream "+trees[0].ref, "vendor "+path.Base(trees[0].label)
	}
	withVirtualRoots(map[string]*carve.Node{a: upstream, b: vendor})
	cfg := analysis.Config{A: a, B: b, Depth: 3, FetchAhead: -1, Workers: 2, AutoDeepen: 2}
	if addr != "" {
		return runDiffWeb(cfg, addr)
	}
	return runDiffInteractive(cfg)
}
