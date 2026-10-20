package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// diffContainers compares two inputs that are containers (archives, images
// with children, directories) member by member, descending into members that
// are containers on both sides. ok is false when either input is not a
// container, so the caller falls back to the signed-image comparison.
//
// A member gone from one place and new in another with the same bytes is
// reported as a rename (or move), wherever in the tree each sits.
func diffContainers(pathA, pathB string, depth int, verbose bool) (ok bool, err error) {
	a, err := diffRoot(pathA)
	if err != nil {
		return false, nil
	}
	b, err := diffRoot(pathB)
	if err != nil {
		return false, nil
	}
	if !a.IsContainer() || !b.IsContainer() {
		return false, nil
	}
	fmt.Printf("%s vs %s\n", infile.Base(pathA), infile.Base(pathB))
	var t treeDiffTally
	if err := diffNodes(a, b, "", "  ", depth, verbose, &t); err != nil {
		return true, err
	}
	t.pairRenames()
	t.flush()
	fmt.Printf("%d changed, %d added, %d removed", t.changed, t.added, t.removed)
	if t.renamed > 0 {
		fmt.Printf(", %d renamed", t.renamed)
	}
	fmt.Printf(", %d unchanged\n", t.same)
	return true, nil
}

// diffRoot opens an input to compare: a directory (local or ssh://) as a tree
// of its files, anything else through carve.
func diffRoot(p string) (*carve.Node, error) {
	if infile.IsDir(p) {
		return dirNode(p)
	}
	return carveRoot(p)
}

// dirNode is a directory as a carve node, hidden entries left out as in a
// directory recon.
func dirNode(dir string) (*carve.Node, error) {
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
			k, err = carve.Open(full)
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
	path string
	node *carve.Node
	line *diffLine
}

type diffLine struct {
	text string
	drop bool
}

type treeDiffTally struct {
	changed, added, removed, same, renamed int
	lines                                  []*diffLine
	gone, fresh                            []*diffEnt
}

// out queues a line; the report prints once renames are known.
func (t *treeDiffTally) out(format string, args ...any) *diffLine {
	l := &diffLine{text: fmt.Sprintf(format, args...)}
	t.lines = append(t.lines, l)
	return l
}

func (t *treeDiffTally) flush() {
	for _, l := range t.lines {
		if !l.drop {
			fmt.Println(l.text)
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
	used := map[*diffEnt]bool{}
	for _, g := range t.gone {
		for _, f := range bySize[g.node.Size] {
			if g.node.Size < 0 || used[f] {
				continue
			}
			if same, err := sameContent(g.node, f.node); err != nil || !same {
				continue
			}
			used[f] = true
			g.line.text = fmt.Sprintf("  > %s -> %s  %s", g.path, f.path, size(g.node))
			f.line.drop = true
			t.removed--
			t.added--
			t.renamed++
			break
		}
	}
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
	if isNew {
		t.added++
		e.line = t.out("%s+ %-48s %10s", indent, path, size(n))
		t.fresh = append(t.fresh, e)
	} else {
		t.removed++
		e.line = t.out("%s- %-48s %10s", indent, path, size(n))
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

	for _, name := range sorted {
		x, y := byA[name], byB[name]
		path := prefix + name
		switch {
		case y == nil:
			t.addOnly(x, path, indent, false)
		case x == nil:
			t.addOnly(y, path, indent, true)
		default:
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
			same, err := sameContent(x, y)
			if err != nil {
				t.out("%s? %-48s (%v)", indent, path, err)
				continue
			}
			if same {
				t.same++
				if verbose {
					t.out("%s= %-48s %10s", indent, path, size(x))
				}
				continue
			}
			t.changed++
			t.out("%s~ %-48s %10s -> %s", indent, path, size(x), size(y))
			if x.IsContainer() && y.IsContainer() && depth > 1 {
				if err := diffNodes(x, y, path+"/", indent+"    ", depth-1, verbose, t); err != nil {
					t.out("%s    (%v)", indent, err)
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

// sameContent reports whether two members hold the same bytes: sizes first,
// and a hash only when they agree.
func sameContent(a, b *carve.Node) (bool, error) {
	if a.Size >= 0 && b.Size >= 0 && a.Size != b.Size {
		return false, nil
	}
	ha, err := digest(a)
	if err != nil {
		return false, err
	}
	hb, err := digest(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

func digest(n *carve.Node) (string, error) {
	r, err := n.Reader()
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return strings.ToLower(fmt.Sprintf("%x", h.Sum(nil))), nil
}
