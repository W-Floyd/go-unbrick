package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// diffContainers compares two inputs that are containers (archives, images
// with children) member by member, descending into members that are containers
// on both sides. ok is false when either input is not a container, so the
// caller falls back to the signed-image comparison.
func diffContainers(pathA, pathB string, depth int, verbose bool) (ok bool, err error) {
	a, err := carveRoot(pathA)
	if err != nil {
		return false, nil
	}
	b, err := carveRoot(pathB)
	if err != nil {
		return false, nil
	}
	if _, isA := carve.Format(a); !isA {
		return false, nil
	}
	if _, isB := carve.Format(b); !isB {
		return false, nil
	}
	fmt.Printf("%s vs %s\n", filepath.Base(pathA), filepath.Base(pathB))
	var t treeDiffTally
	if err := diffNodes(a, b, "  ", depth, verbose, &t); err != nil {
		return true, err
	}
	fmt.Printf("%d changed, %d added, %d removed, %d unchanged\n", t.changed, t.added, t.removed, t.same)
	return true, nil
}

type treeDiffTally struct{ changed, added, removed, same int }

// diffNodes lists how b's children differ from a's: gone, new, or changed (a
// different size, or the same size with different bytes). Unchanged members
// are counted and, with verbose, listed.
func diffNodes(a, b *carve.Node, indent string, depth int, verbose bool, t *treeDiffTally) error {
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
		switch {
		case y == nil:
			t.removed++
			fmt.Printf("%s- %-48s %10s\n", indent, name, size(x))
		case x == nil:
			t.added++
			fmt.Printf("%s+ %-48s %10s\n", indent, name, size(y))
		default:
			same, err := sameContent(x, y)
			if err != nil {
				fmt.Printf("%s? %-48s (%v)\n", indent, name, err)
				continue
			}
			if same {
				t.same++
				if verbose {
					fmt.Printf("%s= %-48s %10s\n", indent, name, size(x))
				}
				continue
			}
			t.changed++
			fmt.Printf("%s~ %-48s %10s -> %s\n", indent, name, size(x), size(y))
			_, xc := carve.Format(x)
			_, yc := carve.Format(y)
			if xc && yc && depth > 1 {
				if err := diffNodes(x, y, indent+"    ", depth-1, verbose, t); err != nil {
					fmt.Printf("%s    (%v)\n", indent, err)
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
