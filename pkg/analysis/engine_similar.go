package analysis

import (
	"bytes"
	"fmt"
	"path"
	"sort"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// A removed and an added member are paired as "renamed and changed" when they
// are the same kind of thing and look alike. How alike is judged cheaply: a
// container by the overlap of its member names, a plain file by sampled blocks
// of its bytes; both helped by how close the names are.
const (
	simNameMin   = 0.6    // names this alike make a weaker content match enough
	simJaccard   = 0.5    // member-name overlap that matches containers alone
	simJaccardLo = 0.2    // ...and with similar names
	simBlockMin  = 0.25   // sampled blocks equal, enough alone
	simSizeMin   = 0.5    // with similar names, sizes this close
	simBlock     = 4096   // sample size
	simSamples   = 16     // samples per file
	simMaxPairs  = 250000 // candidate pairs worth scoring
)

// nameScore is how much of the longer base name the two share as a common
// prefix and suffix: 1 for equal, near 1 for a changed version number.
func nameScore(a, b string) float64 {
	a, b = path.Base(a), path.Base(b)
	// The extension says what kind of file it is, not whether it is this one.
	if ea, eb := path.Ext(a), path.Ext(b); ea != a && eb != b {
		a, b = a[:len(a)-len(ea)], b[:len(b)-len(eb)]
	}
	n := max(len(a), len(b))
	if n == 0 {
		return 0
	}
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		p++
	}
	s := 0
	for s < len(a)-p && s < len(b)-p && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	return float64(p+s) / float64(n)
}

func childNames(n *carve.Node) map[string]bool {
	_, kids, err := n.Children()
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(kids))
	for _, k := range kids {
		out[k.Name] = true
	}
	return out
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	both := 0
	for k := range a {
		if b[k] {
			both++
		}
	}
	return float64(both) / float64(len(a)+len(b)-both)
}

// blockScore is the fraction of simSamples evenly spaced blocks that are
// byte-identical at the same offset in both; -1 when that cannot be sampled
// (too small, or not readable at random without reading it all).
func blockScore(x, y *carve.Node) float64 {
	m := min(x.Size, y.Size)
	if m < 2*simBlock || !x.RandomAccess() || !y.RandomAccess() {
		return -1
	}
	rx, err := x.ReaderAt()
	if err != nil {
		return -1
	}
	ry, err := y.ReaderAt()
	if err != nil {
		return -1
	}
	bx, by := make([]byte, simBlock), make([]byte, simBlock)
	same := 0
	for i := 0; i < simSamples; i++ {
		off := int64(i) * (m - simBlock) / (simSamples - 1)
		if _, err := rx.ReadAt(bx, off); err != nil {
			return -1
		}
		if _, err := ry.ReadAt(by, off); err != nil {
			return -1
		}
		if bytes.Equal(bx, by) {
			same++
		}
	}
	return float64(same) / simSamples
}

// similarity scores how alike g and f are, and whether that is alike enough.
func similarity(g, f *diffEnt) (score float64, ok bool) {
	xc, yc := g.node.IsContainer(), f.node.IsContainer()
	if xc != yc || g.node.IsDirNode() != f.node.IsDirNode() {
		return 0, false
	}
	if !xc && TypeLabel(g.node.Name, g.node.Head()) != TypeLabel(f.node.Name, f.node.Head()) {
		return 0, false
	}
	ns := nameScore(g.path, f.path)
	if xc {
		j := jaccard(childNames(g.node), childNames(f.node))
		return j + ns/2, j >= simJaccard || (ns >= simNameMin && j >= simJaccardLo)
	}
	sr := 0.0
	if g.node.Size > 0 && f.node.Size > 0 {
		sr = float64(min(g.node.Size, f.node.Size)) / float64(max(g.node.Size, f.node.Size))
	}
	bs := blockScore(g.node, f.node)
	return max(bs, 0) + ns/2 + sr/4, bs >= simBlockMin || (ns >= simNameMin && sr >= simSizeMin)
}

// pairSimilar pairs what pairRenames left: each remaining removed member with
// the added one most like it, best matches first. A pair of containers is then
// compared member by member, so a renamed package that also changed shows what
// changed inside it.
func (t *treeDiffTally) pairSimilar() {
	var gs, fs []*diffEnt
	for _, g := range t.gone {
		if !g.done {
			gs = append(gs, g)
		}
	}
	for _, f := range t.fresh {
		if !f.done {
			fs = append(fs, f)
		}
	}
	if len(gs) == 0 || len(fs) == 0 || len(gs)*len(fs) > simMaxPairs {
		return
	}
	type pair struct {
		g, f  *diffEnt
		score float64
	}
	var pairs []pair
	dprog.begin("matching similar files", "removed files", len(gs))
	for i, g := range gs {
		dprog.at(g.path, i > 0)
		for _, f := range fs {
			if s, ok := similarity(g, f); ok {
				pairs = append(pairs, pair{g, f, s})
			}
		}
	}
	dprog.at("", true)
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].score > pairs[j].score })
	for _, p := range pairs {
		if p.g.done || p.f.done {
			continue
		}
		p.g.done, p.f.done = true, true
		t.removed--
		t.added--
		t.similar++
		p.g.line.tag('≈', p.g.path+" -> "+p.f.path, p.g.node, p.f.node)
		live(func() {
			p.f.line.drop = true
			p.g.line.text = fmt.Sprintf("  ≈ %s -> %s  %s -> %s", p.g.path, p.f.path, size(p.g.node), size(p.f.node))
		})
		if t.depth > 1 && p.g.node.IsContainer() && p.f.node.IsContainer() {
			t.descend(p.g, p.f)
		}
	}
}

// descend compares a similar pair's members, under the pair's own line. A pair
// with nothing different inside is a plain rename after all.
func (t *treeDiffTally) descend(g, f *diffEnt) {
	sub := &treeDiffTally{depth: t.depth - 1, verbose: t.verbose,
		claimsA: subClaims(g.node, ""), claimsB: subClaims(f.node, "")}
	live(func() { g.line.subT = sub }) // visible while it runs
	sub.pref = startPrefetch(g.node, f.node, "", sub)
	err := diffNodes(g.node, f.node, "", "      ", t.depth-1, t.verbose, sub)
	sub.pref.stop()
	if err != nil {
		live(func() {
			g.line.subT = nil
			g.line.sub = []*diffLine{{text: fmt.Sprintf("      (%v)", err)}}
		})
		return
	}
	sub.pairRenames()
	sub.pairSimilar()
	t.merge(sub)
	same := sub.differences() == 0
	if same {
		t.similar--
		t.renamed++
	}
	live(func() {
		g.line.subT, g.line.sub = nil, sub.lines
		if same {
			g.line.text = fmt.Sprintf("  > %s -> %s  %s", g.path, f.path, size(g.node))
			g.line.kind = '>'
		}
	})
}

// differences counts everything a comparison found that is not "unchanged".
func (t *treeDiffTally) differences() int {
	return t.changed + t.added + t.removed + t.renamed + t.similar
}

// merge folds a nested comparison's counts into t.
func (t *treeDiffTally) merge(sub *treeDiffTally) {
	t.changed += sub.changed
	t.added += sub.added
	t.removed += sub.removed
	t.same += sub.same
	t.renamed += sub.renamed
	t.similar += sub.similar
	t.trusted += sub.trusted
}

// claimState says whether stated hashes name x and y with one algorithm, which
// settles whether their bytes differ without opening either, and if so whether
// they are equal.
func (t *treeDiffTally) claimState(x, y *carve.Node, path string) (settled, equal bool) {
	if !diffTrust {
		return false, false
	}
	return commonClaims(claimsFor(t.claimsA, path, x), claimsFor(t.claimsB, path, y))
}

// compareInside compares two containers member by member and reports them as
// unchanged when nothing inside differs, else as changed with the differences
// listed beneath. It returns false, having printed nothing, when either cannot
// be opened, so the caller can fall back to comparing whole bytes.
//
// bytesDiffer says stated hashes already show the containers' bytes differ, so
// members that all match are reported as a change anyway, and explained.
func (t *treeDiffTally) compareInside(x, y *carve.Node, path, indent string, depth int, verbose, bytesDiffer bool) bool {
	if dprof != nil {
		cx, cy := claimsFor(t.claimsA, path, x), claimsFor(t.claimsB, path, y)
		dprof.logf("opening %s (%s vs %s; stated hashes: %s | %s; bytes differ by claim: %v)",
			path, size(x), size(y), algoList(cx), algoList(cy), bytesDiffer)
	}
	sub := &treeDiffTally{depth: depth - 1, verbose: verbose,
		claimsA: subClaims(x, path+"/"), claimsB: subClaims(y, path+"/")}
	// The line exists from the start, reading as under way, with the comparison of
	// the inside hung from it, so a viewer shows what has been found so far. It
	// becomes what the outcome is, or goes, when the inside is done.
	line := t.out("%s… %-48s %10s -> %s  (comparing)", indent, path, size(x), size(y)).tag('~', path, x, y)
	live(func() { line.subT = sub })
	sub.pref = startPrefetch(x, y, path+"/", sub)
	err := diffNodes(x, y, path+"/", indent+"    ", depth-1, verbose, sub)
	sub.pref.stop()
	if err != nil {
		live(func() { line.subT, line.drop = nil, true })
		return false
	}
	sub.pairRenames()
	sub.pairSimilar()
	switch {
	case sub.differences() == 0 && bytesDiffer:
		t.changed++
		t.trusted += sub.trusted
		live(func() {
			line.subT = nil
			line.text = fmt.Sprintf("%s~ %-48s %10s -> %s  (members identical; container bytes differ)", indent, path, size(x), size(y))
		})
	case sub.differences() == 0:
		t.same++
		t.trusted += sub.trusted
		live(func() {
			line.subT = nil
			if verbose {
				line.kind, line.text = '=', fmt.Sprintf("%s= %-48s %10s", indent, path, size(x))
			} else {
				line.drop = true
			}
		})
	default:
		t.changed++
		t.merge(sub)
		live(func() {
			line.subT, line.sub = nil, sub.lines
			line.text = fmt.Sprintf("%s~ %-48s %10s -> %s", indent, path, size(x), size(y))
		})
	}
	return true
}
