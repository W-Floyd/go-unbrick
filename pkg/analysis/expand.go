package analysis

import (
	"errors"
	"fmt"
)

// Depth is how many container levels the comparison goes into on its own. It
// starts as Config.Depth and Deepen raises it.

// ErrStillRunning is the answer to a request to go deeper while the comparison is
// still working through its first pass: wait for Done.
var ErrStillRunning = errors.New("the comparison is still running")

// ErrNotExpandable is the answer for an entry with no containers of unlooked-at
// members: not a pair of containers, or already compared, or being compared.
var ErrNotExpandable = errors.New("nothing to compare inside it")

// Depth is the container levels compared into so far.
func (r *Run) Depth() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.depth
}

// pending lists the container pairs the comparison stopped at: changed pairs
// whose members were not looked at because the depth ran out. Caller holds liveMu.
func pendingLines(ls []*diffLine, out *[]*diffLine) {
	for _, l := range ls {
		if l.drop {
			continue
		}
		switch {
		case l.subT != nil: // being compared now
		case len(l.sub) > 0:
			pendingLines(l.sub, out)
		case !l.compared && l.a != nil && l.b != nil && (l.kind == '~' || l.kind == '≈'):
			*out = append(*out, l)
		}
	}
}

// Deepen compares one more level: every container pair the comparison stopped at
// has its members compared now, in the background and one pair at a time, hung
// under it as it goes (see Entry.Pending). The pairs it finds inside are then the
// ones to stop at, so asking again goes a level deeper again. It returns how many
// pairs it set out to compare. The first pass must have finished.
func (r *Run) Deepen() (int, error) {
	if !r.Finished() {
		return 0, ErrStillRunning
	}
	root, _, _ := r.get()
	if root == nil {
		return 0, nil
	}
	var todo []*diffLine
	liveMu.Lock()
	pendingLines(root.lines, &todo)
	liveMu.Unlock()
	var cands []*diffLine
	for _, l := range todo { // is it a container? reads its head, so off the lock
		if isContainerNode(l.a) && isContainerNode(l.b) {
			cands = append(cands, l)
		}
	}
	r.mu.Lock()
	r.depth++
	r.mu.Unlock()
	live(func() {
		for _, l := range cands {
			l.subT = &treeDiffTally{} // marks it in progress at once, before its turn
		}
	})
	go func() {
		r.xmu.Lock()
		defer r.xmu.Unlock()
		for _, l := range cands {
			r.expandLine(l)
		}
	}()
	return len(cands), nil
}

// Expand is Deepen for one entry.
func (r *Run) Expand(e Entry) error {
	if !r.Finished() {
		return ErrStillRunning
	}
	l := e.src
	if l == nil || l.a == nil || l.b == nil || !(isContainerNode(l.a) && isContainerNode(l.b)) {
		return ErrNotExpandable
	}
	ok := false
	live(func() {
		if l.subT == nil && len(l.sub) == 0 && !l.compared {
			l.subT = &treeDiffTally{}
			ok = true
		}
	})
	if !ok {
		return ErrNotExpandable
	}
	go func() {
		r.xmu.Lock()
		defer r.xmu.Unlock()
		r.expandLine(l)
	}()
	return nil
}

// expandLine compares the members of a container line's pair, one level, as
// descend does for a similar pair, and folds what it found into the run's counts.
func (r *Run) expandLine(l *diffLine) {
	sub := &treeDiffTally{depth: 1, claimsA: subClaims(l.a, ""), claimsB: subClaims(l.b, "")}
	live(func() { l.subT = sub }) // visible while it runs
	sub.pref = startPrefetch(l.a, l.b, "", sub)
	err := diffNodes(l.a, l.b, "", "      ", 1, false, sub)
	sub.pref.stop()
	if err != nil {
		live(func() {
			l.subT = nil
			l.sub = []*diffLine{{text: fmt.Sprintf("      (%v)", err)}}
		})
		return
	}
	sub.pairRenames()
	sub.pairSimilar()
	same := sub.differences() == 0
	root, _, _ := r.get()
	live(func() {
		l.subT, l.sub, l.compared = nil, sub.lines, true
		if same && l.kind == '≈' {
			l.kind = '>' // renamed, and nothing inside it differs after all
			root.similar--
			root.renamed++
		}
		root.merge(sub)
	})
	r.mu.Lock()
	r.summary = fmt.Sprintf("%d changed, %d added, %d removed, %d renamed, %d unchanged",
		root.changed, root.added, root.removed, root.renamed+root.similar, root.same)
	r.mu.Unlock()
}

// Working says whether any pair is being compared inside right now, after the
// first pass: what Deepen and Expand start.
func (r *Run) Working() bool {
	root, _, _ := r.get()
	if root == nil {
		return false
	}
	liveMu.Lock()
	defer liveMu.Unlock()
	var walk func([]*diffLine) bool
	walk = func(ls []*diffLine) bool {
		for _, l := range ls {
			if l.drop {
				continue
			}
			if l.subT != nil || walk(l.sub) {
				return true
			}
		}
		return false
	}
	return walk(root.lines)
}
