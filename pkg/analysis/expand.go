package analysis

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Going deeper than the first pass did. The first pass stops at Config.Depth; what
// it stopped at (changed pairs of containers whose members were not looked at) is
// compared later, a pair at a time:
//
//   - on demand: Focus names the entry a front end is looking at, and if it is such
//     a pair, its members are compared at once, ahead of everything else;
//   - in the background: with Config.AutoDeepen, spare workers keep going, nearest
//     the focus first, each path as far as AutoDeepen levels beyond the first pass;
//   - on request: Deepen and Expand.
//
// Depth is per path: each pair found by going deeper is its own candidate for the
// next level, whatever its neighbours' depth.

// ErrStillRunning is the answer to a request to go deeper while the comparison is
// still working through its first pass: wait for Done.
var ErrStillRunning = errors.New("the comparison is still running")

// ErrNotExpandable is the answer for an entry with no containers of unlooked-at
// members: not a pair of containers, or already compared, or being compared.
var ErrNotExpandable = errors.New("nothing to compare inside it")

// Depth is the container levels compared into so far: Config.Depth, and what Deepen
// has added.
func (r *Run) Depth() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.depth
}

// AutoDeepen is how many levels beyond the first pass the background goes on its
// own (Config.AutoDeepen): 0 none, negative without limit.
func (r *Run) AutoDeepen() int { return r.auto }

// candidate is a container pair the first pass, or a deeper one, stopped at, with
// how far it is from the focus.
type candidate struct {
	line *diffLine
	anc  []*diffLine // the lines above it
	dist int
}

// walkPending lists the container pairs nothing has looked inside, each with the
// chain of lines above it. Caller holds liveMu.
func walkPending(ls []*diffLine, anc []*diffLine, visit func(l *diffLine, anc []*diffLine)) {
	for _, l := range ls {
		if l.drop {
			continue
		}
		switch {
		case l.subT != nil: // being compared now
		case len(l.sub) > 0:
			walkPending(l.sub, append(anc[:len(anc):len(anc)], l), visit)
		case !l.compared && l.a != nil && l.b != nil && (l.kind == '~' || l.kind == '≈'):
			visit(l, anc)
		}
	}
}

// pendingLines is every pair not looked inside.
func pendingLines(ls []*diffLine, out *[]*diffLine) {
	walkPending(ls, nil, func(l *diffLine, _ []*diffLine) { *out = append(*out, l) })
}

// Deepen compares one more level: every container pair the comparison stopped at
// has its members compared now, in the background, hung under it as it goes (see
// Entry.Pending). The pairs it finds inside are then the ones to stop at, so asking
// again goes a level deeper again. It returns how many pairs it set out to compare.
// The first pass must have finished.
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
		if r.container(l) {
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
		for _, l := range cands {
			r.run(l, true)
		}
	}()
	return len(cands), nil
}

// container says whether both sides of a line are containers, remembering a no.
func (r *Run) container(l *diffLine) bool {
	r.mu.Lock()
	no := r.notContainer[l]
	r.mu.Unlock()
	if no {
		return false
	}
	if isContainerNode(l.a) && isContainerNode(l.b) {
		return true
	}
	r.mu.Lock()
	if r.notContainer == nil {
		r.notContainer = map[*diffLine]bool{}
	}
	r.notContainer[l] = true
	r.mu.Unlock()
	return false
}

// Expand is Deepen for one entry, at once and ahead of the background.
func (r *Run) Expand(e Entry) error {
	if !r.Finished() {
		return ErrStillRunning
	}
	l := e.src
	if l == nil || l.a == nil || l.b == nil || !r.container(l) {
		return ErrNotExpandable
	}
	if !r.claim(l) {
		return ErrNotExpandable
	}
	go r.run(l, true)
	return nil
}

// claim marks a pair as being compared, if nothing has started on it.
func (r *Run) claim(l *diffLine) bool {
	ok := false
	live(func() {
		if l.subT == nil && len(l.sub) == 0 && !l.compared {
			l.subT = &treeDiffTally{}
			ok = true
		}
	})
	return ok
}

// Focus says which entry a front end is looking at. The background goes on from
// there, and if the entry is a pair of containers nothing has looked inside, its
// members are compared at once, ahead of everything else. Without AutoDeepen it
// only remembers the focus. It reads the head of the entry's sides: call it off a
// front end's own goroutine.
func (r *Run) Focus(e Entry) {
	if e.src == nil {
		return
	}
	r.mu.Lock()
	r.focus = e.src
	r.mu.Unlock()
	if r.auto == 0 || !r.Finished() {
		return
	}
	r.Expand(e) //nolint:errcheck // not being an expandable pair is the usual case
	r.wakeCrawl()
}

func (r *Run) wakeCrawl() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// run expands a pair that was claimed: it takes a worker's place first, foreground
// work ahead of the background's.
func (r *Run) run(l *diffLine, foreground bool) {
	if foreground {
		r.fgWait.Add(1)
		r.sem <- struct{}{}
		r.fgWait.Add(-1)
	}
	defer func() { <-r.sem }()
	r.expandLine(l)
}

// startCrawl has the spare workers go deeper on their own, once the first pass is
// done: Workers-1 of them (at least one), so a front end asking for something finds
// a free place, each taking the pair nearest the focus that is within AutoDeepen
// levels of the first pass.
func (r *Run) startCrawl() {
	n := max(r.workers-1, 1)
	for i := 0; i < n; i++ {
		go func() {
			<-r.done
			for {
				l := r.next()
				if l == nil {
					select {
					case <-r.wake:
					case <-r.closed:
						return
					case <-time.After(2 * time.Second): // something may have been found since
					}
					continue
				}
				r.run(l, false)
			}
		}()
	}
}

// next is the pair nearest the focus that the background may go into, claimed, once
// a worker's place is free and no foreground request is waiting; nil if there is
// none now.
func (r *Run) next() *diffLine {
	if r.fgWait.Load() > 0 || r.isClosed() {
		return nil
	}
	root, _, _ := r.get()
	if root == nil {
		return nil
	}
	r.mu.Lock()
	focus := r.focus
	r.mu.Unlock()
	var cands []candidate
	var focusAnc []*diffLine
	liveMu.Lock()
	walkPending(root.lines, nil, func(l *diffLine, anc []*diffLine) {
		if r.auto > 0 && l.level >= r.auto {
			return
		}
		cands = append(cands, candidate{line: l, anc: anc})
		if l == focus {
			focusAnc = anc
		}
	})
	if focus != nil && focusAnc == nil { // the focus is not itself a candidate: find its chain
		findChain(root.lines, nil, focus, &focusAnc)
	}
	// Distance is the steps between the two through their common ancestor.
	for i := range cands {
		cands[i].dist = chainDist(cands[i].anc, focus != nil, focusAnc)
	}
	liveMu.Unlock()
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].dist < cands[j].dist })
	for _, c := range cands {
		if !r.container(c.line) {
			continue
		}
		select { // a worker's place must be free: the crawl never waits for one
		case r.sem <- struct{}{}:
		default:
			return nil
		}
		if r.claim(c.line) {
			return c.line // the place stays taken: run gives it back when the pair is done
		}
		<-r.sem
	}
	return nil
}

// findChain sets chain to the lines above target. Caller holds liveMu.
func findChain(ls []*diffLine, anc []*diffLine, target *diffLine, chain *[]*diffLine) bool {
	for _, l := range ls {
		if l == target {
			*chain = anc
			return true
		}
		if len(l.sub) > 0 && findChain(l.sub, append(anc[:len(anc):len(anc)], l), target, chain) {
			return true
		}
	}
	return false
}

// chainDist is how many steps from a candidate to the focus through the tree: with
// no focus, the candidate's own depth (shallowest first).
func chainDist(cAnc []*diffLine, hasFocus bool, focusAnc []*diffLine) int {
	if !hasFocus {
		return len(cAnc)
	}
	common := 0
	for common < len(cAnc) && common < len(focusAnc) && cAnc[common] == focusAnc[common] {
		common++
	}
	return len(cAnc) + len(focusAnc) - 2*common
}

// Working says whether any pair is being compared inside right now, after the
// first pass: what Deepen, Expand and the background start.
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

// Close stops the background: no new pair is started. What is running finishes.
func (r *Run) Close() {
	if r.closing.CompareAndSwap(false, true) {
		close(r.closed)
	}
}

func (r *Run) isClosed() bool { return r.closing.Load() }

// expandLine compares the members of a container line's pair, one level, as
// descend does for a similar pair, and folds what it found into the run's counts.
// What it finds inside is one level further from the first pass than the line.
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
		for _, k := range sub.lines {
			k.level = l.level + 1
		}
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
		root.changed, root.added, root.removed, root.renamed+root.similar, root.same) + root.metaNote()
	r.mu.Unlock()
	r.wakeCrawl() // what it found inside may be next
}
