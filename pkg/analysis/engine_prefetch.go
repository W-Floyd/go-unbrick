package analysis

import (
	"sort"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/hashcache"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// prefetchBudget is how many bytes of upcoming ssh:// data are fetched ahead of
// the comparison, summed over every container being compared, so the network is
// already working on the next members while this one is hashed. 0 turns it off.
var prefetchBudget int64 = DefaultFetchAhead

// warmWindow is how much of a member too big to fetch whole is started early;
// the rest follows as the comparison reads it (read-ahead).
const warmWindow = 16 << 20

// warm and evict are the transport's, replaceable so the scheduling can be
// tested. whole is a whole remote file, otherwise a byte range of one.
var (
	warm = func(w warmSrc, n int64) {
		if w.whole {
			infile.Warm(w.path, n) // and its last block, where an index may sit
		} else {
			infile.WarmRange(w.path, w.off, n)
		}
	}
	evict = func(w warmSrc) {
		if w.whole {
			infile.Evict(w.path)
		} else {
			infile.EvictRange(w.path, w.off, w.length)
		}
	}
)

// warmSrc is where a member's bytes are on the remote side.
type warmSrc struct {
	path        string
	off, length int64
	whole       bool // the entire file at path
}

func sourceOf(n *carve.Node) (warmSrc, bool) {
	path, off, length, ok := n.Source()
	if !ok || !infile.IsSSH(path) || length <= 0 {
		return warmSrc{}, false
	}
	return warmSrc{path: path, off: off, length: length, whole: n.Path() == path}, true
}

// pfMu guards every prefetcher and the budget they share.
var (
	pfMu   sync.Mutex
	pfCond = sync.NewCond(&pfMu)
	pfHeld int64 // bytes warmed and not yet released, across all prefetchers
)

// prefetcher fetches, for one container being compared, the members the
// comparison will have to read, in the order it will read them, as far ahead of
// it as the shared budget allows.
type prefetcher struct {
	items   []pfItem
	index   map[string]int // path -> item
	cursor  int            // items before this are done with
	next    int            // items before this have been started
	stopped bool
}

type pfItem struct {
	a, b warmSrc
	warm int64 // bytes started early, per side
	held bool  // counted in pfHeld
}

func (it *pfItem) cost() int64 { return 2 * it.warm }

// startPrefetch plans the fetches for comparing a with b, whose members the
// comparison names prefix+name: every pair of ssh:// members, equal in size and
// not already settled by a cache or a stated hash, that it will have to read.
// It returns nil when there is nothing to do.
func startPrefetch(a, b *carve.Node, prefix string, t *treeDiffTally) *prefetcher {
	if prefetchBudget <= 0 {
		return nil
	}
	p := &prefetcher{index: map[string]int{}}
	p.plan(a, b, prefix, t)
	if len(p.items) == 0 {
		return nil
	}
	go p.run()
	return p
}

// plan adds a and b's comparable members in the order diffNodes visits them.
func (p *prefetcher) plan(a, b *carve.Node, prefix string, t *treeDiffTally) {
	_, ak, _ := a.Children()
	_, bk, _ := b.Children()
	byA, byB := map[string]*carve.Node{}, map[string]*carve.Node{}
	names := map[string]bool{}
	for _, k := range ak {
		byA[k.Name], names[k.Name] = k, true
	}
	for _, k := range bk {
		byB[k.Name], names[k.Name] = k, true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		x, y := byA[name], byB[name]
		if x == nil || y == nil {
			continue
		}
		path := prefix + name
		if x.IsDirNode() != y.IsDirNode() {
			continue
		}
		if x.IsDirNode() {
			p.plan(x, y, path+"/", t)
			continue
		}
		sx, okx := sourceOf(x)
		sy, oky := sourceOf(y)
		if !okx || !oky || x.Size <= 0 || x.Size != y.Size || p.settled(x, y, path, t) {
			continue
		}
		p.index[path] = len(p.items)
		p.items = append(p.items, pfItem{a: sx, b: sy, warm: min(warmBytes(sx.length), warmBytes(sy.length))})
	}
}

func warmBytes(length int64) int64 {
	if length <= prefetchBudget/4 {
		return length
	}
	return warmWindow
}

// settled reports whether comparing x and y will not read them: both digests
// are cached, or stated hashes name both.
func (p *prefetcher) settled(x, y *carve.Node, path string, t *treeDiffTally) bool {
	if s, _ := t.claimState(x, y, path); s {
		return true
	}
	_, okx := hashcache.Get(cacheKey(x, "sha256"), x.Size, diffTrust)
	_, oky := hashcache.Get(cacheKey(y, "sha256"), y.Size, diffTrust)
	return okx && oky
}

// heldHere is what this prefetcher has warmed and not released. pfMu is held.
func (p *prefetcher) heldHere() int64 {
	var n int64
	for i := range p.items {
		if p.items[i].held {
			n += p.items[i].cost()
		}
	}
	return n
}

// run starts items in order. The item the comparison is at, or a prefetcher
// holding nothing, always goes however big; the rest wait for the comparison to
// release budget.
func (p *prefetcher) run() {
	pfMu.Lock()
	defer pfMu.Unlock()
	for p.next < len(p.items) && !p.stopped {
		p.next = max(p.next, p.cursor) // one the comparison has passed is not worth fetching
		it := &p.items[p.next]
		if p.next > p.cursor && p.heldHere() > 0 && pfHeld+it.cost() > prefetchBudget {
			pfCond.Wait()
			continue
		}
		warm(it.a, it.warm)
		warm(it.b, it.warm)
		it.held = true
		pfHeld += it.cost()
		p.next++
	}
}

// release lets go of items [from, to). pfMu is held.
func (p *prefetcher) release(from, to int) {
	for i := from; i < to; i++ {
		it := &p.items[i]
		if it.held {
			evict(it.a)
			evict(it.b)
			it.held = false
			pfHeld -= it.cost()
		}
	}
}

// reached tells the prefetcher the comparison is now at path: everything
// before it is finished with and released, and the budget that frees goes to
// fetching further ahead, here and in any other container. Nil-safe.
func (p *prefetcher) reached(path string) {
	if p == nil {
		return
	}
	pfMu.Lock()
	defer pfMu.Unlock()
	i, ok := p.index[path]
	if !ok || i <= p.cursor {
		return
	}
	p.release(p.cursor, i)
	p.cursor = i
	pfCond.Broadcast()
}

// stop ends the prefetching and releases everything it holds. Nil-safe.
func (p *prefetcher) stop() {
	if p == nil {
		return
	}
	pfMu.Lock()
	defer pfMu.Unlock()
	p.stopped = true
	p.release(0, len(p.items))
	pfCond.Broadcast()
}
