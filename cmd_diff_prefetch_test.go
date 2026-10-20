package main

import (
	"sync"
	"testing"
	"time"
)

// fakeTransport swaps in recorders for the fetch and release calls.
func fakeTransport(t *testing.T, budget int64) (warmed, evicted func() []string) {
	var mu sync.Mutex
	var w, e []string
	oldW, oldE, oldB := warm, evict, prefetchBudget
	warm = func(s warmSrc, _ int64) { mu.Lock(); w = append(w, s.path); mu.Unlock() }
	evict = func(s warmSrc) { mu.Lock(); e = append(e, s.path); mu.Unlock() }
	prefetchBudget = budget
	pfMu.Lock()
	pfHeld = 0
	pfMu.Unlock()
	t.Cleanup(func() { warm, evict, prefetchBudget = oldW, oldE, oldB })
	get := func(s *[]string) func() []string {
		return func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), *s...) }
	}
	return get(&w), get(&e)
}

func newPrefetcher(names ...string) *prefetcher {
	p := &prefetcher{index: map[string]int{}}
	for i, n := range names {
		p.index[n] = i
		p.items = append(p.items, pfItem{a: warmSrc{path: n + "1"}, b: warmSrc{path: n + "2"}, warm: 30}) // 60 per item
	}
	return p
}

func settle(t *testing.T, count func() []string, want int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if len(count()) == want {
			time.Sleep(20 * time.Millisecond) // and no further
			if len(count()) == want {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("got %d, want %d: %v", len(count()), want, count())
}

// A prefetcher starts items in order, holds no more than the budget ahead of
// the comparison, and goes further only as the comparison reaches later items.
func TestPrefetcherHonoursBudget(t *testing.T) {
	warmed, evicted := fakeTransport(t, 100)
	p := newPrefetcher("a", "b", "c", "d")
	go p.run()

	settle(t, warmed, 2) // item a only: a+b would be 120 > 100
	p.reached("b")
	settle(t, warmed, 4) // a released; b is current, and b+c would be 120 > 100
	if e := evicted(); len(e) != 2 || e[0] != "a1" {
		t.Errorf("evicted %v, want a's two sides", e)
	}
	p.reached("d") // the comparison skipped c: it is not fetched late
	settle(t, warmed, 6)
	for _, w := range warmed() {
		if w == "c1" || w == "c2" {
			t.Errorf("fetched c after the comparison passed it: %v", warmed())
		}
	}
	p.stop()
}

// The budget is shared: one container's fetching leaves less for another's, but
// each always gets its current item, so neither can starve.
func TestPrefetchersShareOneBudget(t *testing.T) {
	warmed, _ := fakeTransport(t, 100)
	p, q := newPrefetcher("p"), newPrefetcher("q")
	go p.run()
	settle(t, warmed, 2)
	go q.run() // p holds 60 of 100; q's first item is allowed regardless
	settle(t, warmed, 4)
	pfMu.Lock()
	held := pfHeld
	pfMu.Unlock()
	if held != 120 {
		t.Errorf("held %d, want both items counted", held)
	}
	p.stop()
	q.stop()
	pfMu.Lock()
	defer pfMu.Unlock()
	if pfHeld != 0 {
		t.Errorf("held %d after stop, want everything released", pfHeld)
	}
}
