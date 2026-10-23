package infile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// A run of at least splitChunks missing chunks is spread over the mirrors in
// parallel, at most maxParallel at once, each given a share by its speed.
const (
	splitChunks = 16
	maxParallel = 4
)

// withMirrors is u and the mirrors Mirrors names for it, u first.
func withMirrors(u string) []string {
	out := []string{u}
	if Mirrors == nil {
		return out
	}
	seen := map[string]bool{u: true}
	for _, m := range Mirrors(u) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// hostStat is what has been seen of one host's service, kept across runs in
// the cache root so a later run starts from the fastest.
type hostStat struct {
	BytesPerSec float64   `json:"bytes_per_sec"`
	Fails       int       `json:"fails"` // consecutive
	Seen        time.Time `json:"seen"`
}

var hosts struct {
	sync.Mutex
	loaded bool
	m      map[string]*hostStat
}

func hostOf(u string) string {
	if pu, err := url.Parse(u); err == nil {
		return pu.Host
	}
	return u
}

func hostsPath() string {
	root, err := cacheRoot()
	if err != nil {
		return ""
	}
	return filepath.Join(root, "hosts.json")
}

// stat returns a copy of host's record, loading the file once.
func stat(host string) hostStat {
	hosts.Lock()
	defer hosts.Unlock()
	loadHosts()
	if s := hosts.m[host]; s != nil {
		st := *s
		// A failure streak is a recent judgment: a day on, try it again.
		if time.Since(st.Seen) > 24*time.Hour {
			st.Fails = 0
		}
		return st
	}
	return hostStat{}
}

func loadHosts() {
	if hosts.loaded {
		return
	}
	hosts.loaded = true
	hosts.m = map[string]*hostStat{}
	if b, err := os.ReadFile(hostsPath()); err == nil {
		json.Unmarshal(b, &hosts.m)
	}
}

// observe records a transfer of n bytes in d from host, or a failure. A
// throttled transfer replaces the host's speed outright, not into the average.
func observe(host string, n int64, d time.Duration, failed, throttled bool) {
	hosts.Lock()
	defer hosts.Unlock()
	loadHosts()
	s := hosts.m[host]
	if s == nil {
		s = &hostStat{}
		hosts.m[host] = s
	}
	s.Seen = time.Now()
	if failed {
		s.Fails++
	} else {
		s.Fails = 0
	}
	// Under a chunk, a transfer's time is mostly the round trip, not speed.
	if (n >= chunkSize || throttled) && d > 0 {
		bps := float64(n) / d.Seconds()
		if s.BytesPerSec == 0 || throttled {
			s.BytesPerSec = bps
		} else {
			s.BytesPerSec = 0.7*s.BytesPerSec + 0.3*bps
		}
	}
	if p := hostsPath(); p != "" {
		if b, err := json.MarshalIndent(hosts.m, "", "  "); err == nil {
			writeFileAtomic(p, b)
		}
	}
}

// ranked returns r's usable URLs, fastest first: by measured speed, slowed by
// recent failures. One never measured ranks at half the best known, so it is
// still given a share of a split and its speed learned; the URL as given
// leads while nothing is known.
func (r *remote) ranked() []string {
	var urls []string
	r.dropMu.Lock()
	for _, u := range r.urls {
		if !r.dropped[u] {
			urls = append(urls, u)
		}
	}
	r.dropMu.Unlock()
	best := 0.0
	for _, u := range urls {
		best = max(best, stat(hostOf(u)).BytesPerSec)
	}
	score := map[string]float64{}
	for i, u := range urls {
		s := stat(hostOf(u))
		v := s.BytesPerSec
		if v == 0 {
			v = best / 2
			if best == 0 {
				v = float64(len(urls) - i) // the given order
			}
		}
		score[u] = v / float64(1+s.Fails)
	}
	sort.SliceStable(urls, func(i, j int) bool { return score[urls[i]] > score[urls[j]] })
	return urls
}

// fetch fills chunks first..last: shared among the fastest mirrors when the
// run is long, then whatever is still missing from the best one left.
func (r *remote) fetch(first, last int) error {
	if urls := r.ranked(); len(urls) > 1 && last-first+1 >= splitChunks {
		r.fetchParallel(first, last, urls[:min(len(urls), maxParallel)])
	}
	return r.fetchSerial(first, last)
}

// Parallel fetches hand out pieces of about pieceTime at a host's measured
// speed, so each request is long enough that its round trip is small beside
// it; a host not yet measured gets minPiece, which is how its speed is learned.
// A piece still running after hedgeAfter, once there is nothing left to hand
// out, is fetched again by an idle worker, and the copy that finishes first
// wins: one slow mirror cannot hold up a read the others have done.
const (
	pieceTime  = 1500 * time.Millisecond
	minPiece   = 4 // chunks
	maxPiece   = 64
	hedgeAfter = time.Second
)

func pieceChunks(u string) int {
	bps := stat(hostOf(u)).BytesPerSec
	if bps == 0 {
		return minPiece
	}
	return max(minPiece, min(maxPiece, int(bps*pieceTime.Seconds()/chunkSize)))
}

// flight is one piece being fetched; a hedged piece has two.
type flight struct {
	a, b    int
	started time.Time
	cancel  context.CancelFunc
	hedged  bool
}

// fetchParallel fills first..last with a worker per URL, each taking the next
// piece as it finishes one. Best effort: what is left is fetchSerial's.
func (r *remote) fetchParallel(first, last int, urls []string) {
	var mu sync.Mutex
	next := first
	var inflight []*flight
	// claim hands out the next piece, or a stalled one to hedge. done means
	// there is nothing left to do at all.
	claim := func(u string) (f *flight, ctx context.Context, done bool) {
		mu.Lock()
		defer mu.Unlock()
		piece := flight{started: time.Now()}
		if next <= last {
			piece.a, piece.b = next, min(last, next+pieceChunks(u)-1)
			next = piece.b + 1
		} else {
			var stalled *flight
			for _, g := range inflight {
				if !g.hedged && time.Since(g.started) > hedgeAfter {
					stalled = g
					break
				}
			}
			if stalled == nil {
				return nil, nil, len(inflight) == 0
			}
			stalled.hedged = true
			piece.a, piece.b, piece.hedged = stalled.a, stalled.b, true
			logf("hedging bytes %d- of %s on %s", int64(piece.a)*chunkSize, Base(r.url), hostOf(u))
		}
		ctx, piece.cancel = context.WithCancel(context.Background())
		f = &piece
		inflight = append(inflight, f)
		return f, ctx, false
	}
	// finish retires f, and once its piece is whole, every other copy of it.
	finish := func(f *flight) {
		mu.Lock()
		defer mu.Unlock()
		whole := r.firstMissing(f.a, f.b) >= min(int64(f.b+1)*chunkSize, r.size)
		kept := inflight[:0]
		for _, g := range inflight {
			switch {
			case g == f:
				g.cancel()
			case whole && g.a == f.a:
				g.cancel()
				kept = append(kept, g) // its worker retires it
			default:
				kept = append(kept, g)
			}
		}
		inflight = kept
	}
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fails := 0; fails < 2; {
				f, ctx, done := claim(u)
				if done {
					return
				}
				if f == nil {
					time.Sleep(hedgeAfter / 4)
					continue
				}
				start, stop := r.firstMissing(f.a, f.b), min(int64(f.b+1)*chunkSize, r.size)
				if start < stop {
					if err := r.get(ctx, u, start, stop); err != nil && ctx.Err() == nil {
						fails++
					}
				}
				finish(f)
			}
		}()
	}
	wg.Wait()
}

// fetchSerial fills what is missing of first..last from the best URL,
// moving to the next after a failure. A break mid-stream that made progress
// is not counted against the attempts.
func (r *remote) fetchSerial(first, last int) error {
	stop := min(int64(last+1)*chunkSize, r.size)
	var lastErr error
	for attempt := 0; attempt < fetchAttempts*len(r.urls); {
		start := r.firstMissing(first, last)
		if start >= stop {
			return nil
		}
		urls := r.ranked()
		if len(urls) == 0 {
			break
		}
		u := urls[0]
		err := r.get(context.Background(), u, start, stop)
		if errors.Is(err, errFatal) {
			return errors.Unwrap(err)
		}
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", hostOf(u), err)
		}
		if r.firstMissing(first, last) == start {
			attempt++
		}
	}
	if lastErr == nil {
		lastErr = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("fetching %s: %w", r.url, lastErr)
}

// errFatal marks a fetch error no retry can fix.
var errFatal = errors.New("fatal")

type fatal struct{ err error }

func (f fatal) Error() string        { return f.err.Error() }
func (f fatal) Unwrap() error        { return f.err }
func (f fatal) Is(target error) bool { return target == errFatal }

// IdleTimeout is how long a request may go without a byte arriving before
// it is abandoned and retried: a CDN can stall a stream without closing it.
var IdleTimeout = 30 * time.Second

// get makes one range request to u for [start, stop), start chunk-aligned,
// and fills what arrives. A mirror found serving anything but this object is
// dropped; the URL that was probed doing so means the object has changed.
func (r *remote) get(parent context.Context, u string, start, stop int64) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stalled := time.AfterFunc(IdleTimeout, cancel)
	defer stalled.Stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fatal{err}
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, stop-1))
	if v := r.meta.ifRange(); v != "" {
		req.Header.Set("If-Range", v)
	}
	logf("GET %s bytes=%d-%d (%d KiB) from %s", Base(r.url), start, stop-1, (stop-start)>>10, hostOf(u))
	t0 := time.Now()
	resp, err := Client.Do(req)
	if err != nil {
		observe(hostOf(u), 0, 0, true, false)
		return stallErr(ctx, err)
	}
	defer resp.Body.Close()
	total, terr := contentRangeTotal(resp.Header.Get("Content-Range"))
	s, serr := contentRangeStart(resp.Header.Get("Content-Range"))
	switch {
	case resp.StatusCode == http.StatusOK && u == r.url:
		return fatal{fmt.Errorf("%s changed since it was first read; rerun to refetch", r.url)}
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent && (terr != nil || total != r.size):
		r.drop(u)
		return fmt.Errorf("mirror %s does not serve the same object", hostOf(u))
	case resp.StatusCode != http.StatusPartialContent:
		observe(hostOf(u), 0, 0, true, false)
		return fmt.Errorf("%s: %s", hostOf(u), resp.Status)
	case serr != nil || s != start:
		return fatal{fmt.Errorf("%s: unexpected Content-Range %q for offset %d", u, resp.Header.Get("Content-Range"), start)}
	}
	var cr *countReader
	var slow atomic.Bool
	cr = &countReader{r: resp.Body, progress: func() {
		stalled.Reset(IdleTimeout)
		if r.tooSlow(u, cr.n.Load(), time.Since(t0)) && slow.CompareAndSwap(false, true) {
			cancel()
		}
	}}
	err = r.fill(cr, start, stop)
	n, d := cr.n.Load(), time.Since(t0)
	observe(hostOf(u), n, d, err != nil, slow.Load())
	if slow.Load() {
		logf("%s is serving %d KiB/s; trying another mirror", hostOf(u), int64(float64(n)/d.Seconds())>>10)
		return fmt.Errorf("%s: throttled", hostOf(u))
	}
	if err != nil {
		return stallErr(ctx, err)
	}
	return nil
}

// A host trickling below minRate after slowGrace is abandoned for another
// that is unmeasured or faster: a throttling CDN holds a stream open at a
// few KiB/s, which the idle watchdog never sees.
const (
	slowGrace = 3 * time.Second
	minRate   = 128 << 10
)

func (r *remote) tooSlow(u string, n int64, d time.Duration) bool {
	if d < slowGrace || float64(n)/d.Seconds() >= minRate {
		return false
	}
	for _, v := range r.ranked() {
		if v != u && (stat(hostOf(v)).BytesPerSec == 0 || stat(hostOf(v)).BytesPerSec > minRate) {
			return true
		}
	}
	return false
}

func (r *remote) drop(u string) {
	logf("dropping mirror %s for %s: it serves a different object", hostOf(u), Base(r.url))
	r.dropMu.Lock()
	r.dropped[u] = true
	r.dropMu.Unlock()
}

// countReader counts what arrives and reports each read that brings bytes,
// which holds off the stall watchdog.
type countReader struct {
	r        io.Reader
	n        atomic.Int64
	progress func()
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
		c.progress()
	}
	return n, err
}
