// Package web serves a comparison (analysis.Run) to a browser: a JSON API over the
// same calls the terminal viewer makes, and a single-page Alpine.js front end,
// embedded, with nothing fetched from the network.
//
// Mount it anywhere: the page and its API use relative URLs.
//
//	run := analysis.Start(analysis.Config{A: "old.tar", B: "new.tar", Depth: 3})
//	http.Handle("/diff/", http.StripPrefix("/diff", web.Handler(run, web.Options{Title: "old vs new"})))
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

//go:embed static
var assets embed.FS

// Options tunes the handler.
type Options struct {
	Title string
	// Limit is the bytes read of each side of a file to show what differs (default
	// 32 MiB); a request may ask for up to MaxLimit.
	Limit    int64
	MaxLimit int64 // default 256 MiB
}

const (
	defaultLimit = 32 << 20
	maxLimit     = 256 << 20
	cachedPairs  = 4
)

// Handler serves run. It is safe for concurrent requests.
func Handler(run *analysis.Run, opts Options) http.Handler {
	if opts.Limit <= 0 {
		opts.Limit = defaultLimit
	}
	if opts.MaxLimit <= 0 {
		opts.MaxLimit = maxLimit
	}
	s := &server{run: run, opts: opts, loads: map[loadKey]*loadState{}}
	run.Root().SetTitle(opts.Title)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", s.state)
	mux.HandleFunc("/api/level", s.level)
	mux.HandleFunc("/api/entry", s.entry)
	mux.HandleFunc("/api/deepen", s.deepen)
	sub, _ := fs.Sub(assets, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return mux
}

type server struct {
	run  *analysis.Run
	opts Options

	mu    sync.Mutex
	pairs []cachedPair           // the last few files read, newest last
	loads map[loadKey]*loadState // reads in flight
	load  sync.Mutex             // one read at a time: the filesystems underneath are not safe for more
}

type cachedPair struct {
	key   analysis.EntryKey
	limit int64
	pair  *analysis.Pair
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	http.Error(w, err.Error(), code)
}

func (s *server) state(w http.ResponseWriter, r *http.Request) {
	st := struct {
		Title    string `json:"title"`
		Finished bool   `json:"finished"`
		Summary  string `json:"summary"`
		Status   string `json:"status"`
		Depth    int    `json:"depth"`   // container levels compared into
		Working  bool   `json:"working"` // going deeper, after the first pass
		Err      string `json:"err,omitempty"`
	}{Title: s.opts.Title, Finished: s.run.Finished(), Summary: s.run.Summary(), Status: s.run.Status(), Depth: s.run.Depth(), Working: s.run.Working()}
	if st.Finished {
		st.Status = "" // the last thing it was doing
	}
	if err := s.run.Err(); err != nil {
		st.Err = err.Error()
	}
	writeJSON(w, st)
}

func (s *server) resolve(path []string) (*analysis.Level, error) { return s.run.LevelAt(path) }

// level lists a level as it stands: the page polls it while the comparison runs.
func (s *server) level(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query()["p"]
	l, err := s.resolve(path)
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	es := s.run.Entries(l, false)
	if es == nil {
		es = []analysis.Entry{}
	}
	writeJSON(w, struct {
		Title   string           `json:"title"`
		Path    []string         `json:"path"`
		Busy    bool             `json:"busy"`
		Entries []analysis.Entry `json:"entries"`
	}{l.Title(), path, l.Busy(), es})
}

// containerResp is what to show for two containers: what is inside them (the
// level's entries say) and how their own headers compare. Their bytes are read only
// in the overlap view.
type containerResp struct {
	Headers *analysis.Headers `json:"headers,omitempty"`
}

func (s *server) entry(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	loc := analysis.ParseLocation(r.URL.RawQuery) // the page's own location, as it keeps it in its URL
	name := loc.Entry
	if name == "" {
		name = q.Get("name")
	}
	l, err := s.resolve(loc.Path)
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	e, ok := analysis.FindEntry(s.run.Entries(l, false), name)
	if !ok {
		fail(w, http.StatusNotFound, analysis.ErrNoSuchEntry)
		return
	}
	resp := struct {
		Entry     analysis.Entry        `json:"entry"`
		Title     string                `json:"title"`
		Detail    *analysis.EntryDetail `json:"detail,omitempty"`
		Container *containerResp        `json:"container,omitempty"`
		Loading   *loadingResp          `json:"loading,omitempty"`
	}{Entry: e, Title: e.Title()}
	if !e.HasFiles() {
		writeJSON(w, resp)
		return
	}
	view := loc.View
	if view == "" {
		view = analysis.ViewAuto
	}
	s.load.Lock() // what reads the inputs goes one at a time
	e.Probe()
	if view != analysis.ViewOverlap && e.ContainerPair() {
		c := &containerResp{}
		if e.HeaderFormat() {
			c.Headers = e.ReadHeaders()
		}
		s.load.Unlock()
		resp.Container = c
		writeJSON(w, resp)
		return
	}
	s.load.Unlock()
	limit := s.opts.Limit
	if n, err := strconv.ParseInt(q.Get("limit"), 10, 64); err == nil && n > 0 {
		limit = min(n, s.opts.MaxLimit)
	}
	opts := analysis.Options{View: view, Words: !loc.NoWords, HexBudget: 4 << 10}
	if q.Get("more") == "1" {
		opts.HexBudget = 1 << 20
	}
	p, st := s.pair(e, limit)
	if p == nil { // still being read: say how far, and the page asks again
		resp.Loading = &loadingResp{Read: st.read.Load(), Total: st.total}
		writeJSON(w, resp)
		return
	}
	resp.Detail = p.Detail(e, opts)
	writeJSON(w, resp)
}

// loadingResp is how far the read of an entry has got, in bytes of Total.
type loadingResp struct {
	Read  int64 `json:"read"`
	Total int64 `json:"total"`
}

// loadState is a read in flight.
type loadState struct {
	read  atomic.Int64
	total int64
}

type loadKey struct {
	key   analysis.EntryKey
	limit int64
}

// pair is the bytes of an entry if they have been read (kept for the next few
// requests: a page switching views asks again for the same file). Otherwise it
// starts the read, in the background and one at a time with the others, and
// returns its progress; the page asks again until the pair is there.
func (s *server) pair(e analysis.Entry, limit int64) (*analysis.Pair, *loadState) {
	k := e.Key()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.pairs {
		if c.key == k && c.limit == limit {
			return c.pair, nil
		}
	}
	lk := loadKey{k, limit}
	if st, ok := s.loads[lk]; ok {
		return nil, st
	}
	st := &loadState{total: analysis.LoadSize(e, limit)}
	s.loads[lk] = st
	go func() {
		s.load.Lock()
		p := analysis.LoadProgress(e, limit, func(n int64) { st.read.Add(n) })
		s.load.Unlock()
		s.mu.Lock()
		s.pairs = append(s.pairs, cachedPair{k, limit, p})
		if len(s.pairs) > cachedPairs {
			s.pairs = s.pairs[len(s.pairs)-cachedPairs:]
		}
		delete(s.loads, lk)
		s.mu.Unlock()
	}()
	return nil, st
}

// deepen compares one more container level, in the background (POST: it changes
// what the run holds). The page sees it come in as it polls.
func (s *server) deepen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	n, err := s.run.Deepen()
	if err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, struct {
		Depth   int `json:"depth"`
		Started int `json:"started"` // container pairs it set out to compare
	}{s.run.Depth(), n})
}
