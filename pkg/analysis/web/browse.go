package web

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"sync"

	"github.com/alecthomas/chroma/v2"
	chtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// ReconFunc reports on one entry in text: what the host knows how to say about a
// file (go-unbrick's recon). It may take long; the handler runs them one at a
// time in the background and the page shows each as it lands.
type ReconFunc func(e analysis.BrowseEntry) (string, error)

// BrowseOptions tunes BrowseHandler.
type BrowseOptions struct {
	Title string
	// PreviewCap is the bytes of a file read to preview it as text (default
	// analysis.PreviewCap, 256 KiB). ImageCap bounds an image served inline (default
	// 32 MiB).
	PreviewCap int64
	ImageCap   int64
	// AllowDownload decides whether a request may fetch an entry's whole content
	// (GET /api/raw?download=1). Nil allows it. Inline images are always capped.
	AllowDownload func(*http.Request) bool
	// Recon, when set, adds a report to the preview of every file, run in the
	// background.
	Recon ReconFunc
	// Redact is applied to the errors the handler sends (see Options.Redact).
	Redact func(string) string
}

// BrowseHandler serves a Browser to a browser: the same levels, previews and
// reports the terminal browser shows, as a JSON API and an embedded Alpine.js
// page. Mount it anywhere; it uses relative URLs.
func BrowseHandler(b *analysis.Browser, opts BrowseOptions) http.Handler {
	if opts.PreviewCap <= 0 {
		opts.PreviewCap = analysis.PreviewCap
	}
	if opts.ImageCap <= 0 {
		opts.ImageCap = 32 << 20
	}
	s := &browseServer{b: b, opts: opts, jobs: map[string]*reconJob{}}
	if opts.Recon != nil {
		s.queue = make(chan *reconJob, 1024)
		go s.worker()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/info", s.info)
	mux.HandleFunc("/api/level", s.level)
	mux.HandleFunc("/api/progress", progressHandler(s.redact))
	mux.HandleFunc("/api/preview", s.preview)
	mux.HandleFunc("/api/raw", s.raw)
	mux.HandleFunc("/chroma.css", chromaCSS)
	sub, _ := fs.Sub(assets, "static")
	files := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			r.URL.Path = "/browse.html"
		}
		files.ServeHTTP(w, r)
	})
	return mux
}

type browseServer struct {
	b    *analysis.Browser
	opts BrowseOptions

	mu    sync.Mutex
	jobs  map[string]*reconJob
	queue chan *reconJob

	filterMu  sync.Mutex
	curFilter string // the match/grep pair currently applied, so an unchanged request skips re-opening
}

type reconJob struct {
	entry analysis.BrowseEntry
	done  bool
	text  string
	err   string
}

func (s *browseServer) fail(w http.ResponseWriter, code int, err error) {
	m := err.Error()
	if s.opts.Redact != nil {
		m = s.opts.Redact(m)
	}
	http.Error(w, m, code)
}

func (s *browseServer) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, struct {
		Title string `json:"title"`
		Recon bool   `json:"recon"`
	}{s.opts.Title, s.opts.Recon != nil})
}

// locate is the level and entry a request names, in analysis.Location's form.
func (s *browseServer) locate(r *http.Request) (*analysis.BrowseLevel, analysis.BrowseEntry, error) {
	loc := analysis.ParseLocation(r.URL.RawQuery)
	if err := s.applyFilters(loc.Match, loc.Grep); err != nil {
		return nil, analysis.BrowseEntry{}, err
	}
	l, err := s.b.LevelAt(loc.Path)
	if err != nil {
		return nil, analysis.BrowseEntry{}, err
	}
	name := loc.Entry
	if name == "" {
		name = r.URL.Query().Get("name")
	}
	if name == "" {
		return l, analysis.BrowseEntry{}, nil
	}
	e, ok := l.Find(name)
	if !ok {
		return l, e, analysis.ErrNoSuchEntry
	}
	return l, e, nil
}

// applyFilters compiles match/grep and, if they differ from what is currently
// applied, updates the browser's filters (analysis.Browser.SetFilters) to match.
// A no-op when both are already current, so navigating within an unchanged
// filter doesn't re-open the input on every request.
func (s *browseServer) applyFilters(match, grep string) error {
	key := match + "\x00" + grep
	s.filterMu.Lock()
	unchanged := key == s.curFilter
	s.filterMu.Unlock()
	if unchanged {
		return nil
	}
	var matchRe, grepRe *regexp.Regexp
	var err error
	if match != "" {
		if matchRe, err = regexp.Compile(match); err != nil {
			return fmt.Errorf("match: %w", err)
		}
	}
	if grep != "" {
		if grepRe, err = regexp.Compile(grep); err != nil {
			return fmt.Errorf("grep: %w", err)
		}
	}
	if err := s.b.SetFilters(matchRe, grepRe, analysis.BrowseDepth); err != nil {
		return err
	}
	s.filterMu.Lock()
	s.curFilter = key
	s.filterMu.Unlock()
	return nil
}

func (s *browseServer) level(w http.ResponseWriter, r *http.Request) {
	l, _, err := s.locate(r)
	if err != nil {
		s.fail(w, http.StatusNotFound, err)
		return
	}
	es := l.Entries
	if es == nil {
		es = []analysis.BrowseEntry{}
	}
	writeJSON(w, struct {
		Title   string                 `json:"title"`
		Entries []analysis.BrowseEntry `json:"entries"`
	}{l.Title, es})
}

func (s *browseServer) preview(w http.ResponseWriter, r *http.Request) {
	_, e, err := s.locate(r)
	if err != nil {
		s.fail(w, http.StatusNotFound, err)
		return
	}
	resp := buildPreview(e, r.URL.Query().Get("raw") == "1", s.opts.PreviewCap, s.redact)
	if !e.Dir && s.opts.Recon != nil {
		resp.Recon = s.recon(e)
	}
	writeJSON(w, resp)
}

func (s *browseServer) redact(m string) string {
	if s.opts.Redact != nil {
		return s.opts.Redact(m)
	}
	return m
}

// recon is the report for an entry: queued on first ask, then answered with its
// state until it lands.
func (s *browseServer) recon(e analysis.BrowseEntry) *reconResp {
	k := e.Key()
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[k]
	if !ok {
		j = &reconJob{entry: e}
		s.jobs[k] = j
		select {
		case s.queue <- j:
		default:
			delete(s.jobs, k) // the queue is full: ask again later
			return &reconResp{State: "running"}
		}
	}
	switch {
	case !j.done:
		return &reconResp{State: "running"}
	case j.err != "":
		return &reconResp{State: "failed", Err: s.redact(j.err), Text: j.text}
	}
	return &reconResp{State: "done", Text: j.text}
}

// worker runs the reports one at a time: recon spools members to disk and the
// disks underneath are not safe for more.
func (s *browseServer) worker() {
	for j := range s.queue {
		text, err := s.opts.Recon(j.entry)
		s.mu.Lock()
		j.text, j.done = text, true
		if err != nil {
			j.err = err.Error()
		}
		s.mu.Unlock()
	}
}

// raw streams an entry: an image inline (capped), or any file as a download if
// the caller may.
func (s *browseServer) raw(w http.ResponseWriter, r *http.Request) {
	_, e, err := s.locate(r)
	if err != nil {
		s.fail(w, http.StatusNotFound, err)
		return
	}
	serveRaw(w, r, e, s.opts.ImageCap, s.opts.AllowDownload, s.fail)
}

// ---- syntax highlighting ----

var htmlFormatter = chtml.New(chtml.WithClasses(true), chtml.PreventSurroundingPre(true))

// highlightHTML is content as HTML, tokens in classes (styled by /chroma.css),
// matched to a lexer by name first and then by the content.
func highlightHTML(name string, content []byte) string {
	lexer := lexers.Match(name)
	if lexer == nil {
		lexer = lexers.Analyse(string(content))
	}
	if lexer == nil {
		lexer = lexers.Fallback
	}
	it, err := chroma.Coalesce(lexer).Tokenise(nil, string(content))
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	if err := htmlFormatter.Format(&buf, styles.Fallback, it); err != nil {
		return ""
	}
	return buf.String()
}

// chromaCSS is the token classes' colours, a light style and a dark one chosen by
// the page's colour scheme.
func chromaCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=3600")
	var light, dark bytes.Buffer
	htmlFormatter.WriteCSS(&light, styles.Get("github"))
	htmlFormatter.WriteCSS(&dark, styles.Get("github-dark"))
	fmt.Fprintf(w, "%s\n@media (prefers-color-scheme: dark) {\n%s\n}\n", light.String(), dark.String())
}
