package web

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

func write(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mkTar(mtime time.Time, files ...string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i+1 < len(files); i += 2 {
		tw.WriteHeader(&tar.Header{Name: files[i], Mode: 0o644, Size: int64(len(files[i+1])), ModTime: mtime})
		tw.Write([]byte(files[i+1]))
	}
	tw.Close()
	return buf.Bytes()
}

func serve(t *testing.T) *httptest.Server {
	t.Helper()
	a, b := t.TempDir(), t.TempDir()
	bin := bytes.Repeat([]byte{0, 1, 2, 3}, 500)
	bin2 := append([]byte(nil), bin...)
	bin2[40], bin2[41] = 0xde, 0xad
	write(t, a, "notes.txt", []byte("let total = price * 3;\nsame\n"))
	write(t, b, "notes.txt", []byte("let total = cost * 3;\nsame\n"))
	write(t, a, "blob.bin", bin)
	write(t, b, "blob.bin", bin2)
	write(t, a, "sub/only.txt", []byte("gone\n"))
	write(t, a, "pkg_v1.tar", mkTar(time.Unix(1_700_000_000, 0), "x", "same", "y", "same"))
	write(t, b, "pkg_v2.tar", mkTar(time.Unix(1_800_000_000, 0), "x", "same", "y", "same"))
	run := analysis.Start(analysis.Config{A: a, B: b, Depth: 3})
	<-run.Done()
	srv := httptest.NewServer(Handler(run, Options{Title: "a vs b"}))
	t.Cleanup(srv.Close)
	return srv
}

func getJSON(t *testing.T, srv *httptest.Server, path string, into any) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("%s: %s", path, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestServesThePageAndItsScripts(t *testing.T) {
	srv := serve(t)
	for path, want := range map[string]string{"/": "x-data=\"app()\"", "/app.js": "function app()", "/style.css": "--add", "/alpine.min.js": "Alpine"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(buf.String(), want) {
			t.Errorf("%s: %s, lacks %q", path, resp.Status, want)
		}
	}
}

type entryJSON struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	HasKids bool   `json:"hasKids"`
	Summary string `json:"summary"`
}

func TestStateAndLevel(t *testing.T) {
	srv := serve(t)
	var st struct {
		Title    string `json:"title"`
		Finished bool   `json:"finished"`
		Summary  string `json:"summary"`
	}
	getJSON(t, srv, "/api/state", &st)
	if st.Title != "a vs b" || !st.Finished || !strings.Contains(st.Summary, "changed") {
		t.Errorf("state: %+v", st)
	}
	var lv struct {
		Title   string      `json:"title"`
		Entries []entryJSON `json:"entries"`
	}
	getJSON(t, srv, "/api/level", &lv)
	var names []string
	for _, e := range lv.Entries {
		names = append(names, e.Name+":"+e.Kind)
	}
	if got := strings.Join(names, " "); got != "sub/:dir blob.bin:changed notes.txt:changed pkg_v1.tar -> pkg_v2.tar:renamed" {
		t.Errorf("root level: %s", got)
	}
	getJSON(t, srv, "/api/level?"+url.Values{"p": {"sub/"}}.Encode(), &lv)
	if len(lv.Entries) != 1 || lv.Entries[0].Name != "only.txt" || lv.Entries[0].Kind != "removed" {
		t.Errorf("sub/: %+v", lv.Entries)
	}
	if resp, _ := http.Get(srv.URL + "/api/level?p=nope/"); resp.StatusCode != 404 {
		t.Errorf("a level that does not exist: %s", resp.Status)
	}
}

func entry(t *testing.T, srv *httptest.Server, name, view string, extra url.Values) map[string]any {
	t.Helper()
	q := url.Values{"name": {name}, "view": {view}}
	for k, v := range extra {
		q[k] = v
	}
	var out map[string]any
	for i := 0; i < 100; i++ { // a file is read in the background: ask again until it is
		out = nil
		getJSON(t, srv, "/api/entry?"+q.Encode(), &out)
		if out["loading"] == nil {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("still loading: %v", out)
	return out
}

func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func TestEntryTextDiffMarksWords(t *testing.T) {
	srv := serve(t)
	out := entry(t, srv, "notes.txt", "auto", nil)
	lines, _ := dig(out, "detail", "bytes", "diff", "lines").([]any)
	if len(lines) < 3 {
		t.Fatalf("%v", out)
	}
	raw, _ := json.Marshal(lines)
	if !strings.Contains(string(raw), `"op":"-"`) || !strings.Contains(string(raw), `"mark":true`) || !strings.Contains(string(raw), `"t":"price"`) {
		t.Errorf("lines: %s", raw)
	}
	off := entry(t, srv, "notes.txt", "auto", url.Values{"words": {"0"}})
	if raw, _ := json.Marshal(dig(off, "detail", "bytes", "diff")); strings.Contains(string(raw), `"mark"`) {
		t.Errorf("words marked with words=0: %s", raw)
	}
}

func TestEntryBinaryHasHexAsText(t *testing.T) {
	srv := serve(t)
	out := entry(t, srv, "blob.bin", "auto", nil)
	if dig(out, "detail", "bytes", "overlap", "sizeA") == nil {
		t.Errorf("no overlap: %v", out)
	}
	hunks, _ := dig(out, "detail", "bytes", "hex", "hunks").([]any)
	if len(hunks) != 1 {
		t.Fatalf("hex: %v", dig(out, "detail", "bytes", "hex"))
	}
	if hexStr, _ := dig(hunks[0].(map[string]any), "b", "hex").(string); !strings.Contains(hexStr, "dead") {
		t.Errorf("hunk B bytes: %q", hexStr)
	}
	hv := entry(t, srv, "blob.bin", "hex", nil)
	if dig(hv, "detail", "bytes", "overlap") != nil || dig(hv, "detail", "bytes", "hex", "total") != float64(2) {
		t.Errorf("hex view: %v", dig(hv, "detail", "bytes"))
	}
}

func TestEntryContainerShowsHeadersNotBytes(t *testing.T) {
	srv := serve(t)
	out := entry(t, srv, "pkg_v1.tar -> pkg_v2.tar", "auto", nil)
	if dig(out, "detail") != nil || dig(out, "container", "headers", "report", "byField", "mtime") != float64(2) {
		t.Errorf("container: %v", out)
	}
	if ov := entry(t, srv, "pkg_v1.tar -> pkg_v2.tar", "overlap", nil); dig(ov, "detail", "bytes", "overlap") == nil {
		t.Errorf("the overlap view reads the container's bytes: %v", ov)
	}
}

func TestOneSideAndDirectoryEntries(t *testing.T) {
	srv := serve(t)
	q := url.Values{"p": {"sub/"}}
	out := entry(t, srv, "only.txt", "auto", q)
	// A file on one side only is previewed as browse previews any file.
	if dig(out, "preview", "kind") != "text" || dig(out, "preview", "text") != "gone\n" || dig(out, "detail") != nil {
		t.Errorf("one side: %v", out)
	}
	if d := entry(t, srv, "sub/", "auto", nil); dig(d, "detail") != nil || dig(d, "entry", "kind") != "dir" {
		t.Errorf("a directory: %v", d)
	}
}

// Two containers whose members were never compared (the depth ran out) must not
// read as "nothing inside differs": Compared says which it is.
func TestComparedSaysWhetherTheMembersWereLookedAt(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	write(t, a, "pkg_v1.tar", mkTar(time.Unix(1_700_000_000, 0), "x", "one", "gone", "g"))
	write(t, b, "pkg_v2.tar", mkTar(time.Unix(1_700_000_000, 0), "x", "two", "new", "n"))
	for depth, want := range map[int]bool{1: false, 3: true} {
		run := analysis.Start(analysis.Config{A: a, B: b, Depth: depth})
		<-run.Done()
		es := run.Entries(run.Root(), false)
		if len(es) != 1 {
			t.Fatalf("depth %d: %d entries", depth, len(es))
		}
		e := es[0]
		if e.Kind != analysis.RenamedChanged || e.Compared != want {
			t.Errorf("depth %d: kind %v compared %v, want %v", depth, e.Kind, e.Compared, want)
		}
		if want && e.Summary == "" {
			t.Errorf("depth %d: compared but nothing found inside it", depth)
		}
		if !want && e.Summary != "" {
			t.Errorf("depth %d: not compared but summary %q", depth, e.Summary)
		}
	}
}

// Going deeper while it runs: the pairs the first pass stopped at have their
// members compared, and the run's counts follow.
func TestDeepenComparesWhatTheDepthLeftOut(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	write(t, a, "pkg_v1.tar", mkTar(time.Unix(1_700_000_000, 0), "x", "one", "gone", "g"))
	write(t, b, "pkg_v2.tar", mkTar(time.Unix(1_700_000_000, 0), "x", "two", "new", "n"))
	run := analysis.Start(analysis.Config{A: a, B: b, Depth: 1})
	<-run.Done()
	if run.Depth() != 1 {
		t.Fatalf("depth %d", run.Depth())
	}
	before := run.Summary()
	n, err := run.Deepen()
	if err != nil || n != 1 || run.Depth() != 2 {
		t.Fatalf("deepen: %d pairs, %v, depth %d", n, err, run.Depth())
	}
	var e analysis.Entry
	for i := 0; i < 200; i++ {
		e = run.Entries(run.Root(), false)[0]
		if e.Compared {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !e.Compared || e.Pending || !e.HasKids || !strings.Contains(e.Summary, "changed") {
		t.Fatalf("after deepening: %+v", e)
	}
	if run.Summary() == before {
		t.Errorf("the counts did not follow: %q", run.Summary())
	}
	if n, _ := run.Deepen(); n != 0 {
		t.Errorf("a second deepen found %d more pairs with nothing left", n)
	}
	// Not while the first pass runs.
	if _, err := analysis.NewFakeRun(nil, false).Deepen(); err != analysis.ErrStillRunning {
		t.Errorf("deepen before it finished: %v", err)
	}
}

func mkTarOwned(mtime time.Time, uid int, files ...string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i+1 < len(files); i += 2 {
		tw.WriteHeader(&tar.Header{Name: files[i], Mode: 0o644, Uid: uid, Size: int64(len(files[i+1])), ModTime: mtime})
		tw.Write([]byte(files[i+1]))
	}
	tw.Close()
	return buf.Bytes()
}

// Containers whose members are all the same but whose headers differ are listed
// as metadata-only, with what differs; identical ones are not listed at all.
func TestMetadataOnlyContainers(t *testing.T) {
	t1, t2 := time.Unix(1_700_000_000, 0), time.Unix(1_800_000_000, 0)
	a, b := t.TempDir(), t.TempDir()
	m := []string{"x", "same-x", "y", "same-y", "z", "same-z"}
	write(t, a, "same_but_mtime.tar", mkTarOwned(t1, 0, m...))
	write(t, b, "same_but_mtime.tar", mkTarOwned(t2, 0, m...))
	write(t, a, "mtime_and_uid.tar", mkTarOwned(t1, 0, m...))
	write(t, b, "mtime_and_uid.tar", mkTarOwned(t2, 1000, m...))
	write(t, a, "identical.tar", mkTarOwned(t1, 0, m...))
	write(t, b, "identical.tar", mkTarOwned(t1, 0, m...))
	write(t, a, "really_changed.tar", mkTarOwned(t1, 0, m...))
	write(t, b, "really_changed.tar", mkTarOwned(t1, 0, "x", "same-x", "y", "CHANGED", "z", "same-z"))
	run := analysis.Start(analysis.Config{A: a, B: b, Depth: 3})
	<-run.Done()
	got := map[string]analysis.Entry{}
	for _, e := range run.Entries(run.Root(), false) {
		got[strings.TrimSuffix(e.Name, "/")] = e
	}
	if e := got["same_but_mtime.tar"]; e.Kind != analysis.MetaOnly || e.Summary != "mtime of 3 of 3 members" || !e.Compared {
		t.Errorf("same_but_mtime.tar: %+v", e)
	}
	if e := got["mtime_and_uid.tar"]; e.Kind != analysis.MetaOnly || !strings.Contains(e.Summary, "mtime of 3 of 3") || !strings.Contains(e.Summary, "uid of 3") {
		t.Errorf("mtime_and_uid.tar: %+v", e)
	}
	if _, ok := got["identical.tar"]; ok {
		t.Error("an identical tar is listed")
	}
	if e := got["really_changed.tar"]; e.Kind != analysis.Changed {
		t.Errorf("really_changed.tar: %+v", e)
	}
	if s := run.Summary(); !strings.Contains(s, "2 metadata-only") {
		t.Errorf("summary %q", s)
	}
	if b, _ := json.Marshal(got["same_but_mtime.tar"]); !strings.Contains(string(b), `"kind":"metadata-only"`) {
		t.Errorf("json: %s", b)
	}
}

func TestHandlerControlsForUntrustedCallers(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	write(t, a, "pkg_v1.tar", mkTar(time.Unix(1_700_000_000, 0), "x", "one"))
	write(t, b, "pkg_v2.tar", mkTar(time.Unix(1_700_000_000, 0), "x", "two"))
	run := analysis.Start(analysis.Config{A: a, B: b, Depth: 1})
	<-run.Done()
	post := func(h http.Handler) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/deepen", nil))
		return rec
	}
	if rec := post(Handler(run, Options{AllowDeepen: func(*http.Request) bool { return false }})); rec.Code != http.StatusForbidden {
		t.Errorf("AllowDeepen false: %d", rec.Code)
	}
	if rec := post(Handler(run, Options{MaxDepth: 1})); rec.Code != http.StatusForbidden {
		t.Errorf("MaxDepth reached: %d", rec.Code)
	}
	// The state says whether this caller may, so the page can hide the button.
	var st struct {
		CanDeepen bool   `json:"canDeepen"`
		Err       string `json:"err"`
	}
	rec := httptest.NewRecorder()
	Handler(run, Options{MaxDepth: 1}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	json.NewDecoder(rec.Body).Decode(&st)
	if st.CanDeepen {
		t.Error("the state offers deepening past MaxDepth")
	}
	if rec := post(Handler(run, Options{MaxDepth: 5})); rec.Code != 200 {
		t.Errorf("allowed: %d", rec.Code)
	}
	// Redact applies to the errors the handler sends.
	rec = httptest.NewRecorder()
	h := Handler(run, Options{Redact: func(s string) string { return strings.ReplaceAll(s, a, "<A>") }})
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/level?p=nope%2F", nil))
	if rec.Code != 404 {
		t.Errorf("%d", rec.Code)
	}
}

// A picture on one side only is shown as a picture, and served by the same raw
// route as browse's, under the same download gate.
func TestOneSidedImageAndDownload(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	write(t, b, "new.png", png1x1)
	write(t, a, "keep.txt", []byte("x\n"))
	write(t, b, "keep.txt", []byte("y\n"))
	run := analysis.Start(analysis.Config{A: a, B: b, Depth: 1})
	<-run.Done()
	srv := httptest.NewServer(Handler(run, Options{AllowDownload: func(*http.Request) bool { return false }}))
	defer srv.Close()
	out := entry(t, srv, "new.png", "auto", nil)
	if dig(out, "preview", "kind") != "image" {
		t.Fatalf("%v", out)
	}
	resp, err := http.Get(srv.URL + "/api/raw?name=new.png")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/png" {
		t.Errorf("image: %s %s", resp.Status, resp.Header.Get("Content-Type"))
	}
	if r, _ := http.Get(srv.URL + "/api/raw?name=new.png&download=1"); r.StatusCode != 403 {
		t.Errorf("download gate: %s", r.Status)
	}
	// A pair has no raw form.
	if r, _ := http.Get(srv.URL + "/api/raw?name=keep.txt"); r.StatusCode != 400 {
		t.Errorf("raw of a pair: %s", r.Status)
	}
}
