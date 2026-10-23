package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// A 1x1 PNG.
var png1x1 = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 'I', 'H', 'D', 'R', 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0x0d, 'I', 'D', 'A', 'T', 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0, 5, 0, 1, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82}

func browseServe(t *testing.T, opts BrowseOptions) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, "data.json", []byte(`{"a":1,"b":[2,3]}`))
	write(t, dir, "notes.txt", []byte("hello <b>world</b>\n"))
	write(t, dir, "pic.png", png1x1)
	write(t, dir, "sub/inner.txt", []byte("inner\n"))
	write(t, dir, "pkg.tar", mkTar(time.Unix(1_700_000_000, 0), "m.txt", "member text"))
	b, err := analysis.NewBrowser(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts.Title = "fixture"
	srv := httptest.NewServer(BrowseHandler(b, opts))
	t.Cleanup(srv.Close)
	return srv
}

func TestBrowsePageAndLevels(t *testing.T) {
	srv := browseServe(t, BrowseOptions{})
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	var page strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		page.Write(buf[:n])
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(page.String(), `x-data="browse()"`) {
		t.Errorf("the page: %s", resp.Status)
	}
	if r, _ := http.Get(srv.URL + "/chroma.css"); r.StatusCode != 200 || r.Header.Get("Content-Type") != "text/css; charset=utf-8" {
		t.Errorf("chroma.css: %v", r.Status)
	}
	var lv struct {
		Entries []analysis.BrowseEntry `json:"entries"`
	}
	getJSON(t, srv, "/api/level", &lv)
	var names []string
	for _, e := range lv.Entries {
		names = append(names, e.Name)
	}
	if got := strings.Join(names, " "); got != "data.json notes.txt pic.png pkg.tar sub" {
		t.Errorf("level: %s", got)
	}
	getJSON(t, srv, "/api/level?"+url.Values{"p": {"pkg.tar"}}.Encode(), &lv)
	if len(lv.Entries) != 1 || lv.Entries[0].Name != "m.txt" {
		t.Errorf("pkg.tar: %+v", lv.Entries)
	}
	if r, _ := http.Get(srv.URL + "/api/level?p=nope"); r.StatusCode != 404 {
		t.Errorf("a level that is not there: %s", r.Status)
	}
}

func TestBrowsePreviewText(t *testing.T) {
	srv := browseServe(t, BrowseOptions{})
	var p previewResp
	getJSON(t, srv, "/api/preview?name=notes.txt", &p)
	if p.Kind != "text" || !strings.Contains(p.Text, "hello <b>world</b>") || strings.Contains(p.HTML, "<b>world") || !strings.Contains(p.HTML, "&lt;") {
		t.Errorf("text preview must be escaped HTML: %+v", p)
	}
	// JSON is shown reformatted unless raw is asked for.
	getJSON(t, srv, "/api/preview?name=data.json", &p)
	if !p.CanPretty || !p.Pretty || !strings.Contains(p.Text, "\n  \"a\": 1") {
		t.Errorf("pretty: %+v", p)
	}
	getJSON(t, srv, "/api/preview?name=data.json&raw=1", &p)
	if !p.CanPretty || p.Pretty || p.Text != `{"a":1,"b":[2,3]}` {
		t.Errorf("raw: %+v", p)
	}
	// The same location form as the diff page: p= for the level, sel= for the entry.
	getJSON(t, srv, "/api/preview?p=pkg.tar&sel=m.txt", &p)
	if p.Text != "member text" {
		t.Errorf("a member: %+v", p)
	}
	getJSON(t, srv, "/api/preview?name=sub", &p)
	if p.Kind != "dir" {
		t.Errorf("a directory: %+v", p)
	}
}

func TestBrowseRawImagesAndDownloads(t *testing.T) {
	srv := browseServe(t, BrowseOptions{})
	resp, err := http.Get(srv.URL + "/api/raw?name=pic.png")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/png" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("image: %s %v", resp.Status, resp.Header)
	}
	if r, _ := http.Get(srv.URL + "/api/raw?name=notes.txt"); r.StatusCode != 400 {
		t.Errorf("inline raw of a non-image: %s", r.Status)
	}
	resp, _ = http.Get(srv.URL + "/api/raw?name=notes.txt&download=1")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), `filename="notes.txt"`) {
		t.Errorf("download: %s %v", resp.Status, resp.Header)
	}
	resp.Body.Close()

	locked := browseServe(t, BrowseOptions{AllowDownload: func(*http.Request) bool { return false }})
	if r, _ := http.Get(locked.URL + "/api/raw?name=notes.txt&download=1"); r.StatusCode != 403 {
		t.Errorf("downloads refused: %s", r.Status)
	}
	if r, _ := http.Get(locked.URL + "/api/raw?name=pic.png"); r.StatusCode != 200 {
		t.Errorf("inline images stay: %s", r.Status)
	}
}

func TestBrowseReconRunsInTheBackground(t *testing.T) {
	release := make(chan struct{})
	srv := browseServe(t, BrowseOptions{Recon: func(e analysis.BrowseEntry) (string, error) {
		<-release
		return "report for " + e.Name, nil
	}})
	var info struct {
		Recon bool `json:"recon"`
	}
	getJSON(t, srv, "/api/info", &info)
	if !info.Recon {
		t.Error("the page is not told recon is on")
	}
	var p previewResp
	getJSON(t, srv, "/api/preview?name=notes.txt", &p)
	if p.Recon == nil || p.Recon.State != "running" {
		t.Fatalf("first ask: %+v", p.Recon)
	}
	close(release)
	for i := 0; i < 100; i++ {
		getJSON(t, srv, "/api/preview?name=notes.txt", &p)
		if p.Recon.State == "done" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p.Recon.State != "done" || p.Recon.Text != "report for notes.txt" {
		t.Errorf("recon: %+v", p.Recon)
	}
	// Without a Recon hook, previews carry none.
	plain := browseServe(t, BrowseOptions{})
	var q previewResp
	getJSON(t, plain, "/api/preview?name=notes.txt", &q)
	if q.Recon != nil {
		t.Errorf("recon without a hook: %+v", q.Recon)
	}
}

func TestBrowsePreviewOfABinaryListsItsStrings(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "prog.bin", append(append([]byte{0, 1, 2, 3, 0xff, 0xfe}, []byte("a printable string here")...), 0, 0, 9, 9))
	b, err := analysis.NewBrowser(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(BrowseHandler(b, BrowseOptions{}))
	defer srv.Close()
	var p previewResp
	getJSON(t, srv, "/api/preview?name=prog.bin", &p)
	if p.Kind != "binary" || len(p.Strings) != 1 || p.Strings[0] != "a printable string here" {
		t.Errorf("%+v", p)
	}
}

// A download has OnRead told the sha256 of the whole entry, only once it is all read; an inline image preview
// (never the whole file, and not a download) does not call it.
func TestBrowseRawDownloadCallsOnRead(t *testing.T) {
	var got []string
	srv := browseServe(t, BrowseOptions{OnRead: func(e analysis.BrowseEntry, sha256 string, size int64) {
		got = append(got, fmt.Sprintf("%s:%s:%d", e.Name, sha256, size))
	}})
	body := "hello <b>world</b>\n"
	want := sha256Hex([]byte(body))
	resp, err := http.Get(srv.URL + "/api/raw?name=notes.txt&download=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download: %s", resp.Status)
	}
	if want2 := fmt.Sprintf("notes.txt:%s:%d", want, len(body)); len(got) != 1 || got[0] != want2 {
		t.Errorf("OnRead = %v, want [%q]", got, want2)
	}
	if resp, _ := http.Get(srv.URL + "/api/raw?name=pic.png"); resp != nil {
		resp.Body.Close()
	}
	if len(got) != 1 {
		t.Errorf("an inline image preview called OnRead too: %v", got)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
