package infile

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// server serves body with range support, counting requests and bytes sent.
type server struct {
	body   []byte
	etag   string
	ranges bool
	reqs   atomic.Int64
	sent   atomic.Int64
	*httptest.Server
}

type countingWriter struct {
	http.ResponseWriter
	n *atomic.Int64
}

func (w countingWriter) Write(p []byte) (int, error) {
	w.n.Add(int64(len(p)))
	return w.ResponseWriter.Write(p)
}

func newServer(t *testing.T, body []byte, ranges bool) *server {
	s := &server{body: body, etag: `"v1"`, ranges: ranges}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.reqs.Add(1)
		cw := countingWriter{w, &s.sent}
		if !s.ranges {
			r.Header.Del("Range")
		}
		w.Header().Set("ETag", s.etag)
		http.ServeContent(cw, r, "f", time.Unix(0, 0), bytes.NewReader(s.body))
	}))
	t.Cleanup(s.Close)
	return s
}

func reset(t *testing.T) {
	CacheDir = t.TempDir()
	remotesMu.Lock()
	remotes = map[string]*remote{}
	byDir = map[string]*remote{}
	remotesMu.Unlock()
}

// forget drops the in-process handles, as a new run would, keeping the disk cache.
func forget() {
	remotesMu.Lock()
	remotes = map[string]*remote{}
	byDir = map[string]*remote{}
	remotesMu.Unlock()
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(1)).Read(b)
	return b
}

func TestRemoteReadAtAndCache(t *testing.T) {
	reset(t)
	body := randBytes(3*chunkSize + 123)
	s := newServer(t, body, true)
	u := s.URL + "/dir/pkg.zip?sig=abc"

	f, err := Open(u)
	if err != nil {
		t.Fatal(err)
	}
	if f.Size() != int64(len(body)) {
		t.Fatalf("size %d", f.Size())
	}
	for _, c := range []struct{ off, n int }{{0, 10}, {chunkSize - 5, 10}, {len(body) - 50, 50}, {chunkSize, 2 * chunkSize}} {
		got := make([]byte, c.n)
		if _, err := f.ReadAt(got, int64(c.off)); err != nil {
			t.Fatalf("ReadAt(%d,%d): %v", c.off, c.n, err)
		}
		if !bytes.Equal(got, body[c.off:c.off+c.n]) {
			t.Fatalf("ReadAt(%d,%d): wrong bytes", c.off, c.n)
		}
	}
	// Reading past the end is a short read with EOF, as io.ReaderAt requires.
	tail := make([]byte, 100)
	if n, err := f.ReadAt(tail, int64(len(body)-10)); n != 10 || err != io.EOF {
		t.Fatalf("tail read: %d %v", n, err)
	}
	if Base(u) != "pkg.zip" {
		t.Errorf("Base = %q", Base(u))
	}

	// A new run re-validates with one probe and fetches nothing else.
	forget()
	before := s.reqs.Load()
	b, err := ReadFile(u)
	if err != nil || !bytes.Equal(b, body) {
		t.Fatalf("ReadFile: %v", err)
	}
	if d := s.reqs.Load() - before; d != 1 {
		t.Errorf("cached rerun made %d requests, want 1 (the probe)", d)
	}
}

func TestRemoteZipFetchesOnlyWhatIsRead(t *testing.T) {
	reset(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "big.bin", Method: zip.Store})
	w.Write(randBytes(64 << 20))
	w, _ = zw.Create("small.txt")
	io.WriteString(w, "hello")
	zw.Close()
	s := newServer(t, buf.Bytes(), true)

	zr, err := OpenZip(s.URL + "/ota.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "small.txt" {
			continue
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != "hello" {
			t.Fatalf("small.txt = %q", b)
		}
	}
	if sent := s.sent.Load(); sent > 4*chunkSize {
		t.Errorf("fetched %d bytes of a %d-byte zip to read one small member", sent, buf.Len())
	}
}

func TestRemoteWithoutRangesRefused(t *testing.T) {
	reset(t)
	s := newServer(t, randBytes(64<<20), false)
	if _, err := Open(s.URL + "/x"); err == nil || !strings.Contains(err.Error(), "range") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if sent := s.sent.Load(); sent > 16<<20 { // what socket buffers absorb before the close lands
		t.Errorf("read %d bytes of the body before refusing", sent)
	}
}

func TestRemoteChangedMidRun(t *testing.T) {
	reset(t)
	s := newServer(t, randBytes(2*chunkSize), true)
	f, err := Open(s.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	s.etag = `"v2"`
	if _, err := f.ReadAt(make([]byte, 10), chunkSize); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("want a changed-content error, got %v", err)
	}
	// The next run sees the new validator and starts a fresh entry.
	forget()
	f, err = Open(s.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadAt(make([]byte, 10), chunkSize); err != nil {
		t.Fatal(err)
	}
}

// A response that stops arriving without closing is abandoned and retried,
// not waited on forever.
func TestRemoteStalledTransferRetried(t *testing.T) {
	reset(t)
	saved := IdleTimeout
	IdleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { IdleTimeout = saved })
	body := randBytes(2 * chunkSize)
	var gets atomic.Int64
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("Range") != "bytes=0-0" && gets.Add(1) == 1 {
			// Headers and a little of the body, then nothing.
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", chunkSize, 2*chunkSize-1, len(body)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(body[chunkSize : chunkSize+100])
			w.(http.Flusher).Flush()
			<-release
			return
		}
		http.ServeContent(w, r, "f", time.Unix(0, 0), bytes.NewReader(body))
	}))
	t.Cleanup(s.Close)
	t.Cleanup(func() { close(release) }) // before s.Close, which waits for the stalled handler
	f, err := Open(s.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 10)
	done := make(chan error, 1)
	go func() { _, err := f.ReadAt(got, chunkSize); done <- err }()
	select {
	case err := <-done:
		if err != nil || !bytes.Equal(got, body[chunkSize:chunkSize+10]) {
			t.Fatalf("ReadAt after a stall: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReadAt hung on a stalled transfer")
	}
	if gets.Load() < 2 {
		t.Errorf("%d range requests, want a retry after the stall", gets.Load())
	}
}

// TestRemoteRateLimitedUsesCache: a server that starts refusing (429) still
// serves what an earlier run cached; what was never fetched stays an error.
func TestRemoteRateLimitedUsesCache(t *testing.T) {
	reset(t)
	body := randBytes(3 * chunkSize)
	var limited atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limited.Load() {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "f", time.Unix(0, 0), bytes.NewReader(body))
	}))
	t.Cleanup(s.Close)
	var warned string
	saved := Warn
	Warn = func(f string, a ...any) { warned = fmt.Sprintf(f, a...) }
	t.Cleanup(func() { Warn = saved })

	f, err := Open(s.URL + "/fw.zip")
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 100)
	if _, err := f.ReadAt(head, 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	forget()
	limited.Store(true)

	f, err = Open(s.URL + "/fw.zip")
	if err != nil {
		t.Fatalf("rate-limited open with a cache: %v", err)
	}
	defer f.Close()
	got := make([]byte, 100)
	if _, err := f.ReadAt(got, 0); err != nil || !bytes.Equal(got, body[:100]) {
		t.Fatalf("cached range: %v", err)
	}
	if _, err := f.ReadAt(got, 2*chunkSize); err == nil {
		t.Error("an uncached range read while rate-limited")
	}
	if !strings.Contains(warned, "cached copy") {
		t.Errorf("no warning: %q", warned)
	}
}
