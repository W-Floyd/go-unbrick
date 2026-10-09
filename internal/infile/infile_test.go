package infile

import (
	"archive/zip"
	"bytes"
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
	remotesMu.Unlock()
}

// forget drops the in-process handles, as a new run would, keeping the disk cache.
func forget() {
	remotesMu.Lock()
	remotes = map[string]*remote{}
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
