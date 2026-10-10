package infile

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

// mirrored makes servers that each serve body at /pkg.zip, and has Mirrors
// name all of them for any one.
func mirrored(t *testing.T, body []byte, n int) []*server {
	t.Helper()
	reset(t)
	hosts.Lock()
	hosts.loaded, hosts.m = false, nil
	hosts.Unlock()
	var ss []*server
	for i := 0; i < n; i++ {
		ss = append(ss, newServer(t, body, true))
	}
	Mirrors = func(u string) []string {
		var out []string
		for _, s := range ss {
			out = append(out, s.URL+"/pkg.zip")
		}
		return out
	}
	t.Cleanup(func() { Mirrors = nil })
	return ss
}

func readAt(t *testing.T, u string, off, n int) []byte {
	t.Helper()
	f, err := Open(u)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, int64(off)); err != nil {
		t.Fatalf("ReadAt(%d, %d): %v", off, n, err)
	}
	return b
}

func TestMirrorsShareCacheEntry(t *testing.T) {
	body := randBytes(4 * chunkSize)
	ss := mirrored(t, body, 2)
	if got := readAt(t, ss[0].URL+"/pkg.zip", 0, len(body)); !bytes.Equal(got, body) {
		t.Fatal("wrong bytes")
	}
	forget()
	before := ss[1].sent.Load()
	if got := readAt(t, ss[1].URL+"/pkg.zip", 0, len(body)); !bytes.Equal(got, body) {
		t.Fatal("wrong bytes from the cache")
	}
	if sent := ss[1].sent.Load() - before; sent > 1 {
		t.Errorf("the mirror sent %d bytes for an object already cached under the other", sent)
	}
}

func TestMirrorFailover(t *testing.T) {
	body := randBytes(3 * chunkSize)
	ss := mirrored(t, body, 2)
	u := ss[0].URL + "/pkg.zip"
	f, err := Open(u) // the probe succeeds; ranges after it fail
	if err != nil {
		t.Fatal(err)
	}
	ss[0].Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "busy", 503) })
	got := make([]byte, 100)
	if _, err := f.ReadAt(got, chunkSize); err != nil || !bytes.Equal(got, body[chunkSize:chunkSize+100]) {
		t.Fatalf("ReadAt with the first host down: %v", err)
	}
}

func TestSplitAcrossMirrorsAndRemember(t *testing.T) {
	body := randBytes(2 * splitChunks * chunkSize)
	ss := mirrored(t, body, 2)
	if got := readAt(t, ss[0].URL+"/pkg.zip", 0, len(body)); !bytes.Equal(got, body) {
		t.Fatal("wrong bytes")
	}
	for i, s := range ss {
		if s.sent.Load() < chunkSize {
			t.Errorf("mirror %d sent %d bytes; a long read should be spread over both", i, s.sent.Load())
		}
	}
	// What was learned of each host is on disk for the next run.
	hosts.Lock()
	hosts.loaded, hosts.m = false, nil
	hosts.Unlock()
	for i, s := range ss {
		if st := stat(hostOf(s.URL)); st.BytesPerSec == 0 {
			t.Errorf("mirror %d: no speed recorded", i)
		}
	}
}

func TestMirrorServingOtherObjectDropped(t *testing.T) {
	body := randBytes(2 * splitChunks * chunkSize)
	ss := mirrored(t, body, 2)
	ss[1].body, ss[1].etag = randBytes(len(body)), `"other"`
	if got := readAt(t, ss[0].URL+"/pkg.zip", 0, len(body)); !bytes.Equal(got, body) {
		t.Fatal("a mirror with different content got into the cache")
	}
	r := remotes[ss[0].URL+"/pkg.zip"]
	if !r.dropped[ss[1].URL+"/pkg.zip"] {
		t.Error("the mirror serving another object was not dropped")
	}
}

type slowWriter struct{ http.ResponseWriter }

func (s slowWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		k := min(len(p), 8<<10)
		w, err := s.ResponseWriter.Write(p[:k])
		n += w
		if err != nil {
			return n, err
		}
		s.ResponseWriter.(http.Flusher).Flush()
		time.Sleep(80 * time.Millisecond) // ~100 KB/s
		p = p[k:]
	}
	return n, nil
}

// A slow mirror takes a small piece and is hedged; it cannot hold up a read
// the fast one could do alone.
func TestSlowMirrorDoesNotHoldUpRead(t *testing.T) {
	body := randBytes(3 * splitChunks * chunkSize)
	ss := mirrored(t, body, 2)
	slow := ss[1]
	slow.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", slow.etag)
		http.ServeContent(slowWriter{w}, r, "f", time.Unix(0, 0), bytes.NewReader(slow.body))
	})
	t0 := time.Now()
	if got := readAt(t, ss[0].URL+"/pkg.zip", 0, len(body)); !bytes.Equal(got, body) {
		t.Fatal("wrong bytes")
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Errorf("read took %v with one slow mirror", d)
	}
}

// Two readers walking the file in alternation each get readahead.
func TestInterleavedSequentialReadahead(t *testing.T) {
	reset(t)
	body := randBytes(200 * chunkSize)
	s := newServer(t, body, true)
	f, err := Open(s.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	before := s.reqs.Load()
	buf := make([]byte, chunkSize)
	for i := 0; i < 40; i++ {
		for _, base := range []int{0, 100} {
			if _, err := f.ReadAt(buf, int64(base+i)*chunkSize); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n := s.reqs.Load() - before; n > 20 {
		t.Errorf("%d requests for 80 chunks read by two interleaved sequential readers", n)
	}
}
