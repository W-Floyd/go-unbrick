package carve

import (
	"archive/zip"
	"bytes"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// A member too big for memory, in a zip on a server, is unpacked to a temporary
// file by streaming its own bytes: the rest of the archive is never fetched.
func TestSpoolingARemoteMemberFetchesOnlyThatMember(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	random := func(n int) []byte {
		b := make([]byte, n)
		rnd.Read(b)
		return b
	}
	big, other := random(3<<20), random(3<<20)

	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for _, m := range []struct {
		name string
		data []byte
	}{{"first.bin", other}, {"wanted.bin", big}, {"last.bin", other}} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: m.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(m.data)
	}
	zw.Close()
	archive := zb.Bytes()

	var sent atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(countWriter{w, &sent}, r, "a.zip", time.Unix(0, 0), bytes.NewReader(archive))
	}))
	defer srv.Close()

	oldDir, oldMax, oldFull := infile.CacheDir, MaxBuffer, infile.FullDownload
	infile.CacheDir, MaxBuffer, infile.FullDownload = t.TempDir(), 1<<20, true
	t.Cleanup(func() { infile.CacheDir, MaxBuffer, infile.FullDownload = oldDir, oldMax, oldFull })

	root, err := Open(srv.URL + "/a.zip")
	if err != nil {
		t.Fatal(err)
	}
	n, err := root.Walk("wanted.bin")
	if err != nil {
		t.Fatal(err)
	}
	ra, err := n.ReaderAt()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 64)
	if _, err := ra.ReadAt(got, 2<<20); err != nil || !bytes.Equal(got, big[2<<20:2<<20+64]) {
		t.Fatalf("read back %v", err)
	}
	// Two of the three members are the same size and incompressible: fetching the
	// whole archive would send about 9 MiB; one member is about 3.
	if s := sent.Load(); s > 5<<20 {
		t.Errorf("fetched %d bytes of a %d-byte archive to unpack one member", s, len(archive))
	}
}

type countWriter struct {
	http.ResponseWriter
	n *atomic.Int64
}

func (w countWriter) Write(p []byte) (int, error) {
	w.n.Add(int64(len(p)))
	return w.ResponseWriter.Write(p)
}
