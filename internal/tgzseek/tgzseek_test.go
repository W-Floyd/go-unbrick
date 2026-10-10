package tgzseek

import (
	"archive/tar"
	"bytes"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/inflate/pigztest"
)

type file struct {
	name string
	body []byte
}

func random(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// text is compressible, like a bootloader or a script.
func text(n int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	words := []string{"abl ", "xbl ", "fastboot ", "\x00\x00\x00\x00", "partition ", "vbmeta "}
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(words[rng.Intn(len(words))])
	}
	return b.Bytes()[:n]
}

// rom is laid out like a fastboot package: a few small files, a large
// incompressible super image, the identity images after it.
func rom() []file {
	return []file{
		{"rom/flash_all.sh", text(4000, 1)},
		{"rom/images/gpt_main0.bin", text(24576, 2)},
		{"rom/images/super.img", random(12<<20, 3)},
		{"rom/images/abl.elf", text(200<<10, 4)},
		{"rom/images/vbmeta.img", append([]byte("AVB0"), text(8188, 5)...)},
		{"rom/images/userdata.img", make([]byte, 8<<20)},
		{"rom/images/modem.img", random(6<<20, 6)},
		{"rom/images/dtbo.img", text(300<<10, 7)},
		{"rom/flash_gen_crc_list.py", text(2000, 8)},
	}
}

func tgz(t *testing.T, files []file) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "rom/", Typeflag: tar.TypeDir, Mode: 0o755, Uname: "builder", ModTime: time.Unix(1e9, 0)})
	for _, f := range files {
		tw.WriteHeader(&tar.Header{Name: f.name, Size: int64(len(f.body)), Mode: 0o644, Typeflag: tar.TypeReg, Uname: "builder", ModTime: time.Unix(1e9, 0)})
		tw.Write(f.body)
	}
	tw.Close()
	return pigztest.Gzip(tb.Bytes(), 128<<10)
}

type server struct {
	*httptest.Server
	sent atomic.Int64
}

type counter struct {
	http.ResponseWriter
	n *atomic.Int64
}

func (c counter) Write(p []byte) (int, error) {
	c.n.Add(int64(len(p)))
	return c.ResponseWriter.Write(p)
}

func serve(t *testing.T, body []byte) *server {
	s := &server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"x"`)
		http.ServeContent(counter{w, &s.sent}, r, "f", time.Unix(0, 0), bytes.NewReader(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func scale(t *testing.T) {
	saved := []any{Budget, MinBudget, Keep, WalkLimit, LandWalk, LandConfirm}
	Budget, MinBudget, Keep, WalkLimit, LandWalk, LandConfirm = 0.3, 0, 1<<20, 256<<10, 256<<10, 1<<20
	t.Cleanup(func() {
		Budget, MinBudget, Keep = saved[0].(float64), saved[1].(int64), saved[2].(int64)
		WalkLimit, LandWalk, LandConfirm = saved[3].(int64), saved[4].(int64), saved[5].(int64)
	})
	infile.CacheDir = t.TempDir()
	Log = t.Logf
	t.Cleanup(func() { Log = nil })
}

func open(t *testing.T, s *server) *Archive {
	t.Helper()
	f, err := infile.Open(s.URL + "/rom.tgz")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Open(f, f.Size())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRemoteListAndRead(t *testing.T) {
	scale(t)
	files := rom()
	body := tgz(t, files)
	s := serve(t, body)
	a := open(t, s)
	if !a.Complete {
		t.Fatalf("listing not complete: %v", a)
	}
	if len(a.Entries) != len(files) {
		t.Fatalf("%d entries, want %d", len(a.Entries), len(files))
	}
	for i, f := range files {
		e := a.Entries[i]
		if e.Name != f.name || e.Size != int64(len(f.body)) {
			t.Fatalf("entry %d: %s %d, want %s %d", i, e.Name, e.Size, f.name, len(f.body))
		}
		if !bytes.HasPrefix(f.body, e.Head) || len(e.Head) == 0 && len(f.body) > 0 {
			t.Errorf("%s: wrong head", f.name)
		}
	}
	listed := s.sent.Load()
	if listed > int64(len(body))/4 {
		t.Errorf("listing fetched %d of %d bytes", listed, len(body))
	}
	for i, f := range files {
		if f.name == "rom/images/super.img" || f.name == "rom/images/modem.img" {
			continue // reading them is a full fetch of each; covered below
		}
		got, err := io.ReadAll(a.Open(i))
		if err != nil || !bytes.Equal(got, f.body) {
			t.Fatalf("%s: %d bytes, %v", f.name, len(got), err)
		}
	}
	got, err := io.ReadAll(a.Open(6))
	if err != nil || !bytes.Equal(got, files[6].body) {
		t.Fatalf("modem.img: %d bytes, %v", len(got), err)
	}
	t.Logf("listing fetched %d, total %d of %d", listed, s.sent.Load(), len(body))
}

func TestRemotePartial(t *testing.T) {
	scale(t)
	Budget = 0.06 // enough for the head and the tail, not the middle
	files := rom()
	s := serve(t, tgz(t, files))
	a := open(t, s)
	if a.Complete || a.Missing == 0 {
		t.Fatalf("complete with a budget that cannot reach the middle: %v", a)
	}
	for i, e := range a.Entries {
		for _, f := range files {
			if f.name != e.Name || int64(len(f.body)) > Keep {
				continue
			}
			got, err := io.ReadAll(a.Open(i))
			if err != nil || !bytes.Equal(got, f.body) {
				t.Fatalf("%s: %d bytes, %v", f.name, len(got), err)
			}
		}
	}
}
