package carve

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

// hazard stands in for a reader that cannot be shared (go-ext4 seeks one reader
// then reads it): a read that overlaps another is counted, and its result is
// garbage, as the real thing's would be.
type hazard struct{ inside, overlaps atomic.Int32 }

func (h *hazard) read(p []byte, src []byte, off int64) int {
	if h.inside.Add(1) > 1 {
		h.overlaps.Add(1)
	}
	time.Sleep(100 * time.Microsecond) // long enough for another goroutine to arrive
	n := 0
	if off < int64(len(src)) {
		n = copy(p, src[off:])
	}
	if h.overlaps.Load() > 0 { // after an overlap everything read is wrong
		for i := range p[:n] {
			p[i] ^= 0xff
		}
	}
	h.inside.Add(-1)
	return n
}

type hazardFS struct {
	fstest.MapFS
	h *hazard
}

func (f hazardFS) Open(name string) (fs.File, error) {
	file, err := f.MapFS.Open(name)
	if err != nil {
		return nil, err
	}
	if info, _ := file.Stat(); info.IsDir() {
		return file, nil
	}
	return &hazardFile{File: file, data: f.MapFS[name].Data, h: f.h}, nil
}

type hazardFile struct {
	fs.File
	data []byte
	pos  int64
	h    *hazard
}

func (f *hazardFile) Read(p []byte) (int, error) {
	n := f.h.read(p, f.data, f.pos)
	f.pos += int64(n)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// hazardAtFS also hands out files read at random, as ext4fs does.
type hazardAtFS struct{ hazardFS }

func (f hazardAtFS) OpenAt(name string) io.ReaderAt {
	return readerAtFunc(func(p []byte, off int64) (int, error) {
		n := f.h.read(p, f.MapFS[name].Data, off)
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	})
}

type readerAtFunc func(p []byte, off int64) (int, error)

func (r readerAtFunc) ReadAt(p []byte, off int64) (int, error) { return r(p, off) }

func files(n int) fstest.MapFS {
	m := fstest.MapFS{}
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("d/f%02d.bin", i)] = &fstest.MapFile{Data: bytes.Repeat([]byte{byte('a' + i)}, 4000+i)}
	}
	return m
}

// readAll reads every node from several goroutines at once, as a viewer and a
// comparison do, and reports whether any read came back wrong.
func readAll(t *testing.T, nodes []*Node, src fstest.MapFS) (wrong int32) {
	var wg sync.WaitGroup
	var bad atomic.Int32
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for round := 0; round < 3; round++ {
				for i := range nodes {
					n := nodes[(i+g)%len(nodes)]
					got, err := n.Bytes()
					if want := src["d/"+n.Name[2:]].Data; err != nil || !bytes.Equal(got, want) {
						bad.Add(1)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	return bad.Load()
}

func TestWalkFSReadsAreSerialised(t *testing.T) {
	// Control: without the lock the hazard is real, so the test below means something.
	{
		h := &hazard{}
		src := files(4)
		fsys := hazardFS{src, h}
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Through Open: MapFS's own ReadFile would bypass the unsafe reader.
				if f, err := fsys.Open("d/f01.bin"); err == nil {
					io.ReadAll(f)
				}
			}()
		}
		wg.Wait()
		if h.overlaps.Load() == 0 {
			t.Fatal("the unsafe filesystem was not caught being read twice at once: the test cannot tell")
		}
	}

	for name, mk := range map[string]func(fstest.MapFS, *hazard) fs.FS{
		"stream":      func(m fstest.MapFS, h *hazard) fs.FS { return hazardFS{m, h} },
		"random-read": func(m fstest.MapFS, h *hazard) fs.FS { return hazardAtFS{hazardFS{m, h}} },
	} {
		src := files(12)
		h := &hazard{}
		nodes, err := walkFS(mk(src, h))
		if err != nil || len(nodes) != 12 {
			t.Fatalf("%s: %d nodes, %v", name, len(nodes), err)
		}
		for i := range nodes { // make the names "d/..." so readAll can find the source
			nodes[i].Name = "d/" + nodes[i].Name[2:]
		}
		if wrong := readAll(t, nodes, src); wrong != 0 {
			t.Errorf("%s: %d reads came back wrong", name, wrong)
		}
		if n := h.overlaps.Load(); n != 0 {
			t.Errorf("%s: the filesystem was read by two goroutines at once %d times", name, n)
		}
	}
}
