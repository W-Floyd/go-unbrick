package ext4fs

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"
)

// small.ext4 is mke2fs -b 1024 -g 1024 -N 64 -O ^64bit -d of: build.prop,
// etc/sub/x.txt, lib/big.bin (seq 1 12000, several blocks) and many/f1..f40.txt.
func open(t *testing.T) *FS {
	t.Helper()
	f, err := os.Open("testdata/small.ext4.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	img, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	return fsys
}

// go-ext4 refuses an image without flex_bg though it never depends on it
// (Motorola's dspso is built without); the overlay reports it set, leaving
// the image itself untouched.
func TestFlexOverlay(t *testing.T) {
	img := make([]byte, 2048)
	binary.LittleEndian.PutUint32(img[incompatOff:], 0x42) // extents|filetype
	sb := make([]byte, 1024)
	if _, err := (flexOverlay{bytes.NewReader(img)}).ReadAt(sb, 1024); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(sb[0x60:])&flexBG == 0 {
		t.Error("flex_bg not reported")
	}
	if binary.LittleEndian.Uint32(img[incompatOff:])&flexBG != 0 {
		t.Error("the image was modified")
	}
}

func TestFS(t *testing.T) {
	fsys := open(t)
	if err := fstest.TestFS(fsys, "build.prop", "etc/sub/x.txt", "lib/big.bin"); err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	for i := 1; i <= 12000; i++ {
		fmt.Fprintf(&want, "%d\n", i)
	}
	for name, body := range map[string][]byte{
		"build.prop":    []byte("ro.vendor.build.fingerprint=test/fp\n"),
		"etc/sub/x.txt": []byte("nested\n"),
		"lib/big.bin":   want.Bytes(),
	} {
		got, err := fs.ReadFile(fsys, name)
		if err != nil || !bytes.Equal(got, body) {
			t.Errorf("%s: %d bytes, %v", name, len(got), err)
		}
	}
	// 40 files over four 16-inode groups: most of them past the first, where
	// a misread descriptor table puts every inode.
	for i := 1; i <= 40; i++ {
		got, err := fs.ReadFile(fsys, fmt.Sprintf("many/f%d.txt", i))
		if want := fmt.Sprintf("file %d\n", i); err != nil || string(got) != want {
			t.Errorf("many/f%d.txt = %q, %v", i, got, err)
		}
	}
	if _, err := fs.Stat(fsys, "etc/missing"); err == nil {
		t.Error("missing path found")
	}
}

// OpenAt reads a file at any offset without reading what precedes it, and
// agrees with reading it through from the start.
func TestOpenAt(t *testing.T) {
	fsys := open(t)
	whole, err := fs.ReadFile(fsys, "lib/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	ra := fsys.OpenAt("lib/big.bin")
	for _, c := range []struct{ off, n int }{{0, 10}, {4090, 20}, {len(whole) - 7, 7}, {len(whole) / 2, 5000}, {8192, 4096}} {
		got := make([]byte, c.n)
		if n, err := ra.ReadAt(got, int64(c.off)); n != c.n || err != nil {
			t.Fatalf("ReadAt(%d,%d) = %d, %v", c.off, c.n, n, err)
		}
		if !bytes.Equal(got, whole[c.off:c.off+c.n]) {
			t.Errorf("ReadAt(%d,%d) differs from the sequential read", c.off, c.n)
		}
	}
	// Past the end is a short read with io.EOF.
	got := make([]byte, 10)
	if n, err := ra.ReadAt(got, int64(len(whole))-4); n != 4 || err != io.EOF {
		t.Errorf("read across the end: %d, %v", n, err)
	}
	// A missing file reports it on the first read, not when handed out.
	if _, err := fsys.OpenAt("nope").ReadAt(got, 0); err == nil {
		t.Error("missing file read")
	}
}

type countReads struct {
	io.ReaderAt
	n int
}

func (c *countReads) ReadAt(p []byte, off int64) (int, error) {
	c.n++
	return c.ReaderAt.ReadAt(p, off)
}

// A directory is read from the image once: opening more files in it, or in
// directories below it, does not read it again.
func TestDirectoriesAreReadOnce(t *testing.T) {
	f, err := os.Open("testdata/small.ext4.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	img, _ := io.ReadAll(z)
	c := &countReads{ReaderAt: bytes.NewReader(img)}
	fsys, err := Open(c, int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile(fsys, "many/f1.txt"); err != nil { // resolves root and many/
		t.Fatal(err)
	}
	before := c.n
	for i := 2; i <= 40; i++ {
		if _, err := fsys.Open(fmt.Sprintf("many/f%d.txt", i)); err != nil {
			t.Fatal(err)
		}
	}
	// Each open still reads its own inode; the two directories on the way are cached.
	cached := float64(c.n-before) / 39
	// Control: with the cache emptied before each open, the same opens read
	// the directories every time, so the cache is what the figure above measures.
	before = c.n
	for i := 2; i <= 40; i++ {
		fsys.dirsMu.Lock()
		fsys.dirs = nil
		fsys.dirsMu.Unlock()
		if _, err := fsys.Open(fmt.Sprintf("many/f%d.txt", i)); err != nil {
			t.Fatal(err)
		}
	}
	uncached := float64(c.n-before) / 39
	t.Logf("image reads per open: %.1f cached, %.1f with the directory cache emptied", cached, uncached)
	if uncached < cached*1.5 {
		t.Errorf("emptying the cache did not cost reads (%.1f vs %.1f): the test is not measuring it", uncached, cached)
	}
	if cached > 6 {
		t.Errorf("%.1f image reads per open of a file in a directory already read; want its own inode only", cached)
	}
}
