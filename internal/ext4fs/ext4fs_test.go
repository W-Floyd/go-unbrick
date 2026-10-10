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
