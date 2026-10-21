package carve

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"testing"

	"github.com/pierrec/lz4/v4"
)

func tarOf(t *testing.T, files map[string][]byte) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0o644, Typeflag: tar.TypeReg})
		tw.Write(body)
	}
	tw.Close()
	return b.Bytes()
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

// zipOf stores (not deflates) members named stored, so they read in place.
func zipOf(t *testing.T, files map[string][]byte, stored map[string]bool) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range files {
		m := zip.Deflate
		if stored[name] {
			m = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: m})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(body)
	}
	zw.Close()
	return b.Bytes()
}

func read(t *testing.T, n *Node) []byte {
	t.Helper()
	r, err := n.Reader()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWalkNested(t *testing.T) {
	inner := tarOf(t, map[string][]byte{"images/vbmeta.img": []byte("AVB0rest"), "readme": []byte("hi")})
	pkg := zipOf(t, map[string][]byte{
		"rom.tar":          inner,
		"rom.tar.gz":       gz(inner),
		"META-INF/x/y.txt": []byte("deflated"),
	}, map[string]bool{"rom.tar": true})
	root := FromBytes("pkg.zip", pkg)

	for _, p := range []string{"rom.tar/images/vbmeta.img", "rom.tar.gz/rom.tar/images/vbmeta.img"} {
		n, err := root.Walk(p)
		if err != nil {
			t.Fatalf("Walk(%s): %v", p, err)
		}
		if got := read(t, n); string(got) != "AVB0rest" {
			t.Errorf("%s = %q", p, got)
		}
	}
	// A name with slashes is one child, found whole.
	if n, err := root.Walk("META-INF/x/y.txt"); err != nil || string(read(t, n)) != "deflated" {
		t.Errorf("META-INF/x/y.txt: %v", err)
	}
	if _, err := root.Walk("rom.tar/missing"); err == nil {
		t.Error("Walk to a missing path succeeded")
	}
	kind, kids, err := root.Children()
	if kind != "zip" || len(kids) != 3 || err != nil {
		t.Errorf("Children = %s %d %v", kind, len(kids), err)
	}
	// A stored member is read in place, not buffered.
	n, _ := root.Walk("rom.tar")
	if n.at == nil {
		t.Error("stored zip member has no ReaderAt")
	}
}

func TestConcatExtents(t *testing.T) {
	super := []byte("....AAAA....BBBB")
	c := &concat{parts: []extent{
		{ra: bytes.NewReader(super), off: 12, size: 4},
		{size: 3, zero: true},
		{ra: bytes.NewReader(super), off: 4, size: 4},
	}}
	got := make([]byte, 11)
	if n, err := c.ReadAt(got, 0); n != 11 || err != nil || string(got) != "BBBB\x00\x00\x00AAAA" {
		t.Fatalf("ReadAt = %d %v %q", n, err, got)
	}
	part := make([]byte, 4)
	if n, _ := c.ReadAt(part, 5); n != 4 || string(part) != "\x00\x00AA" {
		t.Errorf("mid read = %q", part)
	}
}

// TestOdinPackage walks a firmware zip as Samsung ships one: a deflated
// .tar.md5 of lz4 images, the tar followed by its checksum line.
func TestOdinPackage(t *testing.T) {
	img := append([]byte("AVB0"), bytes.Repeat([]byte("vbmeta "), 4000)...)
	var lz bytes.Buffer
	w := lz4.NewWriter(&lz)
	w.Write(img)
	w.Close()
	odin := append(tarOf(t, map[string][]byte{"vbmeta.img.lz4": lz.Bytes()}),
		"0123456789abcdef0123456789abcdef  BL_TEST.tar\n"...)
	root := FromBytes("fw.zip", zipOf(t, map[string][]byte{"BL_TEST.tar.md5": odin}, nil))

	n, err := root.Walk("BL_TEST.tar.md5/vbmeta.img.lz4/vbmeta.img")
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, n); !bytes.Equal(got, img) {
		t.Errorf("vbmeta.img: %d bytes, want %d", len(got), len(img))
	}
	tarNode, _ := root.Walk("BL_TEST.tar.md5")
	if tarNode.defl == nil || tarNode.Partial() != "" {
		t.Errorf("deflated tar: span %v, partial %q", tarNode.defl, tarNode.Partial())
	}
}

// An LZ4 legacy stream in a padded partition opens as its decompressed content, which
// is itself a container (a cpio ramdisk).
func TestLZ4LegacyOpensToItsCpio(t *testing.T) {
	cpio := func(name, body string) []byte {
		hdr := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", 1, 0o100644, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(name)+1, 0)
		b := append([]byte(hdr+name), 0)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		b = append(b, body...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	archive := append(append(cpio("etc/os-release", "NAME=test\n"), cpio("init", "#!/bin/sh\n")...), cpio("TRAILER!!!", "")...)
	block := make([]byte, lz4.CompressBlockBound(len(archive)))
	n, err := lz4.CompressBlock(archive, block, nil)
	if err != nil || n == 0 {
		t.Fatalf("compress: %d %v", n, err)
	}
	stream := []byte{0x02, 0x21, 0x4c, 0x18, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
	stream = append(append(stream, block[:n]...), make([]byte, 3000)...) // the partition's padding

	root := FromBytes("a7s_root", stream)
	e, ok := Format(root)
	if !ok || e.Kind != "lz4 (legacy)" {
		t.Fatalf("format: %v %v", e.Kind, ok)
	}
	_, kids, err := root.Children()
	if err != nil || len(kids) != 1 || kids[0].Name != "a7s_root.out" {
		t.Fatalf("children: %v %v", kids, err)
	}
	if e2, ok := Format(kids[0]); !ok || e2.Kind != "ramdisk" {
		t.Fatalf("the decompressed content is not a ramdisk: %v %v", e2.Kind, ok)
	}
	_, files, err := kids[0].Children()
	if err != nil || len(files) != 2 {
		t.Fatalf("cpio members: %d %v", len(files), err)
	}
	got, _ := files[1].Bytes()
	if string(got) != "#!/bin/sh\n" {
		t.Errorf("content %q", got)
	}
}
