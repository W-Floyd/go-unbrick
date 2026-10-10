package carve

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
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
