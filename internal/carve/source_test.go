package carve

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A member stored in an archive says where its bytes sit in the file read by
// path, so that range can be fetched on its own.
func TestMemberSource(t *testing.T) {
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	for _, f := range []struct{ n, c string }{{"a.bin", "alpha-bytes"}, {"b.bin", "bravo-bytes-longer"}} {
		tw.WriteHeader(&tar.Header{Name: f.n, Mode: 0o644, Size: int64(len(f.c))})
		tw.Write([]byte(f.c))
	}
	tw.Close()

	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "s.bin", Method: zip.Store})
	w.Write([]byte("stored-member"))
	zw.Close()

	for name, raw := range map[string][]byte{"x.tar": tb.Bytes(), "x.zip": zb.Bytes()} {
		p := filepath.Join(t.TempDir(), name)
		os.WriteFile(p, raw, 0o644)
		root, err := Open(p)
		if err != nil {
			t.Fatal(err)
		}
		if sp, off, n, ok := root.Source(); !ok || sp != p || off != 0 || n != int64(len(raw)) {
			t.Errorf("%s root source: %q %d %d %v", name, sp, off, n, ok)
		}
		_, kids, err := root.Children()
		if err != nil || len(kids) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		for _, k := range kids {
			sp, off, n, ok := k.Source()
			if !ok || sp != p {
				t.Fatalf("%s/%s: no source (%q %v)", name, k.Name, sp, ok)
			}
			got := raw[off : off+n]
			want, _ := k.Bytes()
			if !bytes.Equal(got, want) {
				t.Errorf("%s/%s: source range holds %q, member is %q", name, k.Name, got, want)
			}
		}
	}
}

type countingAt struct {
	b     []byte
	reads int
}

func (c *countingAt) ReadAt(p []byte, off int64) (int, error) {
	c.reads++
	if off >= int64(len(c.b)) {
		return 0, io.EOF
	}
	n := copy(p, c.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Listing a zip reads its directory, not a local header per member; where a
// member's data starts is found when the member is read.
func TestZipListingDoesNotReadMemberHeaders(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	want := map[string]string{}
	for i := 0; i < 200; i++ {
		name := fmt.Sprintf("m%03d.bin", i)
		body := strings.Repeat(name, 50)
		want[name] = body
		method := zip.Store
		if i%2 == 1 {
			method = zip.Deflate
		}
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		w.Write([]byte(body))
	}
	zw.Close()

	src := &countingAt{b: zb.Bytes()}
	root := FromReaderAt("x.zip", src, int64(zb.Len()))
	_, kids, err := root.Children()
	if err != nil || len(kids) != 200 {
		t.Fatalf("%d members, %v", len(kids), err)
	}
	if src.reads > 10 {
		t.Errorf("listing 200 members took %d reads; want the directory only", src.reads)
	}
	for _, k := range kids {
		if k.Claim() == nil || k.Claim().Algo != "crc32" {
			t.Fatalf("%s: no CRC claim", k.Name)
		}
	}
	before := src.reads
	for _, k := range []*Node{kids[0], kids[1]} { // one stored, one deflated
		got, err := k.Bytes()
		if err != nil || string(got) != want[k.Name] {
			t.Errorf("%s: %q, %v", k.Name, got, err)
		}
	}
	if src.reads == before {
		t.Error("reading members read nothing from the zip")
	}
}

// An odex names its dex in a 16-byte header; listing it reads that, and the
// dex is read from the file only when someone reads the dex.
func TestOdexListingReadsOnlyTheHeader(t *testing.T) {
	dex := bytes.Repeat([]byte("DEX-BODY-"), 100000) // ~900 KB
	odex := make([]byte, 40)
	copy(odex, "dey\n036\x00")
	binary.LittleEndian.PutUint32(odex[8:], uint32(len(odex)))
	binary.LittleEndian.PutUint32(odex[12:], uint32(len(dex)))
	odex = append(odex, dex...)
	odex = append(odex, "trailing deps"...)

	src := &countingAt{b: odex}
	root := FromReaderAt("app.odex", src, int64(len(odex)))
	_, kids, err := root.Children()
	if err != nil || len(kids) != 1 || kids[0].Name != "app.dex" {
		t.Fatalf("%v %v", kids, err)
	}
	if kids[0].Size != int64(len(dex)) {
		t.Errorf("dex size %d, want %d", kids[0].Size, len(dex))
	}
	if src.reads > 3 {
		t.Errorf("listing took %d reads; want the header", src.reads)
	}
	got, err := kids[0].Bytes()
	if err != nil || !bytes.Equal(got, dex) {
		t.Errorf("dex read back wrongly: %d bytes, %v", len(got), err)
	}
}
