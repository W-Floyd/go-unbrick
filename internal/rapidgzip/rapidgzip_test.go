package rapidgzip

import (
	"bytes"
	"compress/gzip"
	"io"
	"math/rand"
	"testing"
)

// corpus is compressible but not trivial, and spans many 4 MiB chunks once
// compressed, so the parallel path and the block finder both run.
func corpus(n int) []byte {
	rng := rand.New(rand.NewSource(1))
	words := [][]byte{[]byte("fastboot "), []byte("flash "), []byte("super "), []byte("vbmeta "), []byte("\x00\x00\x00\x00")}
	var b bytes.Buffer
	for b.Len() < n {
		if rng.Intn(8) == 0 {
			var r [64]byte
			rng.Read(r[:])
			b.Write(r[:])
			continue
		}
		b.Write(words[rng.Intn(len(words))])
	}
	return b.Bytes()[:n]
}

func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestRoundTripSeekAndIndex(t *testing.T) {
	plain := corpus(48 << 20)
	comp := gz(t, plain)

	z, err := NewReader(bytes.NewReader(comp), int64(len(comp)), Options{ChunkSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decoded %d bytes, mismatch with %d", len(got), len(plain))
	}
	if n, ok := z.Size(); !ok || n != int64(len(plain)) {
		t.Errorf("Size = %d, %v", n, ok)
	}
	var idx bytes.Buffer
	if err := z.ExportIndex(&idx); err != nil {
		t.Fatal(err)
	}
	z.Close()

	// A fresh reader with the index seeks straight to the target.
	z, err = NewReader(bytes.NewReader(comp), int64(len(comp)), Options{ChunkSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if err := z.ImportIndex(bytes.NewReader(idx.Bytes()), int64(idx.Len())); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{40 << 20, 7, 33<<20 + 12345} {
		p := make([]byte, 100000)
		if _, err := z.ReadAt(p, off); err != nil {
			t.Fatalf("ReadAt %d: %v", off, err)
		}
		if !bytes.Equal(p, plain[off:off+int64(len(p))]) {
			t.Fatalf("ReadAt %d: wrong bytes", off)
		}
	}
}

func TestNotGzip(t *testing.T) {
	junk := []byte("this is not a gzip stream at all")
	z, err := NewReader(bytes.NewReader(junk), int64(len(junk)), Options{})
	if err == nil {
		_, err = io.ReadAll(z)
		z.Close()
	}
	if err == nil {
		t.Fatal("decoding junk succeeded")
	}
}
