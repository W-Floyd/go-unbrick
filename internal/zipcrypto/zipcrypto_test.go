package zipcrypto

import (
	"bytes"
	"hash/crc32"
	"io"
	"math/rand"
	"testing"
)

func TestRoundTripAndCheck(t *testing.T) {
	plain := []byte("PK\x03\x04 a zip inside a zip")
	enc := Encrypt(plain, []byte("260107"), 0x42)
	if len(enc) != HeaderLen+len(plain) {
		t.Fatalf("%d bytes", len(enc))
	}
	if !Check(enc, []byte("260107"), 0x42) || Check(enc, []byte("260108"), 0x42) {
		t.Error("the header check does not tell passwords apart")
	}
	r, err := NewReaderAt(bytes.NewReader(enc), int64(len(plain)), []byte("260107"), 0x42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("%q %v", got, err)
	}
	if _, err := NewReaderAt(bytes.NewReader(enc), int64(len(plain)), []byte("nope"), 0x42); err != ErrPassword {
		t.Errorf("wrong password: %v", err)
	}
}

// The cipher is a stream, but a member can be read at any offset in any order, over
// several checkpoints.
func TestReadsAtRandomAcrossCheckpoints(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	plain := make([]byte, 3*checkpointEvery+12345)
	rng.Read(plain)
	enc := Encrypt(plain, []byte("pw"), byte(crc32.ChecksumIEEE(plain)>>24))
	r, err := NewReaderAt(bytes.NewReader(enc), int64(len(plain)), []byte("pw"), byte(crc32.ChecksumIEEE(plain)>>24))
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{int64(len(plain)) - 100, 0, checkpointEvery + 7, 2*checkpointEvery - 3, 5, int64(len(plain)) - 1} {
		n := 200
		if off+int64(n) > int64(len(plain)) {
			n = int(int64(len(plain)) - off)
		}
		buf := make([]byte, n)
		got, err := r.ReadAt(buf, off)
		if got != n || (err != nil && err != io.EOF) || !bytes.Equal(buf, plain[off:off+int64(n)]) {
			t.Fatalf("at %d: %d bytes, %v", off, got, err)
		}
	}
	// Past the end.
	buf := make([]byte, 10)
	if n, err := r.ReadAt(buf, int64(len(plain))-4); n != 4 || err != io.EOF {
		t.Errorf("short read: %d %v", n, err)
	}
	if n, err := r.ReadAt(buf, int64(len(plain))); n != 0 || err != io.EOF {
		t.Errorf("at the end: %d %v", n, err)
	}
}

type countingReaderAt struct {
	r io.ReaderAt
	n int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

// A reader in small chunks, as io.Copy over a section reader is, must cost about
// one pass over the member, not a pass per checkpoint's worth of chunks.
func TestSequentialSmallReadsCostOnePass(t *testing.T) {
	plain := make([]byte, 3*checkpointEvery)
	rand.New(rand.NewSource(2)).Read(plain)
	enc := Encrypt(plain, []byte("pw"), 7)
	src := &countingReaderAt{r: bytes.NewReader(enc)}
	r, err := NewReaderAt(src, int64(len(plain)), []byte("pw"), 7)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := io.Copy(&out, io.NewSectionReader(r, 0, r.Size())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Fatal("wrong bytes")
	}
	// The checkpoints are made as the copy passes them: one pass in all.
	if src.n > int64(len(plain))+1<<20 {
		t.Errorf("%d bytes read from the source for a %d byte member", src.n, len(plain))
	}
	// And a read behind the cursor still lands right.
	buf := make([]byte, 50)
	if _, err := r.ReadAt(buf, 100); err != nil || !bytes.Equal(buf, plain[100:150]) {
		t.Errorf("a read behind the cursor: %v", err)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	plain := make([]byte, 64<<20)
	enc := Encrypt(plain, []byte("pw"), 1)
	r, err := NewReaderAt(bytes.NewReader(enc), int64(len(plain)), []byte("pw"), 1)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 1<<20)
	b.SetBytes(int64(len(plain)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for off := int64(0); off < int64(len(plain)); off += int64(len(buf)) {
			r.ReadAt(buf, off)
		}
	}
}
