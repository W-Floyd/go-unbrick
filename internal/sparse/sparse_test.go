package sparse

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// buildSparse assembles a minimal sparse image from chunk specs for testing.
func buildSparse(blkSz uint32, chunks []func(*bytes.Buffer)) []byte {
	le := binary.LittleEndian
	var body bytes.Buffer
	for _, c := range chunks {
		c(&body)
	}
	var h bytes.Buffer
	binary.Write(&h, le, uint32(Magic))
	binary.Write(&h, le, uint16(1)) // major
	binary.Write(&h, le, uint16(0)) // minor
	binary.Write(&h, le, uint16(28))
	binary.Write(&h, le, uint16(12))
	binary.Write(&h, le, blkSz)
	binary.Write(&h, le, uint32(0)) // total blocks (unused by decoder)
	binary.Write(&h, le, uint32(len(chunks)))
	binary.Write(&h, le, uint32(0)) // crc
	return append(h.Bytes(), body.Bytes()...)
}

func rawChunk(blkSz uint32, data []byte) func(*bytes.Buffer) {
	return func(b *bytes.Buffer) {
		le := binary.LittleEndian
		binary.Write(b, le, uint16(0xcac1))
		binary.Write(b, le, uint16(0))
		binary.Write(b, le, uint32(uint32(len(data))/blkSz))
		binary.Write(b, le, uint32(12+len(data)))
		b.Write(data)
	}
}

func fillChunk(blocks uint32, val [4]byte) func(*bytes.Buffer) {
	return func(b *bytes.Buffer) {
		le := binary.LittleEndian
		binary.Write(b, le, uint16(0xcac2))
		binary.Write(b, le, uint16(0))
		binary.Write(b, le, blocks)
		binary.Write(b, le, uint32(12+4))
		b.Write(val[:])
	}
}

func dontCareChunk(blocks uint32) func(*bytes.Buffer) {
	return func(b *bytes.Buffer) {
		le := binary.LittleEndian
		binary.Write(b, le, uint16(0xcac3))
		binary.Write(b, le, uint16(0))
		binary.Write(b, le, blocks)
		binary.Write(b, le, uint32(12))
	}
}

func TestDecode(t *testing.T) {
	const blk = 8
	raw := bytes.Repeat([]byte{0xAB}, blk)
	img := buildSparse(blk, []func(*bytes.Buffer){
		rawChunk(blk, raw),
		fillChunk(1, [4]byte{1, 2, 3, 4}),
		dontCareChunk(1),
	})
	got, err := Decode(img)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{}, raw...)
	want = append(want, 1, 2, 3, 4, 1, 2, 3, 4) // fill block (8 bytes)
	want = append(want, make([]byte, blk)...)   // dontcare block
	if !bytes.Equal(got, want) {
		t.Errorf("Decode mismatch:\n got=%x\nwant=%x", got, want)
	}
}

func TestDecodePassthroughNonSparse(t *testing.T) {
	raw := []byte("not a sparse image")
	got, err := Decode(raw)
	if err != nil || !bytes.Equal(got, raw) {
		t.Errorf("non-sparse should pass through unchanged: %x %v", got, err)
	}
	if IsSparse(raw) {
		t.Error("IsSparse false positive")
	}
}

func TestReaderAtMatchesDecode(t *testing.T) {
	blk := uint32(16)
	blob := buildSparse(blk, []func(*bytes.Buffer){
		rawChunk(blk, bytes.Repeat([]byte{0xAB}, 32)), // 2 blocks
		fillChunk(3, [4]byte{1, 2, 3, 4}),             // 3 blocks
		dontCareChunk(4),                              // 4 blocks (zeros)
		rawChunk(blk, bytes.Repeat([]byte{0xCD}, 16)), // 1 block
	})
	// buildSparse writes total_blks=0; set the real count (2+3+4+1=10).
	binary.LittleEndian.PutUint32(blob[16:20], 10)

	want, err := Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	ra, size, err := ReaderAt(blob)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(want)) {
		t.Fatalf("size = %d, want %d", size, len(want))
	}
	for _, w := range [][2]int{{0, len(want)}, {0, 5}, {30, 10}, {78, 20}, {155, 5}} {
		got := make([]byte, w[1])
		n, _ := ra.ReadAt(got, int64(w[0]))
		if !bytes.Equal(got[:n], want[w[0]:w[0]+n]) {
			t.Fatalf("ReadAt(off=%d,len=%d): got %x, want %x", w[0], w[1], got[:n], want[w[0]:w[0]+n])
		}
	}
	// A read straddling the end returns the tail plus io.EOF.
	got := make([]byte, 10)
	if n, err := ra.ReadAt(got, size-3); n != 3 || err != io.EOF {
		t.Fatalf("tail read: n=%d err=%v, want 3, EOF", n, err)
	}
	if _, err := ra.ReadAt(got, size); err != io.EOF {
		t.Fatalf("read at EOF: err=%v, want EOF", err)
	}
}
