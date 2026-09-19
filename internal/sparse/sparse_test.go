package sparse

import (
	"bytes"
	"encoding/binary"
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
