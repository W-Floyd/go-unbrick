package bootimg

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/pierrec/lz4/v4"
)

// legacyLZ4 builds an LZ4 legacy stream from chunks, as `lz4 -l` or a kernel build does.
func legacyLZ4(t *testing.T, chunks ...[]byte) []byte {
	t.Helper()
	b := []byte{0x02, 0x21, 0x4c, 0x18}
	for _, c := range chunks {
		dst := make([]byte, lz4.CompressBlockBound(len(c)))
		n, err := lz4.CompressBlock(c, dst, nil)
		if err != nil || n == 0 {
			t.Fatalf("compress: %d %v", n, err)
		}
		var size [4]byte
		binary.LittleEndian.PutUint32(size[:], uint32(n))
		b = append(append(b, size[:]...), dst[:n]...)
	}
	return b
}

func TestDecompressLZ4LegacyEndsAtPadding(t *testing.T) {
	a := bytes.Repeat([]byte("070701 first chunk "), 400)
	c := bytes.Repeat([]byte("second chunk of the stream "), 300)
	stream := legacyLZ4(t, a, c)
	padded := append(append([]byte(nil), stream...), make([]byte, 5000)...) // a partition's zeros

	out, used, err := DecompressLZ4Legacy(padded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, append(append([]byte(nil), a...), c...)) {
		t.Errorf("content differs: %d bytes", len(out))
	}
	if used != len(stream) {
		t.Errorf("used %d, the stream is %d", used, len(stream))
	}
	// A concatenated stream is followed.
	out, _, err = DecompressLZ4Legacy(append(append([]byte(nil), stream...), legacyLZ4(t, a)...))
	if err != nil || len(out) != len(a)+len(c)+len(a) {
		t.Errorf("concatenated: %d bytes, %v", len(out), err)
	}
	// And the ramdisk path takes it rather than failing on the padding.
	rd, codec, err := DecompressRamdisk(padded)
	if err != nil || codec != CodecLZ4 || len(rd) != len(a)+len(c) {
		t.Errorf("DecompressRamdisk: %d bytes, %s, %v", len(rd), codec, err)
	}
}

func TestDecompressLZ4LegacyRejects(t *testing.T) {
	if _, _, err := DecompressLZ4Legacy([]byte("070701 not lz4")); err == nil {
		t.Error("a non-stream was accepted")
	}
	if _, _, err := DecompressLZ4Legacy([]byte{0x02, 0x21, 0x4c, 0x18}); err == nil {
		t.Error("an empty stream was accepted")
	}
	bad := append([]byte{0x02, 0x21, 0x4c, 0x18, 8, 0, 0, 0}, bytes.Repeat([]byte{0xff}, 8)...)
	if _, _, err := DecompressLZ4Legacy(bad); err == nil {
		t.Error("a corrupt first block was accepted")
	}
	if !IsLZ4Legacy([]byte{0x02, 0x21, 0x4c, 0x18, 1}) || IsLZ4Legacy([]byte{0x04, 0x22, 0x4d, 0x18}) {
		t.Error("IsLZ4Legacy")
	}
}
