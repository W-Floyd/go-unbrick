package carve

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// sparseChunk builds one super sparsechunk: a sparse file for the whole image
// that carries block data at index own and don't-care elsewhere.
func sparseChunk(blocks, own int, data []byte) []byte {
	const blk = 4096
	le := binary.LittleEndian
	var body bytes.Buffer
	count := 0
	dontCare := func(n int) {
		binary.Write(&body, le, uint16(0xcac3))
		binary.Write(&body, le, uint16(0))
		binary.Write(&body, le, uint32(n))
		binary.Write(&body, le, uint32(12))
		count++
	}
	// Layout: own blocks of don't-care, one raw block, the rest don't-care.
	if own > 0 {
		dontCare(own)
	}
	binary.Write(&body, le, uint16(0xcac1))
	binary.Write(&body, le, uint16(0))
	binary.Write(&body, le, uint32(1))
	binary.Write(&body, le, uint32(12+blk))
	body.Write(append(append([]byte{}, data...), make([]byte, blk-len(data))...))
	count++
	if rest := blocks - own - 1; rest > 0 {
		dontCare(rest)
	}

	var out bytes.Buffer
	binary.Write(&out, le, uint32(0xed26ff3a))
	binary.Write(&out, le, [4]uint16{1, 0, 28, 12})
	binary.Write(&out, le, uint32(blk))
	binary.Write(&out, le, uint32(blocks))
	binary.Write(&out, le, uint32(count))
	binary.Write(&out, le, uint32(0))
	return append(out.Bytes(), body.Bytes()...)
}

// Each deflated chunk is unpacked to a temp file, several at once; the image
// they overlay into must be the same as a serial unpack, and the person running
// the command must be told it is happening.
func TestSuperChunksUnpackInParallelAndReport(t *testing.T) {
	const n = 9
	var nodes []*Node
	for i := 0; i < n; i++ {
		blob := sparseChunk(n, i, []byte(fmt.Sprintf("chunk-%d", i)))
		nodes = append(nodes, FromStream(fmt.Sprintf("super.img_sparsechunk.%d", i), int64(len(blob)),
			func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(blob)), nil }))
	}
	nodes = append(nodes, FromBytes("other.bin", []byte("x")))

	var mu sync.Mutex
	var msgs []string
	Progress = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, fmt.Sprintf(f, a...))
	}
	defer func() { Progress = nil }()

	out := joinSuperChunks(nodes)
	var super *Node
	for _, k := range out {
		if k.Name == "super.img" {
			super = k
		}
		if strings.HasPrefix(k.Name, "super.img_sparsechunk") {
			t.Errorf("chunk %s left beside the joined image", k.Name)
		}
	}
	if super == nil || super.Size != int64(n*4096) {
		t.Fatalf("no joined super of %d bytes: %+v", n*4096, super)
	}
	at, err := super.ReaderAt()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		got := make([]byte, 8)
		if _, err := at.ReadAt(got, int64(i*4096)); err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("chunk-%d", i); string(got[:len(want)]) != want {
			t.Errorf("block %d = %q, want %q", i, got, want)
		}
	}
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined, "unpacking the super image") || !strings.Contains(joined, "unpacked 9 of 9 chunks") {
		t.Errorf("progress:\n%s", joined)
	}
}
