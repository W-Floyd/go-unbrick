package carve

import (
	"bytes"
	"io"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/infile"
)

func TestReaderAtSpoolsAStreamOnlyNodeTooBigForMemory(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789abcdef"), 1024)
	node := FromStream("big", int64(len(body)), func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil })

	oldMax, oldFull := MaxBuffer, infile.FullDownload
	t.Cleanup(func() { MaxBuffer, infile.FullDownload = oldMax, oldFull })
	MaxBuffer = 1024

	if _, err := FromStream("big", int64(len(body)), node.stream).ReaderAt(); err == nil {
		t.Error("without --full-download an oversize stream must be refused")
	}
	infile.FullDownload = true
	ra, err := node.ReaderAt()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 32)
	if _, err := ra.ReadAt(got, 8000); err != nil || !bytes.Equal(got, body[8000:8032]) {
		t.Errorf("read %q err %v", got, err)
	}
}
