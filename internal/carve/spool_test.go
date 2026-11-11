package carve

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
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

func TestReaderAtSpillsAnUnknownSizeStreamToDisk(t *testing.T) {
	oldSpill := memSpill
	t.Cleanup(func() { memSpill = oldSpill })
	memSpill = 1024
	body := bytes.Repeat([]byte("0123456789abcdef"), 1024)
	for _, c := range []struct {
		name string
		body []byte
		file bool
	}{{"small stays in memory", body[:100], false}, {"large spills", body, true}} {
		n := FromStream("s", -1, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(c.body)), nil })
		ra, err := n.ReaderAt()
		if err != nil {
			t.Fatal(c.name, err)
		}
		_, isFile := ra.(*os.File)
		got := make([]byte, len(c.body))
		if _, err := ra.ReadAt(got, 0); err != nil && err != io.EOF {
			t.Fatal(c.name, err)
		}
		if isFile != c.file || !bytes.Equal(got, c.body) || n.Size != int64(len(c.body)) {
			t.Errorf("%s: file=%v size=%d", c.name, isFile, n.Size)
		}
	}
}

func TestHostDecompressMatchesGo(t *testing.T) {
	bz, _ := hex.DecodeString("425a68393141592653590b8fd0cf0000008f8040003000010002001c0020002190c210c08da9472f8bb9229c284805c7e86780")
	for _, c := range []struct {
		name, format string
		in           []byte
		want         string
		fails        bool
	}{
		{"bzip2", "bzip2", bz, "AVB0rest", false},
		{"bzip2 trailing garbage is a warning", "bzip2", append(append([]byte{}, bz...), "junk"...), "AVB0rest", false},
		{"bzip2 corrupt", "bzip2", bz[:len(bz)-8], "", true},
	} {
		if hostTool(c.format) == nil {
			t.Skip("no host " + c.format)
		}
		rc, ok := hostDecompress(c.format, bytes.NewReader(c.in))
		if !ok {
			t.Fatal(c.name, "not run")
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if (err != nil) != c.fails || (!c.fails && string(got) != c.want) {
			t.Errorf("%s: got %q err %v", c.name, got, err)
		}
	}
	old := HostDecomp
	defer func() { HostDecomp = old }()
	HostDecomp = false
	if _, ok := hostDecompress("bzip2", bytes.NewReader(bz)); ok {
		t.Error("HostDecomp=false still ran a host tool")
	}
}
