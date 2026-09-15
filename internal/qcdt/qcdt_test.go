package qcdt

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/pierrec/lz4/v4"
)

// makeExtendedQCDT builds a synthetic extended-v3 QCDT: header, n 72-byte entries
// (first 40 bytes distinguishable, last 32 a model string), then a DTB region.
func makeExtendedQCDT(n int, dtb []byte) []byte {
	b := make([]byte, headerSize)
	copy(b, magic)
	b[4] = 3 // version
	b[5] = 1 // extended
	binary.LittleEndian.PutUint32(b[8:], uint32(n))
	for i := 0; i < n; i++ {
		entry := make([]byte, extEntrySize)
		binary.LittleEndian.PutUint32(entry[0:], uint32(0x1000+i)) // platform_id
		binary.LittleEndian.PutUint32(entry[32:], uint32(0xABCD))  // last of first-40 region
		copy(entry[baseEntrySize:], []byte("some-model-string"))   // model[32]
		b = append(b, entry...)
	}
	return append(b, dtb...)
}

func TestStripModel(t *testing.T) {
	dtb := []byte("\xd0\x0d\xfe\xedDEVICE-TREE-BLOBS")
	in := makeExtendedQCDT(3, dtb)
	out, changed, err := StripModel(in)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true for extended QCDT")
	}
	if len(out) != len(in) {
		t.Errorf("size not preserved: in=%d out=%d", len(in), len(out))
	}
	if out[5] != 0 {
		t.Error("extended flag not cleared")
	}
	// entries are now 40 bytes at the front; first-40 fields preserved.
	for i := 0; i < 3; i++ {
		e := headerSize + i*baseEntrySize
		if got := binary.LittleEndian.Uint32(out[e:]); got != uint32(0x1000+i) {
			t.Errorf("entry %d platform_id: got %#x", i, got)
		}
	}
	// no model string survives anywhere.
	if bytes.Contains(out, []byte("some-model-string")) {
		t.Error("model string not stripped")
	}
	// DTB region untouched at the same absolute offset.
	if !bytes.HasSuffix(out, dtb) {
		t.Error("DTB region altered")
	}
}

func TestStripModelLZ4(t *testing.T) {
	in := makeExtendedQCDT(2, []byte("DTBS"))
	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	w.Write(in)
	w.Close()

	out, changed, err := StripModel(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed for LZ4-framed extended QCDT")
	}
	if out[5] != 0 || bytes.Contains(out, []byte("some-model-string")) {
		t.Error("LZ4 path did not strip correctly")
	}
}

func TestStripModelNoOp(t *testing.T) {
	// Not a QCDT.
	if _, changed, err := StripModel([]byte("\x7fELFnope")); err != nil || changed {
		t.Errorf("non-QCDT should be a no-op: changed=%v err=%v", changed, err)
	}
	// A non-extended QCDT: extended flag 0 -> nothing to strip.
	nonExt := makeExtendedQCDT(1, []byte("x"))
	nonExt[5] = 0
	if _, changed, _ := StripModel(nonExt); changed {
		t.Error("non-extended QCDT should not change")
	}
}
