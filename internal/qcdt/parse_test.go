package qcdt

import (
	"encoding/binary"
	"testing"
)

func TestParse(t *testing.T) {
	le := binary.LittleEndian
	const n = 2
	b := make([]byte, headerSize+n*baseEntrySize)
	copy(b, "QCDT")
	b[4] = 3
	le.PutUint32(b[8:], n)
	for i, plat := range []uint32{0x122, 0x128} {
		e := b[headerSize+i*baseEntrySize:]
		le.PutUint32(e, plat)
		le.PutUint32(e[4:], uint32(i+1))
		le.PutUint32(e[32:], uint32(len(b)+i*3))
		le.PutUint32(e[36:], 3)
	}
	b = append(b, "aaabbb"...)
	es, err := Parse(b)
	if err != nil || len(es) != 2 {
		t.Fatalf("got %v, %v", es, err)
	}
	if es[0].Platform != 0x122 || string(es[0].DTB) != "aaa" || es[1].Variant != 2 || string(es[1].DTB) != "bbb" {
		t.Errorf("entries %+v", es)
	}
	if _, err := Parse(b[:20]); err == nil {
		t.Error("truncated table parsed")
	}
}
