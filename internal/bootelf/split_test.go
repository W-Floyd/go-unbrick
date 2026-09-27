package bootelf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// splitFixture builds a PIL split: an ELF32 whose phdrs are [ELF wrapper,
// hash, load, load], the .mdt (headers + hash) and the .bNN segment files.
func splitFixture() (whole, mdt []byte, segs map[int][]byte) {
	le := binary.LittleEndian
	const phoff, nph = 0x34, 4
	hdrEnd := phoff + nph*32
	type ph struct{ off, size, flags uint32 }
	phs := []ph{{0, uint32(hdrEnd), 0x07000000}, {0x1000, 0x40, 0x02200000}, {0x2000, 0x30, 0x80000005}, {0x3000, 0x20, 0x80000006}}
	whole = make([]byte, 0x3020)
	copy(whole, "\x7fELF\x01\x01\x01")
	le.PutUint16(whole[0x10:], 2)    // ET_EXEC
	le.PutUint16(whole[0x12:], 0xa4) // QDSP6
	le.PutUint32(whole[0x14:], 1)
	le.PutUint32(whole[0x1c:], phoff)
	le.PutUint16(whole[0x28:], 0x34)
	le.PutUint16(whole[0x2a:], 32)
	le.PutUint16(whole[0x2c:], nph)
	segs = map[int][]byte{}
	for i, p := range phs {
		h := whole[phoff+i*32:]
		typ := uint32(1)
		if i < 2 {
			typ = 0
		}
		le.PutUint32(h[0:], typ)
		le.PutUint32(h[4:], p.off)
		le.PutUint32(h[16:], p.size)
		le.PutUint32(h[20:], p.size)
		le.PutUint32(h[24:], p.flags)
		if i > 0 {
			for k := range p.size {
				whole[p.off+k] = byte(i*16 + int(k))
			}
		}
	}
	for i, p := range phs {
		segs[i] = append([]byte(nil), whole[p.off:p.off+p.size]...)
	}
	mdt = append(append([]byte(nil), whole[:hdrEnd]...), segs[1]...)
	return whole, mdt, segs
}

func TestJoinSplit(t *testing.T) {
	whole, mdt, segs := splitFixture()

	img, missing, err := JoinSplit(mdt, func(i int) []byte { return segs[i] })
	if err != nil || len(missing) != 0 || !bytes.Equal(img, whole) {
		t.Fatalf("all segments: err=%v missing=%v equal=%v", err, missing, bytes.Equal(img, whole))
	}

	// With only the .mdt, the hash segment still comes from it.
	img, missing, err = JoinSplit(mdt, func(int) []byte { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 2 || missing[0] != 2 || missing[1] != 3 {
		t.Errorf("missing = %v, want [2 3]", missing)
	}
	if !bytes.Equal(img[0x1000:0x1040], segs[1]) {
		t.Error("hash segment not recovered from the .mdt")
	}

	// A whole ELF passes through untouched.
	if img, missing, err := JoinSplit(whole, func(int) []byte { return nil }); err != nil || len(missing) != 0 || !bytes.Equal(img, whole) {
		t.Errorf("whole ELF: err=%v missing=%v", err, missing)
	}
}
