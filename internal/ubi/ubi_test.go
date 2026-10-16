package ubi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// peb writes one eraseblock: EC header, VID header at 64, data at 128.
func peb(size int, vol, lnum uint32, sq uint64, data []byte) []byte {
	b := bytes.Repeat([]byte{0xff}, size)
	copy(b, ecMagic)
	for i := 4; i < 64; i++ {
		b[i] = 0
	}
	binary.BigEndian.PutUint32(b[16:], 64)
	binary.BigEndian.PutUint32(b[20:], 128)
	copy(b[64:], vidMagic)
	b[69] = 1
	binary.BigEndian.PutUint32(b[72:], vol)
	binary.BigEndian.PutUint32(b[76:], lnum)
	binary.BigEndian.PutUint64(b[104:], sq)
	copy(b[128:], data)
	return b
}

func TestParse(t *testing.T) {
	const size = 16 << 10
	tbl := make([]byte, volRecordSize*2)
	binary.BigEndian.PutUint32(tbl[volRecordSize:], 2) // vol 1: 2 LEBs
	tbl[volRecordSize+12] = 1
	binary.BigEndian.PutUint16(tbl[volRecordSize+14:], 6)
	copy(tbl[volRecordSize+16:], "rootfs")
	var img []byte
	img = append(img, peb(size, layoutVolID, 0, 1, tbl)...)
	img = append(img, peb(size, 1, 0, 2, []byte("old"))...)
	img = append(img, peb(size, 1, 0, 3, []byte("new"))...) // supersedes
	img = append(img, peb(size, 1, 1, 4, []byte("tail"))...)
	im, err := Parse(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if im.PEBSize != size || len(im.Volumes) != 1 || im.Volumes[0].Name != "rootfs" {
		t.Fatalf("got %+v", im)
	}
	v := im.Volumes[0]
	if v.Size != 2*(size-128) {
		t.Errorf("size %d", v.Size)
	}
	got := make([]byte, 3)
	v.ReadAt(got, 0)
	if string(got) != "new" {
		t.Errorf("leb 0 reads %q", got)
	}
	v.ReadAt(got[:1], int64(size-128))
	if got[0] != 't' {
		t.Errorf("leb 1 reads %q", got[:1])
	}
}
