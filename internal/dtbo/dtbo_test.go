package dtbo

import (
	"encoding/binary"
	"testing"
)

func TestParse(t *testing.T) {
	be := binary.BigEndian
	hdr := make([]byte, 32)
	be.PutUint32(hdr[0:], magic)
	be.PutUint32(hdr[12:], 16) // entry size
	be.PutUint32(hdr[16:], 2)  // count
	be.PutUint32(hdr[20:], 32) // entries offset
	be.PutUint32(hdr[28:], 0)  // version
	e := make([]byte, 32)
	be.PutUint32(e[0:], 1000)      // size
	be.PutUint32(e[8:], 0x6225)    // id
	be.PutUint32(e[12:], 0x1)      // rev
	be.PutUint32(e[16+8:], 0x6226) // 2nd entry id
	data := append(hdr, e...)

	tbl, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Entries) != 2 || tbl.Entries[0].ID != 0x6225 || tbl.Entries[1].ID != 0x6226 {
		t.Errorf("entries wrong: %+v", tbl.Entries)
	}
	if _, err := Parse([]byte("nope")); err == nil {
		t.Error("expected error for non-dtbo")
	}
}
