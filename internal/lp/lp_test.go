package lp

import (
	"encoding/binary"
	"testing"
)

func TestIsSuper(t *testing.T) {
	buf := make([]byte, reservedBytes+8)
	if IsSuper(buf) {
		t.Error("zeroed buffer should not be super")
	}
	binary.LittleEndian.PutUint32(buf[reservedBytes:], geometryMagic)
	if !IsSuper(buf) {
		t.Error("geometry magic should identify super")
	}
	if _, err := Parse(buf); err == nil {
		t.Error("Parse should fail without a metadata header")
	}
}

// TestParseExtentOffset builds a minimal super metadata with one partition and
// one linear extent, checking that OffsetBytes comes from the extent's
// target_data (packed at offset 12, the field that was misread as 0).
func TestParseExtentOffset(t *testing.T) {
	le := binary.LittleEndian
	metaStart := reservedBytes + 2*geometrySize
	const headerSize = 128
	buf := make([]byte, metaStart+headerSize+256)
	le.PutUint32(buf[reservedBytes:], geometryMagic)

	h := buf[metaStart:]
	le.PutUint32(h[0:], headerMagic)
	le.PutUint32(h[8:], headerSize)
	// descriptors at h[80:]: partitions{off,num,entry}, extents, groups
	d := h[80:]
	le.PutUint32(d[0:], 0)   // pOff
	le.PutUint32(d[4:], 1)   // pNum
	le.PutUint32(d[8:], 52)  // pEntry
	le.PutUint32(d[12:], 52) // eOff
	le.PutUint32(d[16:], 1)  // eNum
	le.PutUint32(d[20:], 24) // eEntry
	le.PutUint32(d[24:], 76) // gOff
	le.PutUint32(d[28:], 1)  // gNum
	le.PutUint32(d[32:], 36) // gEntry

	tables := buf[metaStart+headerSize:]
	copy(tables[0:36], "system")
	le.PutUint32(tables[40:], 0) // first_extent
	le.PutUint32(tables[44:], 1) // num_extents
	le.PutUint32(tables[48:], 0) // group
	// extent at 52: num_sectors=1000, target_type=0 (linear), target_data=2048
	le.PutUint64(tables[52:], 1000)
	le.PutUint32(tables[60:], extentLinear)
	le.PutUint64(tables[64:], 2048) // target_data (offset 12 within the extent)

	m, err := Parse(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Partitions) != 1 {
		t.Fatalf("partitions: %+v", m.Partitions)
	}
	p := m.Partitions[0]
	if p.Name != "system" || p.SizeBytes != 1000*sectorSize || p.OffsetBytes != 2048*sectorSize {
		t.Fatalf("got %+v, want system size=%d off=%d", p, 1000*sectorSize, 2048*sectorSize)
	}
}
