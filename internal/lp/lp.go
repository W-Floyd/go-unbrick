// Package lp reads Android's dynamic-partition (liblp) metadata — the map at the
// front of a `super` partition that describes the logical partitions packed
// inside it (system, vendor, product, … per A/B slot) and their extents. The map
// lives in the first ~tens of KiB, so it can be read from just the start of super
// without expanding the whole (multi-GB) image.
package lp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	reservedBytes  = 4096       // LP_PARTITION_RESERVED_BYTES
	geometrySize   = 4096       // LP_METADATA_GEOMETRY_SIZE
	geometryMagic  = 0x616c4467 // "gDla" LE
	headerMagic    = 0x414c5030 // "0PLA" LE
	sectorSize     = 512
	partitionNames = 36 // name field length in an LpMetadataPartition
)

// Partition is one logical partition in super.
type Partition struct {
	Name      string
	SizeBytes uint64
	Group     string
}

// Metadata is the parsed super map.
type Metadata struct {
	MajorVersion uint16
	MinorVersion uint16
	Partitions   []Partition
}

// Parse reads the primary metadata slot from the start of a super image. data
// need only cover the first metadata region (a few tens of KiB is plenty).
func Parse(data []byte) (*Metadata, error) {
	le := binary.LittleEndian
	if len(data) < reservedBytes+geometrySize {
		return nil, fmt.Errorf("lp: too short for geometry")
	}
	geo := data[reservedBytes:]
	if le.Uint32(geo[:4]) != geometryMagic {
		return nil, fmt.Errorf("lp: no geometry magic (not a super image)")
	}
	// metadata slots begin after primary + backup geometry.
	metaStart := reservedBytes + 2*geometrySize
	if len(data) < metaStart+80 {
		return nil, fmt.Errorf("lp: too short for metadata header")
	}
	h := data[metaStart:]
	if le.Uint32(h[:4]) != headerMagic {
		return nil, fmt.Errorf("lp: no metadata header magic")
	}
	m := &Metadata{MajorVersion: le.Uint16(h[4:6]), MinorVersion: le.Uint16(h[6:8])}
	headerSize := le.Uint32(h[8:12])

	// Table descriptors follow header_checksum (offset 12 + 32). Each is
	// {offset u32, num_entries u32, entry_size u32}. Order: partitions, extents,
	// groups, block_devices. tables_size at 44, tables_checksum[32] at 48, then
	// descriptors at 80.
	desc := h[80:]
	pOff, pNum, pEntry := le.Uint32(desc[0:4]), le.Uint32(desc[4:8]), le.Uint32(desc[8:12])
	eOff, _, eEntry := le.Uint32(desc[12:16]), le.Uint32(desc[16:20]), le.Uint32(desc[20:24])
	gOff, gNum, gEntry := le.Uint32(desc[24:28]), le.Uint32(desc[28:32]), le.Uint32(desc[32:36])

	tables := data[metaStart+int(headerSize):]

	// Group names, indexed as partitions reference them.
	groups := make([]string, gNum)
	for i := uint32(0); i < gNum; i++ {
		base := int(gOff + i*gEntry)
		if base+partitionNames > len(tables) {
			break
		}
		groups[i] = cstr(tables[base : base+partitionNames])
	}

	extentSectors := func(idx uint32) uint64 {
		base := int(eOff + idx*eEntry)
		if base+8 > len(tables) {
			return 0
		}
		return le.Uint64(tables[base : base+8]) // num_sectors is first
	}

	for i := uint32(0); i < pNum; i++ {
		base := int(pOff + i*pEntry)
		if base+int(pEntry) > len(tables) {
			break
		}
		e := tables[base:]
		name := cstr(e[:partitionNames])
		firstExtent := le.Uint32(e[40:44])
		numExtents := le.Uint32(e[44:48])
		groupIdx := le.Uint32(e[48:52])
		var sectors uint64
		for x := uint32(0); x < numExtents; x++ {
			sectors += extentSectors(firstExtent + x)
		}
		grp := ""
		if int(groupIdx) < len(groups) {
			grp = groups[groupIdx]
		}
		m.Partitions = append(m.Partitions, Partition{Name: name, SizeBytes: sectors * sectorSize, Group: grp})
	}
	return m, nil
}

// IsSuper reports whether data begins with a super partition (liblp geometry).
func IsSuper(data []byte) bool {
	return len(data) >= reservedBytes+4 &&
		binary.LittleEndian.Uint32(data[reservedBytes:reservedBytes+4]) == geometryMagic
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
