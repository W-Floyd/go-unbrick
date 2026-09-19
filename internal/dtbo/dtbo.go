// Package dtbo parses the Android DTB/DTBO table image (dt_table_header, magic
// 0xd7b7ab1e, big-endian) that packs multiple device trees (a dtbo.img or a
// concatenated dtb.img). It reads the table of contents — one entry per DT, with
// the SoC/board id and revision each is selected by.
package dtbo

import (
	"encoding/binary"
	"fmt"
)

const magic = 0xd7b7ab1e

// Entry is one device tree in the table.
type Entry struct {
	Size   uint32
	Offset uint32
	ID     uint32 // platform/SoC id
	Rev    uint32 // board revision
}

// Table is the parsed dt_table_header plus its entries.
type Table struct {
	Version uint32
	Entries []Entry
}

// Parse reads the table header and entry list from a full image.
func Parse(data []byte) (*Table, error) {
	if len(data) < 32 || binary.BigEndian.Uint32(data[:4]) != magic {
		return nil, fmt.Errorf("dtbo: not a DT table image")
	}
	be := binary.BigEndian
	entrySize := be.Uint32(data[12:16])
	count := be.Uint32(data[16:20])
	entriesOff := be.Uint32(data[20:24])
	version := be.Uint32(data[28:32])
	if entrySize < 16 {
		return nil, fmt.Errorf("dtbo: implausible entry size %d", entrySize)
	}
	t := &Table{Version: version}
	for i := uint32(0); i < count; i++ {
		off := int(entriesOff + i*entrySize)
		if off+16 > len(data) {
			break
		}
		t.Entries = append(t.Entries, Entry{
			Size:   be.Uint32(data[off : off+4]),
			Offset: be.Uint32(data[off+4 : off+8]),
			ID:     be.Uint32(data[off+8 : off+12]),
			Rev:    be.Uint32(data[off+12 : off+16]),
		})
	}
	return t, nil
}
