package qcdt

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Entry is one device tree in a QCDT table: the board it is for, and its blob.
type Entry struct {
	Platform, Variant, Subtype, SoCRev uint32
	Model                              string // extended tables only
	DTB                                []byte
}

// Parse reads a version-3 QCDT table (LZ4-framed input is unpacked first).
func Parse(data []byte) ([]Entry, error) {
	if isLZ4Frame(data) {
		var err error
		if data, err = lz4Decompress(data); err != nil {
			return nil, fmt.Errorf("lz4 decompress: %w", err)
		}
	}
	if !isQCDT(data) || len(data) < headerSize {
		return nil, fmt.Errorf("qcdt: not a QCDT table")
	}
	if data[4] != 3 {
		return nil, fmt.Errorf("qcdt: version %d not supported", data[4])
	}
	size := baseEntrySize
	if data[5] == 1 {
		size = extEntrySize
	}
	le := binary.LittleEndian
	num := int(le.Uint32(data[8:]))
	if num < 0 || headerSize+num*size > len(data) {
		return nil, fmt.Errorf("qcdt: %d entries exceed %d bytes", num, len(data))
	}
	out := make([]Entry, 0, num)
	for i := 0; i < num; i++ {
		e := data[headerSize+i*size:]
		off, n := int(le.Uint32(e[32:])), int(le.Uint32(e[36:]))
		if off < 0 || n < 0 || off+n > len(data) {
			return nil, fmt.Errorf("qcdt: entry %d runs past the table", i)
		}
		ent := Entry{
			Platform: le.Uint32(e), Variant: le.Uint32(e[4:]), Subtype: le.Uint32(e[8:]),
			SoCRev: le.Uint32(e[12:]), DTB: data[off : off+n],
		}
		if size == extEntrySize {
			ent.Model = string(bytes.TrimRight(e[baseEntrySize:extEntrySize], "\x00"))
		}
		out = append(out, ent)
	}
	return out, nil
}
