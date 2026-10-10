package vendor

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// PIT is a Samsung partition information table (.pit), the layout Odin
// flashes against.
type PIT struct {
	// Tag is the header field after "COM_TAR2" (e.g. "SM6350"). Undocumented,
	// and not this device's SoC: an SM6225 a05s package carries "SM6350",
	// apparently a template's. Never a fact about the device.
	Tag     string
	Entries []PITEntry
}

// PITEntry is one partition. Start and Blocks are in the device's blocks.
type PITEntry struct {
	ID            uint32
	Device        uint32 // 8 is UFS
	Start, Blocks uint32
	Name          string
	File          string // the image Odin flashes there, "" for none
}

const (
	pitHeader = 28
	pitEntry  = 132
)

// ParsePIT parses a .pit.
func ParsePIT(data []byte) (*PIT, error) {
	if len(data) < pitHeader || !bytes.HasPrefix(data, pitMagic) {
		return nil, errors.New("not a Samsung PIT")
	}
	le := binary.LittleEndian
	n := int(le.Uint32(data[4:]))
	if n > (len(data)-pitHeader)/pitEntry {
		return nil, errors.New("PIT: truncated")
	}
	p := &PIT{Tag: cstr(data[16:24])}
	for i := range n {
		e := data[pitHeader+i*pitEntry:][:pitEntry]
		p.Entries = append(p.Entries, PITEntry{
			Device: le.Uint32(e[4:]),
			ID:     le.Uint32(e[8:]),
			Start:  le.Uint32(e[20:]),
			Blocks: le.Uint32(e[24:]),
			Name:   cstr(e[36:68]),
			File:   cstr(e[68:100]),
		})
	}
	return p, nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
