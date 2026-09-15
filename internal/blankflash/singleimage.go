// Package blankflash builds a device blankflash from a same-SoC sibling's signed loader.
package blankflash

// Codec for Motorola's SINGLE_N_LONELY container.
//
// Both singleimage.bin (a qboot blankflash) and bootloader.img (the packed boot
// chain inside a stock firmware package) use this format, and the gpt.bin of a
// UFS device is itself one of these nested inside the stock package. One codec
// handles all three.
//
// Layout (reverse-engineered, round-trips byte-exact against real images):
//
//	off 0x000  16B  magic "SINGLE_N_LONELY\0", rest of a 0x100 block zero
//	then, per file, a record:
//	  off +0x000  0x100  header: name (NUL-terminated) at 0, u64 LE size at 0xf8
//	  off +0x100  size   content, zero-padded up to the next 0x1000 boundary
//	a final record named "LONELY_N_SINGLE" with size 0 marks the end.
//
// The header carries no offset or checksum: position is implied by walking, and
// the 0x1000 content padding is the only alignment. Names live in the header's
// first 0xf8 bytes, so they cap at 247 bytes.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var Magic = []byte("SINGLE_N_LONELY\x00")

const (
	Trailer = "LONELY_N_SINGLE"
	hdr     = 0x100
	page    = 0x1000
	sizeOff = hdr - 8
)

type Record struct {
	Name string
	Data []byte
}

func pad(n int) int { return (page - n%page) % page }

// Parse walks a container into records, including the trailing sentinel.
func Parse(blob []byte) ([]Record, error) {
	if len(blob) < len(Magic) || !bytes.Equal(blob[:len(Magic)], Magic) {
		return nil, fmt.Errorf("not a SINGLE_N_LONELY container")
	}
	var recs []Record
	p := hdr
	for p+hdr <= len(blob) {
		h := blob[p : p+hdr]
		name := h[:sizeOff]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		if len(name) == 0 { // blank header = past the end
			break
		}
		size := int(binary.LittleEndian.Uint64(h[sizeOff:]))
		start := p + hdr
		if size < 0 || start+size > len(blob) {
			return nil, fmt.Errorf("record %q truncated: want %d, have %d", name, size, len(blob)-start)
		}
		data := make([]byte, size)
		copy(data, blob[start:start+size])
		nm := string(name)
		recs = append(recs, Record{Name: nm, Data: data})
		if nm == Trailer {
			break
		}
		p += hdr + size + pad(size)
	}
	return recs, nil
}

// Build serializes records back into a container, appending the sentinel if absent.
func Build(recs []Record) ([]byte, error) {
	out := make([]byte, hdr)
	copy(out, Magic)
	sawTrailer := false
	for _, r := range recs {
		nb := []byte(r.Name)
		if len(nb) > sizeOff {
			return nil, fmt.Errorf("name too long (%d > %d): %s", len(nb), sizeOff, r.Name)
		}
		h := make([]byte, hdr)
		copy(h, nb)
		binary.LittleEndian.PutUint64(h[sizeOff:], uint64(len(r.Data)))
		out = append(out, h...)
		out = append(out, r.Data...)
		out = append(out, make([]byte, pad(len(r.Data)))...)
		sawTrailer = sawTrailer || r.Name == Trailer
	}
	if !sawTrailer {
		h := make([]byte, hdr)
		copy(h, []byte(Trailer))
		out = append(out, h...)
	}
	return out, nil
}

// WithTrailer returns records with exactly one trailing sentinel.
func WithTrailer(recs []Record) []Record {
	out := make([]Record, 0, len(recs)+1)
	for _, r := range recs {
		if r.Name != Trailer {
			out = append(out, r)
		}
	}
	return append(out, Record{Name: Trailer})
}

// Index maps name -> data, ignoring the sentinel. Last write wins on dupes.
func Index(recs []Record) map[string][]byte {
	m := make(map[string][]byte, len(recs))
	for _, r := range recs {
		if r.Name != Trailer {
			m[r.Name] = r.Data
		}
	}
	return m
}

func IsContainer(blob []byte) bool {
	return len(blob) >= len(Magic) && bytes.Equal(blob[:len(Magic)], Magic)
}
