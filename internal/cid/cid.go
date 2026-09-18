// Package cid builds Motorola CID (carrier/customer ID) partition images. The
// CID partition encodes only the software channel: a fixed 44-byte template
// whose sole variable is a big-endian 16-bit value at offset 0x2a. Every stock
// channel image is byte-identical except that field (e.g. cid50 vs cid51 from
// Motorola's flashfile), and nothing on-device signs or hashes it, so a chosen
// channel can be written directly. See the fogona stock cid_template.dat.
package cid

import (
	"encoding/binary"
	"fmt"
)

// Size is the CID partition image length (0x2c), matching the header's declared
// length field.
const Size = 0x2c

// valueOffset is where the 16-bit big-endian channel value lives.
const valueOffset = 0x2a

// header is the invariant prefix shared by every stock CID image: bytes 0x00-0x07
// (0x2c at offset 7 is the length). The remainder up to valueOffset is zero.
var header = []byte{0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c}

// Build returns the 44-byte CID image carrying value (e.g. 0x33 for cid51).
func Build(value uint16) []byte {
	buf := make([]byte, Size)
	copy(buf, header)
	binary.BigEndian.PutUint16(buf[valueOffset:], value)
	return buf
}

// Parse returns the channel value from a CID image, rejecting one whose length
// or header does not match a known-good template.
func Parse(img []byte) (uint16, error) {
	if len(img) != Size {
		return 0, fmt.Errorf("cid image is %d bytes, want %d", len(img), Size)
	}
	for i, b := range header {
		if img[i] != b {
			return 0, fmt.Errorf("cid header mismatch at 0x%02x: %#02x != %#02x", i, img[i], b)
		}
	}
	return binary.BigEndian.Uint16(img[valueOffset:]), nil
}
