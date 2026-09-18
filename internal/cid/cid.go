// Package cid builds Motorola CID (carrier/customer ID) partition images.
//
// There are two on-device formats, distinguished by the u16 version at offset
// 0x02 of the 8-byte header (magic 0x00F0, version, then a u32 BE length):
//
//   - Version 0 — the 44-byte unsigned template this package builds. Header
//     "00 f0 00 00 00 00 00 2c", the sole variable a u16 BE channel at 0x2a.
//     Nothing signs or hashes it, so a chosen channel can be written directly.
//     This is the stock cid_template.dat / flashfile form (cid50 vs cid51).
//   - Version 2 — a signed structure seen on secure-production devices (e.g. a
//     live fogona). Header "00 f0 00 02 00 00 00 70" (length 0x70), carrying the
//     chip serial, SoC id, CID value, device serial and product name, followed
//     by a ~176-byte opaque signature/cert block that is NOT a recomputable hash
//     (it needs Motorola's PKI key — this is the cid_prov_data the after-sales
//     server mints, see cmd_fastboot's cid_prov_req decoding).
//
// Consequence for callers: writing the version-0 image over a device already on
// version 2 is a format downgrade whose acceptance by ABL is unverified — it may
// be read as a valid unsigned cid, or rejected as tampered (CarrierID 0xDEAD,
// which blocks AP fastboot). Detect the target's version (Version below, or the
// recon cid_prov_req format) before overwriting a secure-production cid.
package cid

import (
	"encoding/binary"
	"fmt"
)

// Size is the version-0 CID image length (0x2c), matching its header length field.
const Size = 0x2c

// valueOffset is where the version-0 16-bit big-endian channel value lives.
const valueOffset = 0x2a

// header is the version-0 prefix: magic 0x00F0, version 0, u32 BE length 0x2c.
var header = []byte{0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c}

// Version reads the CID format version (u16 BE at 0x02): 0 = the unsigned
// template this package writes, 2 = the signed secure-production structure.
// Returns false if the image is too short or lacks the 0x00F0 magic.
func Version(img []byte) (uint16, bool) {
	if len(img) < 4 || img[0] != 0x00 || img[1] != 0xf0 {
		return 0, false
	}
	return binary.BigEndian.Uint16(img[2:4]), true
}

// IsSigned reports whether img is a signed (version >= 2) CID that must not be
// overwritten with an unsigned version-0 image.
func IsSigned(img []byte) bool {
	v, ok := Version(img)
	return ok && v >= 2
}

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
