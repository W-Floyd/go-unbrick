package vendor

// Motorola CID (carrier/customer ID) partition images and the vbmeta HAB_META
// binding — Motorola-specific formats, kept behind the vendor seam.
//
// Two on-device CID formats, by the u16 version at offset 0x02 of the 8-byte
// header (magic 0x00F0, version, u32 BE length):
//
//   - Version 0 — the 44-byte unsigned template (CIDBuild writes it). Header
//     "00 f0 00 00 00 00 00 2c", the sole variable a u16 BE channel at 0x2a.
//     Unsigned, so a chosen channel can be written directly (cid_template.dat).
//   - Version 2 — a signed structure on secure-production devices: chip serial,
//     SoC id, CID, device serial, product name, then an RSA signature and an
//     embedded X.509 chain (the cid_prov_data the after-sales server mints).
//
// Writing a v0 image over a v2 device is a downgrade ABL may reject as tampered
// (CarrierID 0xDEAD, blocking AP fastboot) — detect the version first.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// HABMeta is the device binding a Motorola vbmeta image declares in its HAB_META
// AVB property: the codename and the CID (decimal on disk) the build targets.
type HABMeta struct {
	Codename string
	CID      uint16
}

var habMetaMarker = []byte("HAB_META")

// ParseHABMeta scans a vbmeta image for the HAB_META property, whose value is the
// ASCII string "<codename>_<cid-decimal>" (e.g. "eqs_50" → codename "eqs", CID 50
// = 0x0032). Returns the first well-formed occurrence. AVB stores the property as
// key\0value\0, so the value's leading NUL separator is skipped; a corpus that
// packs it contiguously ("HAB_METAeqs_50") also parses.
func ParseHABMeta(data []byte) (HABMeta, bool) {
	for off := 0; ; {
		j := bytes.Index(data[off:], habMetaMarker)
		if j < 0 {
			return HABMeta{}, false
		}
		start := off + j + len(habMetaMarker)
		for start < len(data) && data[start] == 0x00 { // AVB key\0value separator
			start++
		}
		end := start
		for end < len(data) && isHABTokenByte(data[end]) {
			end++
		}
		if m, ok := splitHABToken(string(data[start:end])); ok {
			return m, true
		}
		off = start
	}
}

func isHABTokenByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// splitHABToken splits "<codename>_<cid>" at its last underscore, so codenames
// that themselves contain underscores (e.g. "rav_ov_50") still resolve.
func splitHABToken(token string) (HABMeta, bool) {
	u := strings.LastIndexByte(token, '_')
	if u <= 0 || u == len(token)-1 {
		return HABMeta{}, false
	}
	n, err := strconv.ParseUint(token[u+1:], 10, 16)
	if err != nil {
		return HABMeta{}, false
	}
	return HABMeta{Codename: token[:u], CID: uint16(n)}, true
}

// CIDHex renders the CID the way fastboot reports it (0xNNNN).
func (m HABMeta) CIDHex() string { return fmt.Sprintf("0x%04X", m.CID) }

// CIDSize is the version-0 CID image length (0x2c), matching its header length.
const CIDSize = 0x2c

// cidValueOffset is where the version-0 16-bit big-endian channel value lives.
const cidValueOffset = 0x2a

// cidHeader is the version-0 prefix: magic 0x00F0, version 0, u32 BE length 0x2c.
var cidHeader = []byte{0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c}

// CIDVersion reads the CID format version (u16 BE at 0x02): 0 = unsigned template,
// 2 = signed secure-production. False if too short or lacking the 0x00F0 magic.
func CIDVersion(img []byte) (uint16, bool) {
	if len(img) < 4 || img[0] != 0x00 || img[1] != 0xf0 {
		return 0, false
	}
	return binary.BigEndian.Uint16(img[2:4]), true
}

// CIDIsSigned reports whether img is a signed (version >= 2) CID that must not be
// overwritten with an unsigned version-0 image.
func CIDIsSigned(img []byte) bool {
	v, ok := CIDVersion(img)
	return ok && v >= 2
}

// CIDBuild returns the 44-byte CID image carrying value (e.g. 0x33 for cid51).
func CIDBuild(value uint16) []byte {
	buf := make([]byte, CIDSize)
	copy(buf, cidHeader)
	binary.BigEndian.PutUint16(buf[cidValueOffset:], value)
	return buf
}

// CIDParse returns the channel value from a CID image, rejecting one whose length
// or header does not match a known-good template.
func CIDParse(img []byte) (uint16, error) {
	if len(img) != CIDSize {
		return 0, fmt.Errorf("cid image is %d bytes, want %d", len(img), CIDSize)
	}
	for i, b := range cidHeader {
		if img[i] != b {
			return 0, fmt.Errorf("cid header mismatch at 0x%02x: %#02x != %#02x", i, img[i], b)
		}
	}
	return binary.BigEndian.Uint16(img[cidValueOffset:]), nil
}
