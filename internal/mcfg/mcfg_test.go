package mcfg

import (
	"encoding/binary"
	"testing"
)

// build assembles a minimal MCFG blob: header (config type + item count) and an
// MCFG_TRL trailer carrying a name TLV, plus an APN string, wrapped in some
// leading bytes to stand in for the ELF the real file has.
func build(sw bool, items uint32, name, apn string) []byte {
	le := binary.LittleEndian
	b := []byte("\x7fELFpadding-before-the-mcfg-payload")
	hdr := []byte("MCFG")
	fmtType := make([]byte, 2)
	ctype := make([]byte, 2)
	if sw {
		le.PutUint16(ctype, 1)
	}
	n := make([]byte, 4)
	le.PutUint32(n, items)
	hdr = append(hdr, fmtType...)
	hdr = append(hdr, ctype...)
	hdr = append(hdr, n...)
	// A Data_Profiles entry followed by its APN.
	hdr = append(hdr, "/Data_Profiles/Profile0\x00"...)
	hdr = append(hdr, apn...)
	hdr = append(hdr, 0)
	// Trailer: magic, a 2-byte format word, a filler item, then the name TLV.
	trl := []byte("MCFG_TRL\x00\x02")
	trl = append(trl, 0x01, 0x04, 0x00) // some other tag, len 4
	trl = append(trl, 0, 0x19, 0x01, 0x07)
	nl := make([]byte, 2)
	le.PutUint16(nl, uint16(len(name)))
	trl = append(trl, 0x03)    // name tag
	trl = append(trl, nl...)   // len
	trl = append(trl, name...) // value
	return append(b, append(hdr, trl...)...)
}

func TestParse(t *testing.T) {
	c, ok := Parse(build(true, 123, "W-One", "wirelessone.com"))
	if !ok {
		t.Fatal("not parsed")
	}
	if !c.SW || c.NumItems != 123 || c.Profile != "W-One" {
		t.Errorf("sw=%v items=%d profile=%q", c.SW, c.NumItems, c.Profile)
	}
	if len(c.APNs) != 1 || c.APNs[0] != "wirelessone.com" {
		t.Errorf("apns = %v", c.APNs)
	}

	hw, _ := Parse(build(false, 16, "cmcc_subsidized-Divar", ""))
	if hw.SW || hw.Profile != "cmcc_subsidized-Divar" {
		t.Errorf("hw: sw=%v profile=%q", hw.SW, hw.Profile)
	}

	if _, ok := Parse([]byte("no mcfg here")); ok {
		t.Error("false positive on non-mcfg")
	}
	// A blob whose only MCFG hit is inside MCFG_TRL is not a header.
	if _, ok := Parse([]byte("prefix MCFG_TRL only")); ok {
		t.Error("MCFG_TRL alone must not parse as a header")
	}
}

// The ePDG loopback FQDN is not a carrier APN and must be filtered.
func TestQualcommFQDNExcluded(t *testing.T) {
	c, _ := Parse(build(true, 1, "X", "swu-loopback-epdg.qualcomm.com"))
	if len(c.APNs) != 0 {
		t.Errorf("qualcomm.com should be excluded: %v", c.APNs)
	}
}
