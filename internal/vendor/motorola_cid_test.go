package vendor

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

// Real fogona stock templates: value -> sha1(cid_template.dat).
var known = map[uint16]string{
	0x0033: "203f5d39f0aedefe6279ddf7cb32426b6cbb1073", // cid51 (Tracfone)
	0x0032: "cfc1136c36955ba5ffe514efdf0037e95e47bef3", // cid50 (CC/CCAWS)
}

func TestBuildMatchesStockTemplates(t *testing.T) {
	for val, want := range known {
		got := sha1.Sum(CIDBuild(val))
		if h := hex.EncodeToString(got[:]); h != want {
			t.Errorf("CIDBuild(%#04x) sha1=%s, want %s", val, h, want)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	for val := range known {
		got, err := CIDParse(CIDBuild(val))
		if err != nil {
			t.Fatalf("CIDParse(CIDBuild(%#04x)): %v", val, err)
		}
		if got != val {
			t.Errorf("round trip: got %#04x, want %#04x", got, val)
		}
	}
}

func TestParseRejectsWrongSize(t *testing.T) {
	if _, err := CIDParse(make([]byte, 10)); err == nil {
		t.Error("expected error for short image")
	}
}

func TestVersionAndCIDIsSigned(t *testing.T) {
	// version-0 image this package builds
	v0 := CIDBuild(0x0032)
	if v, ok := CIDVersion(v0); !ok || v != 0 {
		t.Errorf("CIDBuild() version: got %d ok=%v, want 0", v, ok)
	}
	if CIDIsSigned(v0) {
		t.Error("version-0 image must not be reported as signed")
	}
	// version-2 header from a live secure-production fogona cid partition
	v2 := []byte{0x00, 0xf0, 0x00, 0x02, 0x00, 0x00, 0x00, 0x70, 0x16, 0x6e, 0xbd, 0x05}
	if v, ok := CIDVersion(v2); !ok || v != 2 {
		t.Errorf("v2 version: got %d ok=%v, want 2", v, ok)
	}
	if !CIDIsSigned(v2) {
		t.Error("version-2 image must be reported as signed")
	}
	// non-CID data
	if _, ok := CIDVersion([]byte{0xde, 0xad}); ok {
		t.Error("non-0x00F0 data must not parse as a CID version")
	}
}

func TestParseHABMeta(t *testing.T) {
	cases := []struct {
		name     string
		blob     []byte
		codename string
		cid      uint16
		ok       bool
	}{
		{"avb-nul-separated", append([]byte("\x00\x10prop"), append([]byte("HAB_META\x00eqs_50\x00"), []byte("rest")...)...), "eqs", 50, true},
		{"contiguous", []byte("....HAB_METAfogona_51...."), "fogona", 51, true},
		{"underscored-codename", []byte("HAB_META\x00rav_ov_50\x00"), "rav_ov", 50, true},
		{"absent", []byte("no marker here"), "", 0, false},
		{"no-cid", []byte("HAB_META\x00eqs\x00"), "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := ParseHABMeta(tc.blob)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
			if ok && (m.Codename != tc.codename || m.CID != tc.cid) {
				t.Errorf("got %q/%d, want %q/%d", m.Codename, m.CID, tc.codename, tc.cid)
			}
		})
	}
	if got := (HABMeta{CID: 50}).CIDHex(); got != "0x0032" {
		t.Errorf("CIDHex = %q, want 0x0032", got)
	}
}
