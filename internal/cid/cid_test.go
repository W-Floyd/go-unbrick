package cid

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
		got := sha1.Sum(Build(val))
		if h := hex.EncodeToString(got[:]); h != want {
			t.Errorf("Build(%#04x) sha1=%s, want %s", val, h, want)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	for val := range known {
		got, err := Parse(Build(val))
		if err != nil {
			t.Fatalf("Parse(Build(%#04x)): %v", val, err)
		}
		if got != val {
			t.Errorf("round trip: got %#04x, want %#04x", got, val)
		}
	}
}

func TestParseRejectsWrongSize(t *testing.T) {
	if _, err := Parse(make([]byte, 10)); err == nil {
		t.Error("expected error for short image")
	}
}

func TestVersionAndIsSigned(t *testing.T) {
	// version-0 image this package builds
	v0 := Build(0x0032)
	if v, ok := Version(v0); !ok || v != 0 {
		t.Errorf("Build() version: got %d ok=%v, want 0", v, ok)
	}
	if IsSigned(v0) {
		t.Error("version-0 image must not be reported as signed")
	}
	// version-2 header from a live secure-production fogona cid partition
	v2 := []byte{0x00, 0xf0, 0x00, 0x02, 0x00, 0x00, 0x00, 0x70, 0x16, 0x6e, 0xbd, 0x05}
	if v, ok := Version(v2); !ok || v != 2 {
		t.Errorf("v2 version: got %d ok=%v, want 2", v, ok)
	}
	if !IsSigned(v2) {
		t.Error("version-2 image must be reported as signed")
	}
	// non-CID data
	if _, ok := Version([]byte{0xde, 0xad}); ok {
		t.Error("non-0x00F0 data must not parse as a CID version")
	}
}
