package npkg

import (
	"encoding/hex"
	"strings"
	"testing"
)

// decode is a hex string of bytes, for a test fixture written as hex for
// readability (these are the exact bytes a real header's fixed+table part has).
func decode(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// These two fixtures are the real header shapes this package's doc comment
// describes: a one-section package (as seen on oem_nimo_language.npkg) and a
// two-section package (as seen on every oem_std5_*.npkg sample), built the same
// way the real files are, byte for byte, down to the same timestamp text.
const (
	oneSectionHex = "50524e4de803000001000000323032362f30312f31342030343a35313a32310080d35ec62c000000f0a7b200"
	twoSectionHex = "50524e4de803000002000000323032362f30312f31342030343a35313a323100bb48d44b38000000640000000272d44b9c0000002c000000"
)

func TestParseOneSection(t *testing.T) {
	h := decode(t, oneSectionHex)
	if !Is(h) {
		t.Fatal("Is() false on a real header")
	}
	p, err := Parse(h, 44+11708400)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1000 || p.Timestamp != "2026/01/14 04:51:21" || p.HeaderEnd != 44 {
		t.Errorf("%+v", p)
	}
	if len(p.Sections) != 1 || p.Sections[0].Offset != 44 || p.Sections[0].Size != 11708400 {
		t.Errorf("sections: %+v", p.Sections)
	}
	if !strings.Contains(p.Summary(), "1 section") {
		t.Errorf("summary: %q", p.Summary())
	}
}

func TestParseTwoSections(t *testing.T) {
	h := decode(t, twoSectionHex)
	p, err := Parse(h, 56+100+44)
	if err != nil {
		t.Fatal(err)
	}
	if p.HeaderEnd != 56 || len(p.Sections) != 2 {
		t.Fatalf("%+v", p)
	}
	if p.Sections[0] != (Section{Tag: 1272203451, Offset: 56, Size: 100}) {
		t.Errorf("section 0: %+v", p.Sections[0])
	}
	if p.Sections[1] != (Section{Tag: 1272214018, Offset: 156, Size: 44}) {
		t.Errorf("section 1: %+v", p.Sections[1])
	}
	if !strings.Contains(p.Summary(), "2 sections") {
		t.Errorf("summary: %q", p.Summary())
	}
}

func TestParseRejectsWrongSize(t *testing.T) {
	h := decode(t, oneSectionHex)
	if _, err := Parse(h, 44+11708400+1); err == nil {
		t.Error("a size that doesn't match the sections should be refused")
	}
	if _, err := Parse(h, 0); err != nil {
		t.Errorf("size 0 means unchecked, should not error: %v", err)
	}
}

func TestParseRejectsBadMagicOrTruncation(t *testing.T) {
	if Is([]byte("PRN")) {
		t.Error("too short to even hold the magic")
	}
	if Is(append([]byte("XXXX"), make([]byte, 0x1c)...)) {
		t.Error("wrong magic")
	}
	h := decode(t, twoSectionHex)
	if _, err := Parse(h[:40], 0); err == nil {
		t.Error("a header cut short of its own section table should be refused")
	}
}

func TestParseRejectsDiscontiguousSections(t *testing.T) {
	h := decode(t, twoSectionHex)
	// Corrupt section 1's offset so it no longer starts where section 0 ends.
	h[0x20+12+4] = 0xff
	if _, err := Parse(h, 0); err == nil {
		t.Error("a gap/overlap between sections should be refused")
	}
}
