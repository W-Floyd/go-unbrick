package telechips

import (
	"encoding/binary"
	"os"
	"testing"
)

// lkromImage builds a synthetic "ANDROID@TCSBLBS_" image: a header, a table
// of 9 (offset,size) pairs tiling [0x200, end) with no gaps, matching the
// shape a real image has (see lkrom.go's doc comment) but with placeholder
// content -- just enough for each entry's own first bytes to be read.
func lkromImage(t *testing.T) []byte {
	t.Helper()
	// Nine ranges (matching lkromEntryCount), in file order, sized
	// arbitrarily but contiguous from 0x200.
	bounds := []uint64{0x200, 0x400, 0x1000, 0x1100, 0x2100, 0x2200, 0x2300, 0x2400, 0x3000, 0x3100}
	if len(bounds) != lkromEntryCount+1 {
		t.Fatalf("test bug: %d ranges for %d table entries", len(bounds)-1, lkromEntryCount)
	}
	img := make([]byte, bounds[len(bounds)-1])
	copy(img, "ANDROID@")
	copy(img[0x18:], "V7  TEST")
	// Table order deliberately NOT the same as file order, mirroring the real
	// image: slot 0 names the LAST range, the last slot names the FIRST.
	order := []int{8, 7, 6, 5, 4, 3, 2, 1, 0}
	le := binary.LittleEndian
	for slot, rangeIdx := range order {
		off := lkromTableOff + slot*lkromEntrySize
		start := bounds[rangeIdx]
		size := bounds[rangeIdx+1] - start
		le.PutUint64(img[off:], start)
		le.PutUint64(img[off+8:], size)
	}
	copy(img[0x400:], "BL1C@TESTTAG")
	copy(img[0x2200:], "Ver:LB__")
	return img
}

func TestParseLKROM(t *testing.T) {
	img := lkromImage(t)
	if !IsLKROM(img) || IsLKROM(img[:4]) || IsLKROM([]byte("ANDROID@")) {
		t.Fatal("IsLKROM")
	}
	lk, err := ParseLKROM(img)
	if err != nil {
		t.Fatal(err)
	}
	if lk.VersionTag != "V7  TEST" {
		t.Errorf("version tag: %q", lk.VersionTag)
	}
	if len(lk.Entries) != lkromEntryCount {
		t.Fatalf("entries: got %d, want %d", len(lk.Entries), lkromEntryCount)
	}
	if !lk.Contiguous() {
		t.Error("synthetic image should tile contiguously")
	}
	sorted := lk.Sorted()
	if sorted[0].Offset != 0x200 || sorted[len(sorted)-1].Offset+sorted[len(sorted)-1].Size != uint64(len(img)) {
		t.Errorf("sorted range: first=%+v last=%+v", sorted[0], sorted[len(sorted)-1])
	}
	// The BL1-tagged range is [0x400,0x1000) -- find it and check the tag
	// survived.
	var sawBL1, sawTrailer bool
	for _, e := range sorted {
		switch {
		case e.Offset == 0x400:
			sawBL1 = true
			if e.Tag != "BL1C@TESTTAG" {
				t.Errorf("BL1 tag: %q", e.Tag)
			}
		case e.Offset == 0x2200:
			sawTrailer = true
			if e.Tag != "Ver:LB__" {
				t.Errorf("trailer tag: %q", e.Tag)
			}
		}
	}
	if !sawBL1 || !sawTrailer {
		t.Errorf("expected ranges not found: BL1=%v trailer=%v", sawBL1, sawTrailer)
	}
}

func TestLKROMNotContiguous(t *testing.T) {
	img := lkromImage(t)
	// Corrupt a MIDDLE entry's size (slot 4, naming range [0x2100,0x2200) --
	// one with both a predecessor and a successor in sorted order) so the
	// chain actually breaks; shrinking the entry naming the LAST byte range
	// wouldn't be caught, since Contiguous only checks gaps BETWEEN
	// consecutive entries, not whether the chain reaches true EOF.
	le := binary.LittleEndian
	le.PutUint64(img[lkromTableOff+4*lkromEntrySize+8:], 1)
	lk, err := ParseLKROM(img)
	if err != nil {
		t.Fatal(err)
	}
	if lk.Contiguous() {
		t.Error("expected a broken chain to be detected")
	}
}

// With UNBRICK_LKROM_SAMPLE pointing at a real decrypted lk.rom, it is read
// too, and the known-contiguous invariant must hold against the real file.
func TestRealLKROM(t *testing.T) {
	p := os.Getenv("UNBRICK_LKROM_SAMPLE")
	if p == "" {
		t.Skip("UNBRICK_LKROM_SAMPLE not set")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lk, err := ParseLKROM(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", lk.Report())
	if !lk.Contiguous() {
		t.Error("a real image's table should tile contiguously")
	}
	if uint64(len(data)) != lk.Sorted()[len(lk.Entries)-1].Offset+lk.Sorted()[len(lk.Entries)-1].Size {
		t.Error("last entry should end at EOF")
	}
}
