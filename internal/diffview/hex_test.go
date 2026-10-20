package diffview

import (
	"bytes"
	"testing"
)

func TestHexDiffFindsTheChangedBytes(t *testing.T) {
	a := bytes.Repeat([]byte{1, 2, 3, 4}, 100)
	b := append([]byte(nil), a...)
	b[10], b[11] = 0xff, 0xee
	b[300] = 0x77
	hs, total, ok := HexDiff(a, b)
	if !ok || len(hs) != 2 || total != 3 {
		t.Fatalf("%d hunks, %d bytes, ok=%v", len(hs), total, ok)
	}
	if h := hs[0]; h.OffA != 10 || h.OffB != 10 || !bytes.Equal(h.B, []byte{0xff, 0xee}) || !bytes.Equal(h.A, []byte{3, 4}) {
		t.Errorf("first: %+v", h)
	}
	if h := hs[1]; h.OffA != 300 || len(h.A) != 1 {
		t.Errorf("second: %+v", h)
	}
}

func TestHexDiffInsertionShiftsNothingAfterIt(t *testing.T) {
	a := bytes.Repeat([]byte("abcdefgh"), 50)
	b := append(append(append([]byte(nil), a[:100]...), 9, 9, 9), a[100:]...)
	hs, total, _ := HexDiff(a, b)
	if len(hs) != 1 || total != 3 || len(hs[0].A) != 0 || len(hs[0].B) != 3 || hs[0].OffB != 100 {
		t.Errorf("%+v (%d bytes)", hs, total)
	}
}

func TestHexDiffIdenticalAndHuge(t *testing.T) {
	if hs, n, ok := HexDiff([]byte("same"), []byte("same")); !ok || len(hs) != 0 || n != 0 {
		t.Errorf("identical: %v %d %v", hs, n, ok)
	}
	big := make([]byte, exactMax+10)
	other := make([]byte, exactMax+11)
	if _, _, ok := HexDiff(big, other); ok {
		t.Error("unequal huge strings were diffed")
	}
	c := append([]byte(nil), big...)
	c[5000] = 1
	if hs, n, ok := HexDiff(big, c); !ok || len(hs) != 1 || n != 1 {
		t.Errorf("equal-size huge: %v %d %v", hs, n, ok)
	}
}

func TestHexDiffOutsideStringsLeavesTheStringsToTheirOwnDiff(t *testing.T) {
	mk := func(s string, tail byte) []byte {
		return append(append([]byte{1, 2, 3, 4}, append([]byte(s), 0, 5, 6, 7, tail)...), 8, 9, 10)
	}
	a, b := mk("hello world", 0x11), mk("hellp world", 0x22)
	if hs, _, _ := HexDiff(a, b); len(hs) != 2 {
		t.Fatalf("%d hunks with strings", len(hs))
	}
	hs, total, ok := HexDiffOutsideStrings(a, b, 6)
	if !ok || len(hs) != 1 || total != 1 || hs[0].B[0] != 0x22 {
		t.Errorf("%+v %d", hs, total)
	}
}

func TestMarkWords(t *testing.T) {
	ls := MarkWords([]Line{{Op: '-', A: 1, Text: "let total = price * 3;"}, {Op: '+', B: 1, Text: "let total = cost * 3;"}, {Op: ' ', A: 2, B: 2, Text: "x"}})
	if len(ls[0].Hi) != 1 || ls[0].Text[ls[0].Hi[0][0]:ls[0].Hi[0][1]] != "price" || ls[1].Text[ls[1].Hi[0][0]:ls[1].Hi[0][1]] != "cost" || ls[2].Hi != nil {
		t.Errorf("%+v", ls)
	}
}
