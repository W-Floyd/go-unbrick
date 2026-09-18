package edl

import "testing"

const samplePrintGPT = `
main - Mode detected: firehose

Parsing Lun 1:

GPT Table:
-------------
xbl_a:               Offset 0x0000000000020000, Length 0x0000000000400000, Flags 0x0, UUID x, Type 0x1, Active False
xbl_config_a:        Offset 0x0000000000520000, Length 0x0000000000040000, Flags 0x0, UUID x, Type 0x1, Active False

Total disk size:0x0000000000800000, sectors:0x0000000000000800


Parsing Lun 3:

GPT Table:
-------------
tz_a:                Offset 0x0000000000020000, Length 0x0000000000400000, Flags 0x0, UUID x, Type 0x1, Active False
abl_a:               Offset 0x00000000006e0000, Length 0x0000000000100000, Flags 0x0, UUID x, Type 0x1, Active False

Total disk size:0x000000003b000000, sectors:0x000000000003b000
`

func TestParsePrintGPT(t *testing.T) {
	g, err := ParsePrintGPT(samplePrintGPT)
	if err != nil {
		t.Fatalf("ParsePrintGPT: %v", err)
	}
	if len(g.Parts) != 4 {
		t.Fatalf("got %d partitions, want 4", len(g.Parts))
	}
	if !g.HasLUN(1) || !g.HasLUN(3) || g.HasLUN(0) {
		t.Errorf("HasLUN wrong: %v", g.LunSize)
	}
	if sz := g.LunSize[3]; sz != 0x3b000000 {
		t.Errorf("LUN3 size = 0x%X, want 0x3b000000", sz)
	}
	xbl, ok := g.Find("xbl_a")
	if !ok || xbl.LUN != 1 || xbl.Offset != 0x20000 || xbl.Length != 0x400000 {
		t.Errorf("xbl_a = %+v", xbl)
	}
	abl, ok := g.Find("ABL_A") // case-insensitive
	if !ok || abl.LUN != 3 || abl.Offset != 0x6e0000 {
		t.Errorf("abl_a = %+v", abl)
	}
}

func TestParsePrintGPTEmpty(t *testing.T) {
	if _, err := ParsePrintGPT("main - Waiting for the device\n"); err == nil {
		t.Fatal("expected error for output with no partitions")
	}
}
