package qfil

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"go-unbrick/internal/blankflash"
)

// makeMockGPT creates a minimal valid 17408-byte GPT structure (MBR + Header + 128 entries).
func makeMockGPT(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 512+512+128*128)

	// Header at 512
	hdr := buf[512:1024]
	copy(hdr[0:8], "EFI PART")
	binary.LittleEndian.PutUint32(hdr[8:12], 0x00010000) // Revision
	binary.LittleEndian.PutUint32(hdr[12:16], 92)         // Header size
	binary.LittleEndian.PutUint64(hdr[24:32], 1)          // Current LBA
	binary.LittleEndian.PutUint64(hdr[32:40], 100000)     // Backup LBA
	binary.LittleEndian.PutUint64(hdr[40:48], 34)         // First usable LBA
	binary.LittleEndian.PutUint64(hdr[48:56], 99966)      // Last usable LBA
	binary.LittleEndian.PutUint64(hdr[72:80], 2)          // Part entry LBA
	binary.LittleEndian.PutUint32(hdr[80:84], 128)        // Num part entries
	binary.LittleEndian.PutUint32(hdr[84:88], 128)        // Part entry size

	// Helper to write partition entry at index idx
	writeEntry := func(idx int, name string, startLBA, endLBA uint64) {
		ent := buf[1024+idx*128 : 1024+(idx+1)*128]
		ent[0] = 0xAA // non-zero type GUID
		ent[16] = 0xBB // unique GUID
		binary.LittleEndian.PutUint64(ent[32:40], startLBA)
		binary.LittleEndian.PutUint64(ent[40:48], endLBA)

		// UTF-16LE name at 56..128
		u16 := utf16.Encode([]rune(name))
		for j, code := range u16 {
			if j >= 36 {
				break
			}
			binary.LittleEndian.PutUint16(ent[56+j*2:56+(j+1)*2], code)
		}
	}

	writeEntry(0, "xbl_a", 1000, 1999)
	writeEntry(1, "xbl_b", 2000, 2999)
	writeEntry(2, "abl_a", 3000, 4999)
	writeEntry(3, "tz_a", 5000, 5999)

	return buf
}

func TestParseGPT(t *testing.T) {
	raw := makeMockGPT(t)
	tbl, err := ParseGPT(raw)
	if err != nil {
		t.Fatalf("ParseGPT failed: %v", err)
	}

	if len(tbl.Partitions) != 4 {
		t.Fatalf("got %d partitions, want 4", len(tbl.Partitions))
	}

	p0 := tbl.Partitions[0]
	if p0.Name != "xbl_a" || p0.StartLBA != 1000 || p0.EndLBA != 1999 || p0.NumSectors != 1000 {
		t.Errorf("unexpected partition 0: %+v", p0)
	}

	// Test PartitionByName lookups
	if p, ok := tbl.PartitionByName("xbl_a"); !ok || p.StartLBA != 1000 {
		t.Errorf("PartitionByName('xbl_a') failed: ok=%v, p=%+v", ok, p)
	}
	// Case-insensitive
	if p, ok := tbl.PartitionByName("XBL_A"); !ok || p.StartLBA != 1000 {
		t.Errorf("PartitionByName('XBL_A') failed: ok=%v, p=%+v", ok, p)
	}
	// Slot-agnostic fallback
	if p, ok := tbl.PartitionByName("xbl"); !ok || p.Name != "xbl_a" {
		t.Errorf("PartitionByName('xbl') fallback failed: ok=%v, p=%+v", ok, p)
	}
	if p, ok := tbl.PartitionByName("abl"); !ok || p.StartLBA != 3000 || p.NumSectors != 2000 {
		t.Errorf("PartitionByName('abl') fallback failed: ok=%v, p=%+v", ok, p)
	}
}

func TestGenerateAndParseRawProgram(t *testing.T) {
	raw := makeMockGPT(t)
	tbl, err := ParseGPT(raw)
	if err != nil {
		t.Fatalf("ParseGPT: %v", err)
	}

	parts := map[string][]byte{
		"xbl.elf": bytes.Repeat([]byte("x"), 1000*512),
		"abl.elf": bytes.Repeat([]byte("a"), 2000*512),
		"tz.mbn":  bytes.Repeat([]byte("t"), 1000*512),
	}
	flashMap := map[string]string{
		"xbl": "xbl.elf",
		"abl": "abl.elf",
		"tz":  "tz.mbn",
	}
	flashOrder := []string{"xbl", "tz", "abl"}

	xmlBytes, err := GenerateRawProgram(tbl, parts, flashMap, flashOrder, "gpt_main0.bin", "a")
	if err != nil {
		t.Fatalf("GenerateRawProgram failed: %v", err)
	}

	entries, err := ParseRawProgram(xmlBytes)
	if err != nil {
		t.Fatalf("ParseRawProgram failed: %v", err)
	}

	// We expect 4 entries: PrimaryGPT + xbl + tz + abl (in flashOrder)
	if len(entries) != 4 {
		t.Fatalf("got %d program entries, want 4", len(entries))
	}

	if entries[0].Label != "PrimaryGPT" || entries[0].StartSector != 0 {
		t.Errorf("entry 0: got label %q, start %d", entries[0].Label, entries[0].StartSector)
	}
	if entries[1].Label != "xbl_a" || entries[1].StartSector != 1000 || entries[1].Filename != "xbl.elf" {
		t.Errorf("entry 1: got %+v", entries[1])
	}
	if entries[2].Label != "tz_a" || entries[2].StartSector != 5000 || entries[2].Filename != "tz.mbn" {
		t.Errorf("entry 2: got %+v", entries[2])
	}
	if entries[3].Label != "abl_a" || entries[3].StartSector != 3000 || entries[3].Filename != "abl.elf" {
		t.Errorf("entry 3: got %+v", entries[3])
	}
}

func TestGenerateAndParsePatch(t *testing.T) {
	raw := makeMockGPT(t)
	tbl, _ := ParseGPT(raw)

	patchXML := GeneratePatch(tbl)
	entries, err := ParsePatch(patchXML)
	if err != nil {
		t.Fatalf("ParsePatch failed: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("got %d patches, want 3", len(entries))
	}
}

func TestAssembleQFIL(t *testing.T) {
	donorProg := []byte("SIGNED_FIREHOSE_LOADER_BYTES")
	d := &blankflash.Donor{
		Programmer: donorProg,
		Storage:    "emmc",
	}

	rawGPT := makeMockGPT(t)
	tParts := map[string][]byte{
		"xbl.elf": []byte("XBL_DATA"),
		"abl.elf": []byte("ABL_DATA"),
	}
	tgt := &blankflash.Target{
		Parts:      tParts,
		FlashMap:   map[string]string{"xbl": "xbl.elf", "abl": "abl.elf"},
		FlashOrder: []string{"xbl", "abl"},
		GPT:        rawGPT,
		Storage:    "emmc",
	}

	res, err := Assemble(d, tgt, AssembleOptions{Slot: "a"})
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	if res.Singleimage != nil {
		t.Errorf("expected Singleimage == nil, got %d bytes", len(res.Singleimage))
	}

	// Verify required files in Aux
	expectedFiles := []string{
		"prog_firehose_lite.elf",
		"gpt_main0.bin",
		"rawprogram0.xml",
		"patch0.xml",
		"xbl.elf",
		"abl.elf",
		"flash.sh",
		"flash.bat",
	}

	for _, fn := range expectedFiles {
		if _, ok := res.Aux[fn]; !ok {
			t.Errorf("missing expected file in Aux: %s", fn)
		}
	}

	if !bytes.Equal(res.Aux["prog_firehose_lite.elf"], donorProg) {
		t.Errorf("programmer mismatch")
	}
}

func TestParseRealStockGPT(t *testing.T) {
	gptPath := "../../library/stock/motorola/fogona/240823-b2e77d5e/gpt.bin"
	data, err := os.ReadFile(gptPath)
	if err != nil {
		t.Skipf("skipping real GPT test: %v", err)
	}

	if !blankflash.IsContainer(data) {
		t.Fatalf("expected container gpt.bin")
	}

	recs, err := blankflash.Parse(data)
	if err != nil {
		t.Fatalf("blankflash.Parse failed: %v", err)
	}

	var totalParts int
	for _, r := range recs {
		t.Logf("record: %s (%d bytes)", r.Name, len(r.Data))
		if !strings.HasPrefix(r.Name, "gpt_main") {
			continue
		}
		tbl, err := ParseGPT(r.Data)
		if err != nil {
			t.Logf("ParseGPT failed for %s: %v", r.Name, err)
			continue
		}
		efiIdx := bytes.Index(r.Data, []byte("EFI PART"))
		t.Logf("%s: efiIdx=%d, rawLen=%d, parts=%d", r.Name, efiIdx, len(r.Data), len(tbl.Partitions))
		totalParts += len(tbl.Partitions)
		for _, p := range tbl.Partitions {
			if p.Name != "" {
				t.Logf("real GPT partition in %s: %s (LBA %d..%d, %d sectors)",
					r.Name, p.Name, p.StartLBA, p.EndLBA, p.NumSectors)
			}
		}
	}

	if totalParts == 0 {
		t.Errorf("no partitions parsed from real GPT container")
	}

	// Cross-verify rawprogram generation with real LUN 3 GPT (boot chain)
	for _, r := range recs {
		if r.Name != "gpt_main3.bin" {
			continue
		}
		tbl, err := ParseGPT(r.Data)
		if err != nil {
			t.Fatalf("ParseGPT on gpt_main3.bin failed: %v", err)
		}
		parts := map[string][]byte{
			"abl.elf":    bytes.Repeat([]byte("a"), 256*int(tbl.SectorSize)),
			"tz.mbn":     bytes.Repeat([]byte("t"), 1024*int(tbl.SectorSize)),
			"devcfg.mbn": bytes.Repeat([]byte("d"), 32*int(tbl.SectorSize)),
		}
		flashMap := map[string]string{
			"abl":    "abl.elf",
			"tz":     "tz.mbn",
			"devcfg": "devcfg.mbn",
		}
		flashOrder := []string{"abl", "tz", "devcfg"}

		xmlData, err := GenerateRawProgram(tbl, parts, flashMap, flashOrder, "gpt_main3.bin", "a")
		if err != nil {
			t.Fatalf("GenerateRawProgram on real table failed: %v", err)
		}
		entries, err := ParseRawProgram(xmlData)
		if err != nil {
			t.Fatalf("ParseRawProgram failed: %v", err)
		}

		if len(entries) != 4 { // PrimaryGPT + abl + tz + devcfg
			t.Fatalf("got %d entries, want 4", len(entries))
		}
		if entries[1].Label != "abl_a" || entries[1].StartSector != 1760 || entries[1].NumPartitionSectors != 256 {
			t.Errorf("unexpected abl_a entry from real GPT: %+v", entries[1])
		}
		if entries[2].Label != "tz_a" || entries[2].StartSector != 32 || entries[2].NumPartitionSectors != 1024 {
			t.Errorf("unexpected tz_a entry from real GPT: %+v", entries[2])
		}
		if entries[3].Label != "devcfg_a" || entries[3].StartSector != 2528 || entries[3].NumPartitionSectors != 32 {
			t.Errorf("unexpected devcfg_a entry from real GPT: %+v", entries[3])
		}
	}
}

