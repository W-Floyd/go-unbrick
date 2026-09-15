package library

import (
	"bytes"
	"testing"

	"blankflash-forge/internal/bfforge"
	"blankflash-forge/internal/catalog"
)

func TestLoaderRoundtrip(t *testing.T) {
	lib := Open(t.TempDir())
	fam := catalog.Family{Vendor: "motorola", CPUName: "SM_DIVAR"}
	if lib.HasLoader(fam) {
		t.Fatal("empty library reports a loader")
	}
	d := &bfforge.Donor{
		Programmer: []byte("\x7fELFsigned-loader"),
		Qboot:      map[string][]byte{"qboot": []byte("QB"), "qboot.exe": []byte("QBX")},
		CPUName:    "SM_DIVAR",
		Storage:    "UFS",
	}
	ref, err := lib.AddLoader(fam, d, "blankflash_devon_S2SNS32.34-60-2.zip")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Build != "devon_S2SNS32.34-60-2" {
		t.Errorf("build id: got %q", ref.Build)
	}
	if !lib.HasLoader(fam) {
		t.Fatal("loader not reported after add")
	}
	got, gotRef, err := lib.FindLoader(fam, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Programmer, d.Programmer) {
		t.Error("programmer bytes differ")
	}
	if got.CPUName != "SM_DIVAR" || got.Storage != "UFS" {
		t.Errorf("meta not restored: %+v", got)
	}
	if !bytes.Equal(got.Qboot["qboot.exe"], []byte("QBX")) {
		t.Error("qboot aux not restored")
	}
	if gotRef.Meta.Source != "blankflash_devon_S2SNS32.34-60-2.zip" || gotRef.Meta.SHA256 == "" {
		t.Errorf("loader meta: %+v", gotRef.Meta)
	}
	if fams := lib.Loaders(); len(fams) != 1 || fams[0] != fam {
		t.Errorf("Loaders(): %v", fams)
	}
}

func TestMultipleBuildsAndDedupe(t *testing.T) {
	lib := Open(t.TempDir())
	fam := catalog.Family{Vendor: "motorola", CPUName: "SM_DIVAR"}
	a := &bfforge.Donor{Programmer: []byte("loaderA"), CPUName: "SM_DIVAR"}
	b := &bfforge.Donor{Programmer: []byte("loaderBBB"), CPUName: "SM_DIVAR"}

	lib.AddLoader(fam, a, "blankflash_devon_X.zip")
	lib.AddLoader(fam, b, "blankflash_rhode_Y.zip")
	if got := lib.Builds(fam); len(got) != 2 {
		t.Fatalf("want 2 builds, got %d: %+v", len(got), got)
	}
	// re-adding an identical loader under a different source must not duplicate
	ref, _ := lib.AddLoader(fam, a, "blankflash_hawao_Z.zip")
	if got := lib.Builds(fam); len(got) != 2 {
		t.Errorf("dedupe failed: %d builds", len(got))
	}
	if ref.Build != "devon_X" {
		t.Errorf("dedupe should return existing build, got %q", ref.Build)
	}
	// selecting a specific build
	d, dref, err := lib.FindLoader(fam, "rhode_Y")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.Programmer, b.Programmer) || dref.Build != "rhode_Y" {
		t.Errorf("wrong build selected: %q", dref.Build)
	}
	if _, _, err := lib.FindLoader(fam, "nope"); err == nil {
		t.Error("expected error for unknown build id")
	}
}

func TestStockRoundtrip(t *testing.T) {
	lib := Open(t.TempDir())
	if lib.HasStock("motorola", "fogona") {
		t.Fatal("empty library reports stock")
	}
	tgt := &bfforge.Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("XBL"), "abl.elf": []byte("ABL")},
		FlashMap: map[string]string{"xbl": "xbl.elf", "abl": "abl.elf"},
		GPT:      []byte("GPTDATA"),
		Storage:  "emmc",
		Source:   "dumps:/x",
	}
	if _, err := lib.AddStock("motorola", "fogona", tgt); err != nil {
		t.Fatal(err)
	}
	got, err := lib.FindStock("motorola", "fogona")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.GPT, tgt.GPT) {
		t.Error("gpt differs")
	}
	if !bytes.Equal(got.Parts["xbl.elf"], []byte("XBL")) || len(got.Parts) != 2 {
		t.Errorf("parts not restored: %v", got.Parts)
	}
	if got.FlashMap["abl"] != "abl.elf" || got.Storage != "emmc" {
		t.Errorf("stock meta not restored: %+v", got)
	}
	if refs := lib.Stock(); len(refs) != 1 || refs[0] != (StockRef{"motorola", "fogona"}) {
		t.Errorf("Stock(): %v", refs)
	}
}

// AddStock replaces wholesale: a part removed from a re-harvest must not linger.
func TestStockReplaceDropsStale(t *testing.T) {
	lib := Open(t.TempDir())
	first := &bfforge.Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("X"), "stale.mbn": []byte("S")},
		FlashMap: map[string]string{"xbl": "xbl.elf"},
	}
	lib.AddStock("m", "d", first)
	second := &bfforge.Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("X2")},
		FlashMap: map[string]string{"xbl": "xbl.elf"},
	}
	lib.AddStock("m", "d", second)
	got, _ := lib.FindStock("m", "d")
	if _, ok := got.Parts["stale.mbn"]; ok {
		t.Error("stale part survived re-harvest")
	}
	if !bytes.Equal(got.Parts["xbl.elf"], []byte("X2")) {
		t.Error("part not updated")
	}
}
