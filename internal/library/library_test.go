package library

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/catalog"
)

func TestLoaderRoundtrip(t *testing.T) {
	lib := Open(t.TempDir())
	fam := catalog.Family{Vendor: "motorola", JTAGID: "0016F0E1"}
	if lib.HasLoader(fam) {
		t.Fatal("empty library reports a loader")
	}
	d := &blankflash.Donor{
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
	fam := catalog.Family{Vendor: "motorola", JTAGID: "0016F0E1"}
	a := &blankflash.Donor{Programmer: []byte("loaderA"), CPUName: "SM_DIVAR"}
	b := &blankflash.Donor{Programmer: []byte("loaderBBB"), CPUName: "SM_DIVAR"}

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

// LoadersForCPU is the emergent device↔loader bridge: a full donor establishes
// the cpu_name↔JTAG link, which then pulls in a bare fhprg loader that shares the
// JTAG but carries no cpu_name of its own — and one cpu_name may span two JTAGs.
func TestLoadersForCPUBridge(t *testing.T) {
	lib := Open(t.TempDir())
	divarA := catalog.Family{Vendor: "motorola", JTAGID: "0016F0E1"}
	divarB := catalog.Family{Vendor: "motorola", JTAGID: "001B80E1"} // same cpu, other silicon
	// Full donor on JTAG A carries the cpu_name label and a low SW_ID.
	lib.AddLoader(divarA, &blankflash.Donor{Programmer: []byte("A-full"), CPUName: "SM_DIVAR"}, "blankflash_devon_X.zip")
	// Bare fhprg on the same JTAG A: no cpu_name, but must be reachable via the bridge.
	bare, _ := lib.AddLoader(divarA, &blankflash.Donor{Programmer: []byte("A-bare")}, "0016f0e1_bkerler.bin")
	_ = bare
	// Full donor on JTAG B under the same cpu_name.
	lib.AddLoader(divarB, &blankflash.Donor{Programmer: []byte("B-full"), CPUName: "SM_DIVAR"}, "blankflash_hawao_Y.zip")

	got := lib.LoadersForCPU("motorola", "SM_DIVAR")
	if len(got) != 3 {
		t.Fatalf("bridge should reach all 3 loaders (2 full + 1 bare across 2 JTAGs), got %d: %+v", len(got), got)
	}
	if !lib.HasLoaderForCPU("motorola", "SM_DIVAR") {
		t.Error("HasLoaderForCPU should be true")
	}
	if lib.HasLoaderForCPU("motorola", "SM_UNKNOWN") {
		t.Error("unknown cpu_name should not resolve")
	}
	// A bare loader whose JTAG no cpu_name ever labeled must NOT be reached.
	lib.AddLoader(catalog.Family{Vendor: "motorola", JTAGID: "00000000"},
		&blankflash.Donor{Programmer: []byte("orphan")}, "orphan.bin")
	if n := len(lib.LoadersForCPU("motorola", "SM_DIVAR")); n != 3 {
		t.Errorf("orphan JTAG leaked into cpu bridge: got %d", n)
	}
}

// A pinned jtag_id resolves exactly the loaders that authenticate on that
// silicon, unlike the cpu_name bridge which over-groups sibling JTAGs. It also
// reaches a bare fhprg loader on that JTAG that no full donor ever labeled.
func TestCandidateLoadersByJTAG(t *testing.T) {
	lib := Open(t.TempDir())
	jtagA := catalog.Family{Vendor: "motorola", JTAGID: "0016F0E1"}
	jtagB := catalog.Family{Vendor: "motorola", JTAGID: "001B80E1"} // same cpu_name, other silicon
	lib.AddLoader(jtagA, &blankflash.Donor{Programmer: []byte("A-full"), CPUName: "SM_DIVAR"}, "blankflash_devon_X.zip")
	lib.AddLoader(jtagA, &blankflash.Donor{Programmer: []byte("A-bare")}, "0016f0e1_bkerler.bin") // no cpu_name
	lib.AddLoader(jtagB, &blankflash.Donor{Programmer: []byte("B-full"), CPUName: "SM_DIVAR"}, "blankflash_hawao_Y.zip")

	// Pinning JTAG A must reach A's two loaders and NOT B's, even though both
	// carry cpu_name SM_DIVAR (the over-grouping the bridge cannot avoid).
	if got := lib.LoadersForJTAGs("motorola", []string{"0016F0E1"}); len(got) != 2 {
		t.Fatalf("jtag A: want 2 loaders, got %d: %+v", len(got), got)
	}
	// Lowercase input is normalized.
	if got := lib.LoadersForJTAGs("motorola", []string{"0016f0e1"}); len(got) != 2 {
		t.Errorf("jtag lowercasing not handled: got %d", len(got))
	}

	pinned := &catalog.Device{Vendor: "motorola", CPUName: "SM_DIVAR", JTAGIDs: []string{"0016F0E1"}}
	if got := lib.CandidateLoaders(pinned); len(got) != 2 {
		t.Errorf("pinned device should resolve via jtag_id (2), got %d", len(got))
	}
	unpinned := &catalog.Device{Vendor: "motorola", CPUName: "SM_DIVAR"}
	if got := lib.CandidateLoaders(unpinned); len(got) != 3 {
		t.Errorf("unpinned device should fall back to cpu bridge (3), got %d", len(got))
	}
}

// A device with a recorded JTAG_ID must still reach a loader that could only be
// filed under its cpu_name (unparseable cert), or pinning the JTAG strands it.
func TestCandidateLoadersFallsBackWhenJTAGFamilyEmpty(t *testing.T) {
	lib := Open(t.TempDir())
	fam := catalog.Family{Vendor: "motorola", JTAGID: "SM_WAIPIO"} // cpu_name key
	if _, err := lib.AddLoader(fam, &blankflash.Donor{
		Programmer: []byte("LOADER"),
		CPUName:    "SM_WAIPIO",
	}, "blankflash_hiphi.zip"); err != nil {
		t.Fatal(err)
	}
	dev := &catalog.Device{
		Codename: "hiphi", Vendor: "motorola",
		CPUName: "SM_WAIPIO", JTAGIDs: []string{"001870E1"},
	}
	if got := lib.CandidateLoaders(dev); len(got) == 0 {
		t.Error("a pinned JTAG_ID with no JTAG-keyed loader should still reach the cpu_name bridge")
	}

	// But where the JTAG family does hold loaders, those answer and the lossier
	// bridge is not consulted.
	jfam := catalog.Family{Vendor: "motorola", JTAGID: "001870E1"}
	if _, err := lib.AddLoader(jfam, &blankflash.Donor{
		Programmer: []byte("EXACT"),
		CPUName:    "SM_WAIPIO",
	}, "blankflash_exact.zip"); err != nil {
		t.Fatal(err)
	}
	got := lib.CandidateLoaders(dev)
	if len(got) != 1 || got[0].Family.JTAGID != "001870E1" {
		t.Errorf("JTAG-keyed loader should win alone, got %+v", got)
	}
}

func TestStockRoundtrip(t *testing.T) {
	lib := Open(t.TempDir())
	if lib.HasStock("motorola", "fogona") {
		t.Fatal("empty library reports stock")
	}
	tgt := &blankflash.Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("XBL"), "abl.elf": []byte("ABL")},
		FlashMap: map[string]string{"xbl": "xbl.elf", "abl": "abl.elf"},
		GPT:      []byte("GPTDATA"),
		Storage:  "emmc",
		Source:   "dumps:/x",
	}
	if _, err := lib.AddStock("motorola", "fogona", "250831-abc", tgt); err != nil {
		t.Fatal(err)
	}
	got, ref, err := lib.FindStock("motorola", "fogona", "")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Build != "250831-abc" {
		t.Errorf("build id: got %q", ref.Build)
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
	if refs := lib.Stock(); len(refs) != 1 || refs[0].Codename != "fogona" || refs[0].Build != "250831-abc" {
		t.Errorf("Stock(): %v", refs)
	}
}

// Distinct extracts are kept side by side -- the point of the catalogue -- and
// each build keeps only its own parts, so a part absent from one build does not
// leak in from another.
func TestStockKeepsEveryBuild(t *testing.T) {
	lib := Open(t.TempDir())
	old := &blankflash.Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("X"), "only-old.mbn": []byte("S")},
		FlashMap: map[string]string{"xbl": "xbl.elf"},
	}
	newer := &blankflash.Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("X2")},
		FlashMap: map[string]string{"xbl": "xbl.elf"},
	}
	if _, err := lib.AddStock("m", "d", "240823-aaa", old); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.AddStock("m", "d", "250831-bbb", newer); err != nil {
		t.Fatal(err)
	}
	if got := lib.StockBuilds("m", "d"); len(got) != 2 {
		t.Fatalf("both builds should be kept, got %d", len(got))
	}
	// Default resolves to the newest, and carries none of the older build.
	got, ref, _ := lib.FindStock("m", "d", "")
	if ref.Build != "250831-bbb" {
		t.Errorf("default should be newest, got %q", ref.Build)
	}
	if _, ok := got.Parts["only-old.mbn"]; ok {
		t.Error("part leaked across builds")
	}
	if !bytes.Equal(got.Parts["xbl.elf"], []byte("X2")) {
		t.Error("wrong build's parts")
	}
	// The older build is still selectable and intact.
	oldGot, oldRef, err := lib.FindStock("m", "d", "240823-aaa")
	if err != nil {
		t.Fatal(err)
	}
	if oldRef.Build != "240823-aaa" || !bytes.Equal(oldGot.Parts["only-old.mbn"], []byte("S")) {
		t.Error("older build not retrievable intact")
	}
	if _, _, err := lib.FindStock("m", "d", "nope"); err == nil {
		t.Error("unknown build should error, not fall back")
	}
}

// Re-importing identical bytes must not create a second build.
func TestStockDedupesIdenticalImport(t *testing.T) {
	lib := Open(t.TempDir())
	mk := func() *blankflash.Target {
		return &blankflash.Target{
			Parts:    map[string][]byte{"xbl.elf": []byte("X")},
			FlashMap: map[string]string{"xbl": "xbl.elf"},
		}
	}
	if _, err := lib.AddStock("m", "d", "250831-bbb", mk()); err != nil {
		t.Fatal(err)
	}
	// Same bytes arriving under a different build id is still the same extract.
	ref, err := lib.AddStock("m", "d", "different-id", mk())
	if err != nil {
		t.Fatal(err)
	}
	if got := lib.StockBuilds("m", "d"); len(got) != 1 {
		t.Errorf("identical import duplicated: %d builds", len(got))
	}
	if ref.Build != "250831-bbb" {
		t.Errorf("dedupe should return the existing build, got %q", ref.Build)
	}
}

// Stock stored under the old flat layout is moved into a build directory rather
// than orphaned by the build-keyed one.
func TestStockMigratesFlatLayout(t *testing.T) {
	lib := Open(t.TempDir())
	dev := lib.stockDeviceDir("motorola", "devon")
	if err := lib.writeStock(dev, &blankflash.Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("LEGACY")},
		FlashMap: map[string]string{"xbl": "xbl.elf"},
		GPT:      []byte("G"),
	}, StockMeta{Source: "bootloader.img", Storage: "ufs"}); err != nil {
		t.Fatal(err)
	}
	if err := lib.migrateFlatStock("motorola", "devon"); err != nil {
		t.Fatal(err)
	}
	builds := lib.StockBuilds("motorola", "devon")
	if len(builds) != 1 {
		t.Fatalf("expected 1 migrated build, got %d", len(builds))
	}
	got, _, err := lib.FindStock("motorola", "devon", "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Parts["xbl.elf"], []byte("LEGACY")) || got.Storage != "ufs" {
		t.Errorf("migrated stock lost content: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dev, "meta.json")); !os.IsNotExist(err) {
		t.Error("flat layout should be gone after migration")
	}
}
