package vendor

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go-unbrick/internal/blankflash"
)

func TestRegistryLookup(t *testing.T) {
	if d, ok := For("motorola"); !ok || d.ID() != "motorola" {
		t.Errorf("For(motorola): %v %v", d, ok)
	}
	if d, ok := ForOEMID("02E8"); !ok || d.ID() != "motorola" {
		t.Errorf("ForOEMID(02E8) should be motorola: %v %v", d, ok)
	}
	if d, ok := ForOEMID("0020"); !ok || d.ID() != "samsung" {
		t.Errorf("ForOEMID(0020) should be samsung: %v %v", d, ok)
	}
	if _, ok := ForOEMID("FFFF"); ok {
		t.Error("unknown OEM_ID should not resolve")
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()

	// A SINGLE_N_LONELY container -> motorola.
	moto := filepath.Join(dir, "singleimage.bin")
	blob, _ := blankflash.Build(blankflash.WithTrailer([]blankflash.Record{{Name: "programmer.elf", Data: []byte("x")}}))
	os.WriteFile(moto, blob, 0o644)
	if d, ok := Detect(moto); !ok || d.ID() != "motorola" {
		t.Errorf("Detect(singleimage) should be motorola: %v %v", d, ok)
	}

	// A .pit table -> samsung.
	pit := filepath.Join(dir, "STARQLTE.pit")
	os.WriteFile(pit, []byte("PIT dummy"), 0o644)
	if d, ok := Detect(pit); !ok || d.ID() != "samsung" {
		t.Errorf("Detect(.pit) should be samsung: %v %v", d, ok)
	}

	// Something unrecognized.
	other := filepath.Join(dir, "random.txt")
	os.WriteFile(other, []byte("hello"), 0o644)
	if _, ok := Detect(other); ok {
		t.Error("Detect(random) should not match")
	}
}

func TestPlatforms(t *testing.T) {
	cases := map[string]string{"motorola": PlatformQualcomm, "samsung": PlatformQualcomm, "mediatek": PlatformMediaTek}
	for id, want := range cases {
		d, ok := For(id)
		if !ok {
			t.Fatalf("driver %q not registered", id)
		}
		if d.Platform() != want {
			t.Errorf("%s platform: got %q want %q", id, d.Platform(), want)
		}
	}
}

func TestDetectMediaTek(t *testing.T) {
	dir := t.TempDir()
	scatter := filepath.Join(dir, "MT6765_Android_scatter_blankflash.txt")
	os.WriteFile(scatter, []byte("- partition_index: SYS0\n"), 0o644)
	if d, ok := Detect(scatter); !ok || d.ID() != "mediatek" {
		t.Errorf("Detect(scatter) should be mediatek: %v %v", d, ok)
	}
	// A MediaTek OEM_ID space is separate; it declares none.
	if m, _ := For("mediatek"); len(m.OEMIDs()) != 0 {
		t.Error("mediatek should declare no Qualcomm OEM_IDs")
	}
}

// writeZip builds a zip with the given members (name -> contents).
func writeZip(t *testing.T, path string, members map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDetectStock(t *testing.T) {
	dir := t.TempDir()

	// A retail firmware zip: the boot chain plus payload we ignore.
	stock := filepath.Join(dir, "XT2413V_FOGONA_TRACFONE_14.xml.zip")
	writeZip(t, stock, map[string]string{
		"bootloader.img":          "bl",
		"gpt.bin":                 "gpt",
		"super.img_sparsechunk.0": "super",
		"radio.img":               "radio",
	})
	d, sp, ok := DetectStock(stock)
	if !ok || d.ID() != "motorola" || sp == nil {
		t.Fatalf("DetectStock(stock zip) should be motorola: %v %v", d, ok)
	}

	// Missing gpt.bin -> not a stock package.
	partial := filepath.Join(dir, "partial.zip")
	writeZip(t, partial, map[string]string{"bootloader.img": "bl"})
	if _, _, ok := DetectStock(partial); ok {
		t.Error("zip without gpt.bin should not match")
	}

	// A blankflash donor is a donor, not a stock package.
	donor := filepath.Join(dir, "blankflash_devon.zip")
	blob, _ := blankflash.Build(blankflash.WithTrailer([]blankflash.Record{{Name: "programmer.elf", Data: []byte("x")}}))
	writeZip(t, donor, map[string]string{"singleimage.bin": string(blob)})
	if _, _, ok := DetectStock(donor); ok {
		t.Error("blankflash donor should not match DetectStock")
	}

	// ...and conversely a stock zip is not a donor.
	if _, ok := Detect(stock); ok {
		t.Error("stock zip should not match Detect (donor path)")
	}
}

// A crafted member path must not be able to place bytes outside the archive:
// members are matched on base name and never written to disk.
func TestStockZipTraversalMemberIsBaseNamed(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(dir, "evil.zip")
	writeZip(t, evil, map[string]string{
		"../../../../etc/bootloader.img": "bl",
		"gpt.bin":                        "gpt",
	})
	m, err := zipMembers(evil, stockMembers)
	if err != nil {
		t.Fatal(err)
	}
	if string(m["bootloader.img"]) != "bl" {
		t.Errorf("traversal member should be read under its base name: %q", m["bootloader.img"])
	}
	if _, err := os.Stat("/etc/bootloader.img"); err == nil {
		t.Fatal("zip member escaped to /etc")
	}
}

// lunImage fakes one gpt_mainN.bin: the PROD/CSV trailer is what carries the
// device name, in a fixed 16-byte space-padded cell.
func lunImage(prod string) []byte {
	b := make([]byte, 32768)
	copy(b[28640:], []byte(prod+strings.Repeat(" ", 16-len(prod))+"CSV:18          "))
	return b
}

func gptContainer(t *testing.T, recs ...blankflash.Record) []byte {
	t.Helper()
	b, err := blankflash.Build(blankflash.WithTrailer(recs))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCodenameFromGPT(t *testing.T) {
	ok := gptContainer(t,
		blankflash.Record{Name: "index.xml", Data: []byte("<index/>")},
		blankflash.Record{Name: "gpt_main0.bin", Data: lunImage("PROD:fogona")},
		blankflash.Record{Name: "gpt_main1.bin", Data: lunImage("PROD:fogona")},
	)
	if got := CodenameFromGPT(ok); got != "fogona" {
		t.Errorf("got %q want fogona", got)
	}

	// LUN0 untagged: fall through to a later LUN rather than giving up.
	fallthru := gptContainer(t,
		blankflash.Record{Name: "gpt_main0.bin", Data: make([]byte, 32768)},
		blankflash.Record{Name: "gpt_main1.bin", Data: lunImage("PROD:devon")},
	)
	if got := CodenameFromGPT(fallthru); got != "devon" {
		t.Errorf("fallthrough: got %q want devon", got)
	}

	// No tag anywhere, and a non-container: both report "unknown", not a guess.
	none := gptContainer(t, blankflash.Record{Name: "gpt_main0.bin", Data: make([]byte, 32768)})
	if got := CodenameFromGPT(none); got != "" {
		t.Errorf("untagged: got %q want empty", got)
	}
	if got := CodenameFromGPT([]byte("not a container")); got != "" {
		t.Errorf("non-container: got %q want empty", got)
	}
}

func TestProdOfRejectsJunk(t *testing.T) {
	cases := map[string]string{
		"PROD:fogona     CSV:18": "fogona",
		"PROD:devon_g    CSV:5":  "devon_g",
		"PROD:FOGONA     CSV:1":  "fogona", // normalized to the catalog's case
		"PROD:           CSV:1":  "",       // empty cell
		"PROD:bad/name   CSV:1":  "",       // not a codename charset
		"nothing here at all":    "",
	}
	for in, want := range cases {
		if got := prodOf([]byte(in)); got != want {
			t.Errorf("prodOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExplodeStock(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "stock.zip")
	writeZip(t, zipPath, map[string]string{
		"boot.img":                "BOOT",
		"dtbo.img":                "DTBO",
		"gpt.bin":                 "GPT",
		"bootloader.img":          "BL", // not a real container; unpack is skipped
		"super.img_sparsechunk.0": "AAA",
		"super.img_sparsechunk.1": "BBB",
	})
	m, _ := For("motorola")
	ex, ok := m.(StockExploder)
	if !ok {
		t.Fatal("motorola should implement StockExploder")
	}

	out := filepath.Join(dir, "out")
	// bootloader.img here is not a real container, so the boot-chain unpack
	// fails; the package's own members must survive that.
	names, err := ex.ExplodeStock(zipPath, out, ExplodeOptions{})
	if err == nil {
		t.Error("an unparseable bootloader.img should be reported")
	}
	for _, want := range []string{"boot.img", "dtbo.img", "gpt.bin"} {
		if !slices.Contains(names, want) {
			t.Errorf("%s not extracted: %v", want, names)
		}
	}
	// super is the bulk of a package and is skipped unless asked for.
	if slices.Contains(names, "super.img") {
		t.Error("super written without --super")
	}
	if _, err := os.Stat(filepath.Join(out, "super.img")); err == nil {
		t.Error("super.img exists on disk without --super")
	}

	// With Super, the chunks are joined back in index order.
	out2 := filepath.Join(dir, "out2")
	ex.ExplodeStock(zipPath, out2, ExplodeOptions{Super: true})
	got, err := os.ReadFile(filepath.Join(out2, "super.img"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "AAABBB" {
		t.Errorf("super joined wrong: %q", got)
	}
}

// A gap in the chunk sequence would silently produce a short image, so it must
// fail instead.
func TestExplodeStockRefusesMissingSuperChunk(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "stock.zip")
	writeZip(t, zipPath, map[string]string{
		"bootloader.img":          "BL",
		"gpt.bin":                 "GPT",
		"super.img_sparsechunk.0": "AAA",
		"super.img_sparsechunk.2": "CCC", // 1 is missing
	})
	m, _ := For("motorola")
	ex := m.(StockExploder)
	if _, err := ex.ExplodeStock(zipPath, filepath.Join(dir, "out"), ExplodeOptions{Super: true}); err == nil {
		t.Error("a missing super chunk should be an error, not a short image")
	}
}

// donorPackage builds a blankflash carrying a loader, a recipe, a boot chain
// and a GPT -- the shape a real donor has.
func donorPackage(t *testing.T, prod string, withChain bool) []byte {
	t.Helper()
	recipe := `<?xml version="1.0" ?><recipe>
		<flash partition="xbl_a" filename="xbl.elf"/>
		<flash partition="abl_a" filename="abl.elf"/>
	</recipe>`
	recs := []blankflash.Record{
		{Name: "index.xml", Data: []byte(`<index><board id="440" name="SM_DIVAR" storage.type="UFS"/></index>`)},
		{Name: "default.xml", Data: []byte(recipe)},
		{Name: "programmer.elf", Data: []byte("LOADER")},
		{Name: "gpt.bin", Data: gptContainer(t,
			blankflash.Record{Name: "gpt_main0.bin", Data: lunImage("PROD:" + prod)},
		)},
	}
	if withChain {
		recs = append(recs,
			blankflash.Record{Name: "xbl.elf", Data: []byte("XBL")},
			blankflash.Record{Name: "abl.elf", Data: []byte("ABL")},
		)
	}
	b, err := blankflash.Build(blankflash.WithTrailer(recs))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHarvestDonorStock(t *testing.T) {
	dir := t.TempDir()
	m, _ := For("motorola")
	dh, ok := m.(DonorStockHarvester)
	if !ok {
		t.Fatal("motorola should implement DonorStockHarvester")
	}

	// A donor zip: the boot chain and GPT come back, and the GPT names the device.
	zipPath := filepath.Join(dir, "blankflash_devon.zip")
	writeZip(t, zipPath, map[string]string{"singleimage.bin": string(donorPackage(t, "devon", true))})
	got, err := dh.HarvestDonorStock(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Parts) != 2 || string(got.Parts["xbl.elf"]) != "XBL" {
		t.Errorf("boot chain not recovered: %v", got.Parts)
	}
	if code := CodenameFromStock(m, got); code != "devon" {
		t.Errorf("codename from donor GPT: %q", code)
	}

	// The bare singleimage works as well as the zip around it.
	raw := filepath.Join(dir, "singleimage.bin")
	os.WriteFile(raw, donorPackage(t, "devon", true), 0o644)
	if _, err := dh.HarvestDonorStock(raw); err != nil {
		t.Errorf("bare singleimage: %v", err)
	}

	// A loader-only donor has no stock to give; that must be an error, not an
	// empty stock entry filed against the device.
	loaderOnly := filepath.Join(dir, "loader_only.zip")
	writeZip(t, loaderOnly, map[string]string{"singleimage.bin": string(donorPackage(t, "devon", false))})
	if _, err := dh.HarvestDonorStock(loaderOnly); err == nil {
		t.Error("a donor without a boot chain should error")
	}
}

func TestSamsungOpsUnsupported(t *testing.T) {
	s, _ := For("samsung")
	if _, err := s.IngestDonor("x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("IngestDonor should wrap ErrUnsupported: %v", err)
	}
	if _, err := s.HarvestStock(TargetSource{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("HarvestStock should wrap ErrUnsupported: %v", err)
	}
	if _, err := s.Assemble(nil, nil, AssembleOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Assemble should wrap ErrUnsupported: %v", err)
	}
}
