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

func TestCarrierFromFlashfile(t *testing.T) {
	ff := []byte(`<?xml version="1.0" ?>
<flashing>
  <header>
    <phone_model model="fogona_g"/>
    <subsidy_lock_config MD5="3cd2" name="slcf_rev_d_ccaws_v5.0.nvm"/>
    <cid_value value="0x0032"/>
  </header>
  <steps interface="AP">
    <step operation="flash" partition="bootloader" filename="bootloader.img"/>
  </steps>
</flashing>`)
	cid, slcf := carrierFromFlashfile(ff)
	if cid != "0x0032" || slcf != "slcf_rev_d_ccaws_v5.0.nvm" {
		t.Errorf("got cid=%q slcf=%q", cid, slcf)
	}
	// A service/donor package has no channel header; that is not an error.
	for _, b := range [][]byte{nil, []byte("not xml"), []byte(`<flashing><steps/></flashing>`)} {
		if cid, slcf := carrierFromFlashfile(b); cid != "" || slcf != "" {
			t.Errorf("headerless input yielded cid=%q slcf=%q", cid, slcf)
		}
	}
}

func TestEDLCommandsAreVendorSpecific(t *testing.T) {
	// Motorola's own route leads; nothing else is fired at it first.
	moto := EDLCommands(motorola{})
	if len(moto) == 0 || strings.Join(moto[0], " ") != "oem blankflash" {
		t.Errorf("motorola EDL route: %v", moto)
	}
	for _, c := range moto {
		if strings.Join(c, " ") == "reboot edl" {
			t.Error("a target current AOSP fastboot rejects locally should not be in a known-vendor route")
		}
	}
	// A driver with no EDL route says so by omitting the capability, rather than
	// inheriting another vendor's commands.
	if got := EDLCommands(google{}); got != nil {
		t.Errorf("google should offer no EDL route, got %v", got)
	}
	if got := EDLCommands(qualcomm{}); len(got) == 0 {
		t.Error("the generic Qualcomm driver should carry the reference routes")
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

func TestQualcommDriver(t *testing.T) {
	q, ok := For("qualcomm")
	if !ok {
		t.Fatal("qualcomm driver not found")
	}
	if q.Platform() != PlatformQualcomm {
		t.Errorf("got platform %q, want %q", q.Platform(), PlatformQualcomm)
	}
	if len(q.OEMIDs()) != 1 || q.OEMIDs()[0] != "0000" {
		t.Errorf("unexpected OEMIDs: %v", q.OEMIDs())
	}

	dir := t.TempDir()
	progPath := filepath.Join(dir, "prog_firehose_lite.elf")
	os.WriteFile(progPath, []byte("QUALCOMM_PROGRAMMER"), 0o644)

	if !q.CanIngest(progPath) {
		t.Errorf("CanIngest should be true for %s", progPath)
	}

	donor, err := q.IngestDonor(progPath)
	if err != nil {
		t.Fatalf("IngestDonor failed: %v", err)
	}
	if string(donor.Programmer) != "QUALCOMM_PROGRAMMER" {
		t.Errorf("unexpected programmer: %s", string(donor.Programmer))
	}

	// Test HarvestStock from dumps dir
	dumpsDir := filepath.Join(dir, "dumps")
	os.MkdirAll(dumpsDir, 0o755)
	os.WriteFile(filepath.Join(dumpsDir, "xbl_a.img"), []byte("XBL_BYTES"), 0o644)
	os.WriteFile(filepath.Join(dumpsDir, "abl_a.img"), []byte("ABL_BYTES"), 0o644)
	os.WriteFile(filepath.Join(dumpsDir, "gpt.bin"), []byte("GPT_BYTES"), 0o644)

	tgt, err := q.HarvestStock(TargetSource{Parts: dumpsDir, Slot: "a"})
	if err != nil {
		t.Fatalf("HarvestStock failed: %v", err)
	}
	if len(tgt.Parts) < 2 {
		t.Errorf("expected harvested parts, got %v", tgt.Parts)
	}

	// Test Assemble
	res, err := q.Assemble(donor, tgt, AssembleOptions{Slot: "a"})
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}
	if res.Singleimage != nil {
		t.Errorf("standard Qualcomm should not produce Singleimage")
	}
	if _, ok := res.Aux["rawprogram0.xml"]; !ok {
		t.Errorf("missing rawprogram0.xml in Aux")
	}
	if _, ok := res.Aux["prog_firehose_lite.elf"]; !ok {
		t.Errorf("missing prog_firehose_lite.elf in Aux")
	}
}

// TestContentBasedIngestion verifies that all vendor drivers detect formats by content/magics
// first, even when filenames are completely arbitrary, non-standard, or obfuscated.
func TestContentBasedIngestion(t *testing.T) {
	dir := t.TempDir()

	// 1. Samsung PIT magic (0x12349876) with arbitrary filename
	samsungFile := filepath.Join(dir, "arbitrary_data.bin")
	os.WriteFile(samsungFile, []byte{0x76, 0x98, 0x34, 0x12, 0x00, 0x00, 0x00, 0x01}, 0o644)
	if sDriver, ok := For("samsung"); !ok || !sDriver.CanIngest(samsungFile) {
		t.Errorf("Samsung CanIngest failed to detect PIT binary magic in %s", samsungFile)
	}

	// 2. MediaTek scatter content with arbitrary filename
	mtkScatter := filepath.Join(dir, "instructions.txt")
	os.WriteFile(mtkScatter, []byte("##################\nMTK_PLATFORM_CFG\nplatform: MT6765\npartition_index: SYS0\n"), 0o644)
	if mtkDriver, ok := For("mediatek"); !ok || !mtkDriver.CanIngest(mtkScatter) {
		t.Errorf("MediaTek CanIngest failed to detect MTK_PLATFORM_CFG in %s", mtkScatter)
	}

	// 3. MediaTek preloader binary magic (EMMC_BOOT) with arbitrary filename
	mtkPreloader := filepath.Join(dir, "boot_header.bin")
	os.WriteFile(mtkPreloader, []byte("EMMC_BOOT\x00\x00\x00\x01\x00\x00"), 0o644)
	if mtkDriver, ok := For("mediatek"); !ok || !mtkDriver.CanIngest(mtkPreloader) {
		t.Errorf("MediaTek CanIngest failed to detect EMMC_BOOT magic in %s", mtkPreloader)
	}

	// 4. Qualcomm rawprogram XML with arbitrary filename
	qcRawProg := filepath.Join(dir, "partition_table.xml")
	os.WriteFile(qcRawProg, []byte(`<?xml version="1.0" ?><data><program SECTOR_SIZE_IN_BYTES="512" filename="xbl.elf" label="xbl"/></data>`), 0o644)
	if qcDriver, ok := For("qualcomm"); !ok || !qcDriver.CanIngest(qcRawProg) {
		t.Errorf("Qualcomm CanIngest failed to detect rawprogram XML in %s", qcRawProg)
	}

	// 5. Qualcomm Firehose binary content with arbitrary filename
	qcFirehose := filepath.Join(dir, "firmware_chunk.bin")
	os.WriteFile(qcFirehose, []byte("\x7fELF\x02\x01\x01\x00Qualcomm Firehose Loader version 1.0"), 0o644)
	if qcDriver, ok := For("qualcomm"); !ok || !qcDriver.CanIngest(qcFirehose) {
		t.Errorf("Qualcomm CanIngest failed to detect Firehose marker in %s", qcFirehose)
	}

	// 6. Motorola SINGLE_N_LONELY container magic with arbitrary filename
	motoContainer := filepath.Join(dir, "firmware.rom")
	blob, _ := blankflash.Build(blankflash.WithTrailer([]blankflash.Record{{Name: "programmer.elf", Data: []byte("x")}}))
	os.WriteFile(motoContainer, blob, 0o644)
	if motoDriver, ok := For("motorola"); !ok || !motoDriver.CanIngest(motoContainer) {
		t.Errorf("Motorola CanIngest failed to detect SINGLE_N_LONELY container in %s", motoContainer)
	}

	// 7. Google Pixel stock OTA zip detected by metadata content (post-build=google/)
	pixelZip := filepath.Join(dir, "android_update.zip")
	writeZip(t, pixelZip, map[string]string{
		"META-INF/com/android/metadata": "post-build=google/blazer/blazer:16/BD1A.250702.001/1234:user/release-keys\npre-device=blazer\n",
	})
	if googleDriver, ok := For("google"); !ok || !googleDriver.CanIngest(pixelZip) {
		t.Errorf("Google CanIngest failed to detect post-build=google/ in %s", pixelZip)
	}

	// 8. Xiaomi stock OTA zip detected by metadata content (post-build=xiaomi/)
	xiaomiZip := filepath.Join(dir, "custom_update.zip")
	writeZip(t, xiaomiZip, map[string]string{
		"META-INF/com/android/metadata": "post-build=xiaomi/apollo/apollo:12/SKQ1.211006.001/V14.0.1.0:user/release-keys\n",
	})
	if xiaomiDriver, ok := For("xiaomi"); !ok || !xiaomiDriver.CanIngest(xiaomiZip) {
		t.Errorf("Xiaomi CanIngest failed to detect post-build=xiaomi/ in %s", xiaomiZip)
	}
}
