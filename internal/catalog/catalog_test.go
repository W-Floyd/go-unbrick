package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const moto = `devices:
  - {codename: fogona, vendor: motorola, cpu_name: SM_DIVAR, name: Moto G Play 2024, soc: "SM6225", models: [XT2413], storage: [emmc, ufs]}
  - {codename: devon, vendor: motorola, cpu_name: SM_DIVAR, name: Moto G32, models: [XT2235]}
`

// A second vendor reusing the same cpu_name, to exercise disambiguation.
const other = `devices:
  - {codename: widget, vendor: acme, cpu_name: SM_DIVAR, name: Acme Widget, models: [AW1]}
`

func writeCatalog(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadAndLookup(t *testing.T) {
	c, err := Load(writeCatalog(t, map[string]string{"a.yaml": moto}))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := c.Device("fogona")
	if !ok {
		t.Fatal("fogona not found")
	}
	if d.Vendor != "motorola" || d.CPUName != "SM_DIVAR" {
		t.Errorf("fields not parsed: %+v", d)
	}
	if got := d.CPUFamily(); got != "motorola/SM_DIVAR" {
		t.Errorf("cpu family: %v", got)
	}
	if len(d.Models) != 1 || d.Models[0] != "XT2413" {
		t.Errorf("models: %v", d.Models)
	}
	sibs, _ := c.Siblings("fogona")
	if len(sibs) != 1 || sibs[0].Codename != "devon" {
		t.Errorf("siblings: %+v", sibs)
	}
}

func TestFamilyStringIsJTAGKeyed(t *testing.T) {
	f := Family{Vendor: "motorola", JTAGID: "0016F0E1"}
	if f.String() != "motorola/0016F0E1" {
		t.Errorf("family key should be vendor/JTAG: %q", f.String())
	}
}

func TestSoCByCPUName(t *testing.T) {
	c, _ := Load(writeCatalog(t, map[string]string{"a.yaml": moto}))
	if soc, ok := c.SoCByCPUName("motorola", "SM_DIVAR"); !ok || soc != "SM6225" {
		t.Errorf("SoCByCPUName: %q %v", soc, ok)
	}
	if _, ok := c.SoCByCPUName("motorola", "SM_NOPE"); ok {
		t.Error("unknown family should not be found")
	}
}

func TestJTAGIDsParsedAndNormalized(t *testing.T) {
	src := "devices:\n  - {codename: rhode, vendor: motorola, cpu_name: SM_STRAIT, name: X, jtag_id: [0016f0e1, 001B80E1]}\n"
	c, err := Load(writeCatalog(t, map[string]string{"a.yaml": src}))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := c.Device("rhode")
	if len(d.JTAGIDs) != 2 || d.JTAGIDs[0] != "0016F0E1" || d.JTAGIDs[1] != "001B80E1" {
		t.Errorf("jtag_id not parsed/uppercased: %v", d.JTAGIDs)
	}
}

func TestBadJTAGIDRejected(t *testing.T) {
	for _, bad := range []string{"[0016F0E]", "[zzzzzzzz]", "[0016F0E100]"} {
		src := "devices:\n  - {codename: x, vendor: m, cpu_name: c, jtag_id: " + bad + "}\n"
		if _, err := Load(writeCatalog(t, map[string]string{"a.yaml": src})); err == nil {
			t.Errorf("expected error for jtag_id %s", bad)
		}
	}
}

func TestDuplicateCodenameRejected(t *testing.T) {
	dup := moto + `  - {codename: fogona, vendor: motorola, cpu_name: SM_X, name: dup}` + "\n"
	if _, err := Load(writeCatalog(t, map[string]string{"a.yaml": dup})); err == nil {
		t.Error("expected duplicate codename error")
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	bad := "devices:\n  - {codename: x, vendor: m, cpu_name: c, bogus: 1}\n"
	if _, err := Load(writeCatalog(t, map[string]string{"a.yaml": bad})); err == nil {
		t.Error("expected error on unknown field (KnownFields)")
	}
}

func TestYAMLMatching(t *testing.T) {
	sampleYAML := `devices:
  - {codename: apollo, vendor: xiaomi, cpu_name: SM8250, name: "Xiaomi Mi 10T / Redmi K30S", models: [M2007J3SG]}
  - {codename: blazer, vendor: google, cpu_name: LAGUNA, name: "Google Pixel 10", models: [G1000]}
  - {codename: fogo, vendor: motorola, cpu_name: CONIC, name: "moto g 5G - 2024", models: [XT2417-1]}
`
	c, err := Load(writeCatalog(t, map[string]string{"test.yaml": sampleYAML}))
	if err != nil {
		t.Fatal(err)
	}

	// 1. MatchesVendor by codename from YAML
	if !c.MatchesVendor("xiaomi", "miui_APOLLOINGlobal_V14.0.1.0.zip") {
		t.Error("expected apollo to match xiaomi via codename from YAML")
	}
	if !c.MatchesVendor("google", "blazer-ota-bd1a.250702.001.zip") {
		t.Error("expected blazer to match google via codename from YAML")
	}
	if !c.MatchesVendor("motorola", "blankflash_fogo_retus.zip") {
		t.Error("expected fogo to match motorola via codename from YAML")
	}

	// 2. MatchesVendor by model from YAML
	if !c.MatchesVendor("motorola", "blankflash_XT2417-1_release.zip") {
		t.Error("expected XT2417-1 to match motorola via model from YAML")
	}
	if !c.MatchesVendor("xiaomi", "fastboot_M2007J3SG_images.tgz") {
		t.Error("expected M2007J3SG to match xiaomi via model from YAML")
	}

	// 3. MatchesVendor by name tokens from YAML
	if !c.MatchesVendor("google", "pixel_update.zip") {
		t.Error("expected pixel to match google via Name token from YAML")
	}
	if !c.MatchesVendor("xiaomi", "redmi_k30s_rom.zip") {
		t.Error("expected redmi to match xiaomi via Name token from YAML")
	}

	// 4. Negative matching
	if c.MatchesVendor("google", "miui_APOLLO.zip") {
		t.Error("apollo should not match google")
	}
	if c.MatchesVendor("xiaomi", "blazer-ota.zip") {
		t.Error("blazer should not match xiaomi")
	}

	// 5. ModelFromFilename and CodenameFromFilename
	if m := c.ModelFromFilename("firmware_XT2417-1.zip"); m != "XT2417-1" {
		t.Errorf("expected XT2417-1, got %q", m)
	}
	if code := c.CodenameFromFilename("ota_blazer_build.zip"); code != "blazer" {
		t.Errorf("expected blazer, got %q", code)
	}
}

func TestVariantsLoadingAndResolution(t *testing.T) {
	devicesYAML := `devices:
  - {codename: pstar, vendor: motorola, cpu_name: SM_KONA, name: "Motorola Edge 20 Pro"}
`
	variantsYAML := `variants:
  soc8250: Qualcomm SM8250 Snapdragon 865/870
  sockailua: Qualcomm SM8550 Snapdragon 8 Gen 2
`
	c, err := Load(writeCatalog(t, map[string]string{
		"devices.yaml":  devicesYAML,
		"variants.yaml": variantsYAML,
	}))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	vars := c.Variants()
	if len(vars) != 2 {
		t.Fatalf("expected 2 variants, got %d", len(vars))
	}
	if vars["soc8250"] != "Qualcomm SM8250 Snapdragon 865/870" {
		t.Errorf("soc8250 variant mismatch: %q", vars["soc8250"])
	}

	// Test ResolveVariant with variant string
	if got := c.ResolveVariant("Soc8250LAA", ""); got != "Qualcomm SM8250 Snapdragon 865/870" {
		t.Errorf("ResolveVariant(Soc8250LAA): got %q", got)
	}
	// Test ResolveVariant with QCVersion fallback
	if got := c.ResolveVariant("", "BOOT.XF.3.2-00336-KAILUA-1"); got != "Qualcomm SM8550 Snapdragon 8 Gen 2" {
		t.Errorf("ResolveVariant(QCVersion): got %q", got)
	}
	// Test ResolveVariant with unknown variant
	if got := c.ResolveVariant("SocUnknown", "UNKNOWN_VER"); got != "" {
		t.Errorf("expected empty string for unknown variant, got %q", got)
	}
}

func TestDefaultCatalogHasVariants(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	vars := c.Variants()
	if len(vars) == 0 {
		t.Fatal("expected Default() catalog to load variants from catalog/variants.yaml")
	}
	if vars["soc8250"] == "" {
		t.Error("expected soc8250 variant in default catalog")
	}
	if got := c.ResolveVariant("Soc8250LAA", ""); got != "Qualcomm SM8250 Snapdragon 865/870" {
		t.Errorf("ResolveVariant(Soc8250LAA): got %q", got)
	}
}

func TestCarrierIDName(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	// fastboot reports hex, firmware filenames spell the same CID in decimal.
	for _, in := range []string{"0x0032", "0X32", "50"} {
		if got := c.CarrierIDName("motorola", in); got != "CC channel (subsidy lock CCAWS)" {
			t.Errorf("CarrierIDName(%q): got %q", in, got)
		}
	}
	if got := c.CarrierIDName("motorola", "0xFFFF"); got != "" {
		t.Errorf("unattested CID should be unnamed, got %q", got)
	}
	if got := c.CarrierIDName("motorola", "not-a-number"); got != "" {
		t.Errorf("garbage CID should be unnamed, got %q", got)
	}
}

func TestCarrierIDReference(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	// A forum-only CID (Verizon 0x0002) has no attested name but a reference one.
	if got := c.CarrierIDName("motorola", "0x0002"); got != "" {
		t.Errorf("0x0002 is not package-attested, want empty CarrierIDName, got %q", got)
	}
	if got := c.CarrierIDReference("motorola", "0x0002"); got != "Verizon" {
		t.Errorf("CarrierIDReference(0x0002) = %q, want Verizon", got)
	}
	// Attested wins for 0x0032: carrier_ids names it, and cid_reference omits it
	// (dropped as redundant), so the reference lookup is empty there.
	if got := c.CarrierIDName("motorola", "0x0032"); got != "CC channel (subsidy lock CCAWS)" {
		t.Errorf("attested 0x0032 name changed: %q", got)
	}
	if got := c.CarrierIDReference("motorola", "0x0032"); got != "" {
		t.Errorf("0x0032 should be omitted from cid_reference, got %q", got)
	}
	// A vendor with no reference block resolves to nothing.
	if got := c.CarrierIDReference("xiaomi", "0x0002"); got != "" {
		t.Errorf("non-motorola vendor should have no CID reference, got %q", got)
	}
}

func TestUnlockEligible(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	// 0x0032 is on Motorola's published list; the retail fogona carries it.
	if eligible, known := c.UnlockEligible("motorola", "0x0032"); !known || !eligible {
		t.Errorf("0x0032: eligible=%v known=%v", eligible, known)
	}
	// The list is closed-world, so the TracFone channel's absence is an answer,
	// not a gap: known must stay true.
	if eligible, known := c.UnlockEligible("motorola", "0x0033"); !known || eligible {
		t.Errorf("0x0033: eligible=%v known=%v", eligible, known)
	}
	if eligible, known := c.UnlockEligible("motorola", "0x00DE"); !known || !eligible {
		t.Errorf("0x00DE: eligible=%v known=%v", eligible, known)
	}
	if _, known := c.UnlockEligible("motorola", "not-a-number"); known {
		t.Error("an unparseable CID cannot be judged")
	}
	// A catalog without the list must not imply every CID is ineligible.
	empty, err := Load(writeCatalog(t, map[string]string{"a.yaml": moto}))
	if err != nil {
		t.Fatal(err)
	}
	if _, known := empty.UnlockEligible("motorola", "0x0032"); known {
		t.Error("no allow-list loaded should report unknown, not ineligible")
	}
}

func TestAliasesAndCanonicalPartition(t *testing.T) {
	aliasesYAML := `aliases:
  qupv3fw.elf: qupfw
  NON-HLOS.bin: modem
`
	c, err := Load(writeCatalog(t, map[string]string{
		"aliases.yaml": aliasesYAML,
	}))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	aliases := c.Aliases()
	if len(aliases) != 2 {
		t.Fatalf("expected 2 aliases, got %d", len(aliases))
	}
	if aliases["qupv3fw.elf"] != "qupfw" {
		t.Errorf("expected qupfw, got %q", aliases["qupv3fw.elf"])
	}

	// CanonicalPartition with alias
	if p := c.CanonicalPartition("qupv3fw.elf"); p != "qupfw" {
		t.Errorf("CanonicalPartition(qupv3fw.elf): got %q", p)
	}
	if p := c.CanonicalPartition("firmware-update/NON-HLOS.bin"); p != "modem" {
		t.Errorf("CanonicalPartition(NON-HLOS.bin): got %q", p)
	}

	// CanonicalPartition extension stripping
	if p := c.CanonicalPartition("images/xbl_a.img"); p != "xbl_a" {
		t.Errorf("CanonicalPartition(xbl_a.img): got %q", p)
	}
	if p := c.CanonicalPartition("prog_firehose.mbn"); p != "prog_firehose" {
		t.Errorf("CanonicalPartition(prog_firehose.mbn): got %q", p)
	}
}

func TestVendorsAndVendorDir(t *testing.T) {
	vendorsYAML := `vendors:
  motorola:
    name: Motorola
    upstream_dir: lenovo_motorola
  xiaomi:
    upstream_dir: xiaomi
`
	c, err := Load(writeCatalog(t, map[string]string{
		"vendors.yaml": vendorsYAML,
	}))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if dir := c.VendorDir("motorola"); dir != "lenovo_motorola" {
		t.Errorf("VendorDir(motorola): got %q, want lenovo_motorola", dir)
	}
	if dir := c.VendorDir("xiaomi"); dir != "xiaomi" {
		t.Errorf("VendorDir(xiaomi): got %q, want xiaomi", dir)
	}
	if dir := c.VendorDir("unknown"); dir != "unknown" {
		t.Errorf("VendorDir(unknown): got %q, want unknown", dir)
	}
}

func TestDeviceSoCAutoResolvedFromVariants(t *testing.T) {
	devicesYAML := `devices:
  - {codename: fogo, vendor: motorola, cpu_name: CONIC, name: "moto g 5G"}
  - {codename: blazer, vendor: google, cpu_name: LAGUNA, name: "Google Pixel 10"}
`
	variantsYAML := `variants:
  conic: Qualcomm SM4375 Snapdragon 4 Gen 1
  laguna: Google Tensor G5 (Laguna)
`
	// Note: write with devices.yaml sort-ordered BEFORE variants.yaml to test two-pass resolution
	c, err := Load(writeCatalog(t, map[string]string{
		"a_devices.yaml":  devicesYAML,
		"z_variants.yaml": variantsYAML,
	}))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	dFogo, ok := c.Device("fogo")
	if !ok {
		t.Fatal("fogo not found")
	}
	if dFogo.SoC != "Qualcomm SM4375 Snapdragon 4 Gen 1" {
		t.Errorf("fogo auto-resolved SoC: got %q", dFogo.SoC)
	}

	dBlazer, ok := c.Device("blazer")
	if !ok {
		t.Fatal("blazer not found")
	}
	if dBlazer.SoC != "Google Tensor G5 (Laguna)" {
		t.Errorf("blazer auto-resolved SoC: got %q", dBlazer.SoC)
	}
}

func TestSWIDsAndEFIGUIDs(t *testing.T) {
	swidsYAML := `sw_ids:
  3: "Emergency Firehose Programmer"
  28: "ABL / Android Bootloader"
`
	guidsYAML := `efi_guids:
  8af09f13-44c5-96ec-1437-dd899cb5ee5d: "QcomPlatformCfg"
`
	c, err := Load(writeCatalog(t, map[string]string{
		"sw_ids.yaml":    swidsYAML,
		"efi_guids.yaml": guidsYAML,
	}))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if name := c.SWIDName(3); name != "Emergency Firehose Programmer" {
		t.Errorf("SWIDName(3): got %q", name)
	}
	if name := c.SWIDName(28); name != "ABL / Android Bootloader" {
		t.Errorf("SWIDName(28): got %q", name)
	}
	if name := c.SWIDName(999); name != "" {
		t.Errorf("expected empty string for unknown SW_ID, got %q", name)
	}

	if name := c.EFIGUIDName("8af09f13-44c5-96ec-1437-dd899cb5ee5d"); name != "QcomPlatformCfg" {
		t.Errorf("EFIGUIDName: got %q", name)
	}
	if name := c.EFIGUIDName("8AF09F13-44C5-96EC-1437-DD899CB5EE5D"); name != "QcomPlatformCfg" {
		t.Errorf("EFIGUIDName (case-insensitive): got %q", name)
	}
	if name := c.EFIGUIDName("00000000-0000-0000-0000-000000000000"); name != "" {
		t.Errorf("expected empty string for unknown GUID, got %q", name)
	}
}

func TestDefaultCatalogHasSWIDsAndEFIGUIDs(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	if name := c.SWIDName(3); name != "Emergency Firehose Programmer" {
		t.Errorf("Default catalog SWIDName(3): got %q", name)
	}
	if name := c.EFIGUIDName("8af09f13-44c5-96ec-1437-dd899cb5ee5d"); name != "QcomPlatformCfg" {
		t.Errorf("Default catalog EFIGUIDName: got %q", name)
	}
}

func TestDeviceAndSoCByJTAG(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}

	// Test 000BA0E1 (ginna -> MSM8953)
	d, ok := c.DeviceByJTAG("000BA0E1")
	if !ok || d.Codename != "ginna" {
		t.Fatalf("DeviceByJTAG(000BA0E1): got %v, want ginna", d)
	}
	soc, ok := c.SoCByJTAG("000ba0e1")
	if !ok || soc != "Qualcomm MSM8953 Snapdragon 625/632" {
		t.Errorf("SoCByJTAG(000ba0e1): got %q, want Qualcomm MSM8953 Snapdragon 625/632", soc)
	}

	// Unknown or wildcard JTAG
	if _, ok := c.DeviceByJTAG("00000000"); ok {
		t.Error("wildcard 00000000 should not resolve to a device")
	}
	if _, ok := c.DeviceByJTAG("FFFFFFFF"); ok {
		t.Error("unknown FFFFFFFF should not resolve")
	}

	// AddVariant in-memory test
	c.AddVariant("customtest", "Custom SoC Name")
	if resolved := c.ResolveVariant("customtest", ""); resolved != "Custom SoC Name" {
		t.Errorf("AddVariant resolve: got %q, want Custom SoC Name", resolved)
	}
}

func TestPartitionsAndSafeguards(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}

	// Test irreplaceable partitions
	for _, p := range []string{"modemst1", "modemst2", "fsg", "persist", "prodpersist", "cid"} {
		if !c.IsProtected(p) {
			t.Errorf("expected %s to be protected", p)
		}
		rule, ok := c.PartitionRule(p)
		if !ok {
			t.Errorf("missing PartitionRule for %s", p)
		}
		if rule.Criticality != "irreplaceable" {
			t.Errorf("partition %s criticality: got %s, want irreplaceable", p, rule.Criticality)
		}
	}

	// Test slot-suffixed lookups
	if !c.IsProtected("persist_a") {
		t.Error("persist_a should be protected")
	}
	if !c.IsProtected("modemst1_b") {
		t.Error("modemst1_b should be protected")
	}

	// Test replaceable bootloader partition
	if c.IsProtected("abl") {
		t.Error("abl should not be marked protected (it is replaceable)")
	}
	if rule, ok := c.PartitionRule("abl_a"); !ok || rule.Category != "boot" {
		t.Errorf("abl_a rule: got %+v, ok=%v", rule, ok)
	}

	// Test SW_ID lower 32-bit matching when anti-rollback is set
	// 0x0000000200000003: Rollback index 2, stage 3 (Emergency Firehose Programmer)
	swidWithAR := uint64(0x0000000200000003)
	if name := c.SWIDName(swidWithAR); name != "Emergency Firehose Programmer" {
		t.Errorf("SWIDName with AR: got %q, want Emergency Firehose Programmer", name)
	}
}

func TestSoftwareChannelAndSoC(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	// Channel lookup is case-insensitive (recon has "retus" from ro.carrier).
	if got := c.SoftwareChannelName("motorola", "retus"); got != "Retail USA" {
		t.Errorf("SoftwareChannelName(retus) = %q, want Retail USA", got)
	}
	if got := c.SoftwareChannelName("motorola", "nope"); got != "" {
		t.Errorf("unknown channel should be empty, got %q", got)
	}
	// The getvar cpu token resolves to its marketing SoC (Hardware line).
	if got := c.ResolveVariant("SM_DIVAR", ""); !strings.Contains(got, "Snapdragon 680") {
		t.Errorf("ResolveVariant(SM_DIVAR) = %q, want it to name Snapdragon 680", got)
	}
}
