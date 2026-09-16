package catalog

import (
	"os"
	"path/filepath"
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

