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
