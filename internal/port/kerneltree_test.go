package port

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestScanKernelTree(t *testing.T) {
	root := writeTree(t, map[string]string{
		"drivers/input/touch/acme.c": `static const struct of_device_id ids[] = {
	{ .compatible = "acme,thing" },
	{ .compatible = "acme,other" },
};
MODULE_FIRMWARE("acme/thing_fw.bin");
static const char *fmt = "qcom/a%d_sqe.fw";
	cfg.init_data = NULL; psy_cfg.fwnode = x; volume_desc.init_volume = 1;`,
		"drivers/misc/unrelated.c":                    `int x; /* no match table here */`,
		"sound/soc/codecs/amp.c":                      `{ .compatible = "acme,amp" }`,
		"Documentation/devicetree/bindings/acme.yaml": "properties:\n  compatible:\n    enum:\n      - acme,thing\n      - acme,bindingonly\n",
	})
	got, err := ScanKernelTree(root, []string{"acme,thing", "acme,amp", "acme,bindingonly", "acme,nowhere"})
	if err != nil {
		t.Fatal(err)
	}
	thing := got["acme,thing"]
	if len(thing.Sources) != 1 || thing.Sources[0] != "drivers/input/touch/acme.c" {
		t.Errorf("thing sources %v", thing.Sources)
	}
	if len(thing.Bindings) != 1 || !strings.HasSuffix(thing.Bindings[0], "acme.yaml") {
		t.Errorf("thing bindings %v", thing.Bindings)
	}
	if strings.Join(thing.Firmware, " ") != "thing_fw.bin" {
		t.Errorf("firmware %v: a printf fragment (d_sqe.fw) is not a file name", thing.Firmware)
	}
	if len(got["acme,amp"].Sources) != 1 {
		t.Errorf("sound/ is searched too: %v", got["acme,amp"].Sources)
	}
	if b := got["acme,bindingonly"]; len(b.Sources) != 0 || len(b.Bindings) != 1 {
		t.Errorf("binding only: %+v", b)
	}
	if n := got["acme,nowhere"]; n == nil || len(n.Sources)+len(n.Bindings) != 0 {
		t.Errorf("an unsupported compatible is still reported, with nothing: %+v", n)
	}
}

func TestScanKernelTreeOffersSimilarCompatibles(t *testing.T) {
	root := writeTree(t, map[string]string{
		"drivers/power/supply/bq25890.c": `{ .compatible = "ti,bq25890" }, { .compatible = "ti,bq25892" }, { .compatible = "ti,other" }`,
	})
	got, err := ScanKernelTree(root, []string{"ti,bq2589x-1", "ti,bq25890", "acme,bq2589x"})
	if err != nil {
		t.Fatal(err)
	}
	// The vendor's variant is not in the tree; its siblings are offered.
	if s := strings.Join(got["ti,bq2589x-1"].Similar, " "); !strings.Contains(s, "ti,bq25890 (drivers/power/supply/bq25890.c)") || !strings.Contains(s, "ti,bq25892") || strings.Contains(s, "ti,other") {
		t.Errorf("similar %q", s)
	}
	// An exact match needs no suggestions, and a different vendor gets none.
	if len(got["ti,bq25890"].Similar) != 0 || len(got["acme,bq2589x"].Similar) != 0 {
		t.Errorf("unexpected similar: %v %v", got["ti,bq25890"].Similar, got["acme,bq2589x"].Similar)
	}
}

func TestSimilarUsesTheVendorBeforeADashAndSmallVendorsInFull(t *testing.T) {
	root := writeTree(t, map[string]string{
		"drivers/input/chipone.c": `{ .compatible = "chipone,icnl9916" }, { .compatible = "chipone,icn6211" }`,
		"drivers/misc/big.c":      `{ .compatible = "bigco,a1" }, { .compatible = "bigco,b2" }, { .compatible = "bigco,c3" }, { .compatible = "bigco,d4" }, { .compatible = "bigco,e5" }`,
	})
	got, err := ScanKernelTree(root, []string{"chipone-tddi", "bigco-zzzzz"})
	if err != nil {
		t.Fatal(err)
	}
	// "chipone-tddi" has no comma; its vendor is chipone, which has two entries.
	if s := strings.Join(got["chipone-tddi"].Similar, " "); !strings.Contains(s, "chipone,icnl9916") || !strings.Contains(s, "chipone,icn6211") {
		t.Errorf("small vendor not listed in full: %q", s)
	}
	// A vendor with many entries and no close name gets nothing, not a dump.
	if s := got["bigco-zzzzz"].Similar; len(s) != 0 {
		t.Errorf("a large vendor must not be dumped: %v", s)
	}
}

func TestScanKernelTreeRejectsANonTree(t *testing.T) {
	if _, err := ScanKernelTree(t.TempDir(), []string{"a,b"}); err == nil {
		t.Error("a directory with no drivers/ is not a kernel tree")
	}
}

func TestMainlineFirmwareBecomesAReferenceEvenWhenAbsent(t *testing.T) {
	p := Package{
		FileIndex: map[string][]string{"stock_fw.bin": {"vendor_a:firmware/stock_fw.bin"}},
		DT:        DT{Parts: []Part{{Compatible: "acme,thing"}}},
		Mainline:  map[string]*MainlineDriver{"acme,thing": {Sources: []string{"drivers/x/acme.c"}, Firmware: []string{"mainline_fw.bin"}}},
	}
	r := refBy(FirmwareRefs(p), "mainline_fw.bin")
	if r == nil || r.By[0] != "mainline drivers/x/acme.c" || len(r.Where) != 0 {
		t.Errorf("got %+v: the file the mainline driver asks for is a need even though the package lacks it", r)
	}
}
