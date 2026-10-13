package port

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKconfigSymbolsAndCompareConfig(t *testing.T) {
	tree := t.TempDir()
	write := func(path, text string) {
		full := filepath.Join(tree, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("drivers/input/touchscreen/Kconfig", "menu \"Touch\"\nconfig TOUCHSCREEN_HIMAX_COMMON\n\ttristate \"himax\"\nmenuconfig INPUT_TOUCH\n\tbool\nendmenu\n")
	write("arch/arm64/Kconfig", "config ARCH_QCOM\n\tbool \"Qualcomm\"\n")
	write("Documentation/Kconfig", "config NOT_SCANNED\n\tbool\n") // outside the walked directories

	syms := KconfigSymbols(tree)
	for _, s := range []string{"TOUCHSCREEN_HIMAX_COMMON", "INPUT_TOUCH", "ARCH_QCOM"} {
		if !syms[s] {
			t.Errorf("missing %s in %v", s, syms)
		}
	}
	if syms["NOT_SCANNED"] {
		t.Error("a Kconfig outside the walked directories was read")
	}

	stock := map[string]string{
		"CONFIG_ARCH_QCOM":                 "y",
		"CONFIG_TOUCHSCREEN_HIMAX_COMMON":  "m",
		"CONFIG_CMDLINE":                   "cgroup_disable=pressure",
		"CONFIG_QCOM_MSM_DOWNSTREAM_ONE":   "y",
		"CONFIG_QCOM_MSM_DOWNSTREAM_TWO":   "y",
		"CONFIG_QCOM_MSM_DOWNSTREAM_THREE": "y",
		"CONFIG_INPUT_TOUCH":               "n", // unset in stock: says nothing
	}
	d := CompareConfig(stock, syms)
	if d.Have != 2 || len(d.Missing) != 4 {
		t.Fatalf("have %d missing %v (CMDLINE is not an option this tree defines here)", d.Have, d.Missing)
	}
	for _, want := range []string{"CONFIG_ARCH_QCOM=y", "CONFIG_TOUCHSCREEN_HIMAX_COMMON=m"} {
		if !strings.Contains(d.Fragment, want) {
			t.Errorf("fragment lacks %q:\n%s", want, d.Fragment)
		}
	}
	if strings.Contains(d.Fragment, "INPUT_TOUCH") || strings.Contains(d.Fragment, "DOWNSTREAM") {
		t.Errorf("fragment has options it should not:\n%s", d.Fragment)
	}
	if sec := ConfigDiffSection(&d, "tree"); !strings.Contains(sec, "`QCOM_*` ×3") {
		t.Errorf("section:\n%s", sec)
	}
	if ConfigDiffSection(nil, "tree") != "" {
		t.Error("no diff, no section")
	}
}
