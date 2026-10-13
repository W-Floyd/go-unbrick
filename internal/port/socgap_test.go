package port

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDTSI(t *testing.T, dir, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestComputeSoCGap(t *testing.T) {
	tree := t.TempDir()
	dir := filepath.Join(tree, "arch", "arm64", "boot", "dts", "qcom")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// sm6225 includes sm6115, which defines the uart; the crypto block is in
	// neither, but agatti has one by that compatible; the qseecom is nowhere.
	writeDTSI(t, dir, "sm6225.dtsi", "#include \"sm6115.dtsi\"\n/ { soc { gcc: clock@1400000 { compatible = \"qcom,gcc\"; }; }; };\n")
	writeDTSI(t, dir, "sm6115.dtsi", "/ { soc { uart@4a90000 { compatible = \"qcom,geni-uart\"; }; }; };\n")
	writeDTSI(t, dir, "agatti.dtsi", "/ { soc { crypto@1b3a000 { compatible = \"qcom,crypto-v5\"; }; }; };\n")
	for i := 0; i < genericCompatFiles; i++ {
		writeDTSI(t, dir, "gen"+string(rune('a'+i))+".dtsi", "/ { x { compatible = \"syscon\"; }; };\n")
	}
	// Two blocks no dtsi names: one a driver's match table does, one a binding
	// schema lists (unquoted, as YAML does).
	for path, text := range map[string]string{
		"drivers/misc/foo.c":                              "static const struct of_device_id m[] = { { .compatible = \"qcom,foo-driver\" }, {} };\n",
		"Documentation/devicetree/bindings/misc/bar.yaml": "properties:\n  compatible:\n    enum:\n      - qcom,bar-binding\n",
	} {
		full := filepath.Join(tree, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	p := Package{
		SoC: []SoCMatch{{File: "arch/arm64/boot/dts/qcom/sm6225.dtsi"}, {File: "arch/arm64/boot/dts/qcom/agatti.dtsi"}},
		DT: DT{SoCNodes: []SoCNode{
			{Name: "clock@1400000", Addr: "1400000", Compatible: []string{"qcom,gcc"}},
			{Name: "serial@4a90000", Addr: "4a90000", Compatible: []string{"qcom,geni-uart"}},
			{Name: "crypto@1b3a000", Addr: "1b3a000", Compatible: []string{"qcom,crypto-v5"}},
			{Name: "qseecom@61800000", Addr: "61800000", Compatible: []string{"qcom,qseecom"}},
			{Name: "syscon@5991008", Addr: "5991008", Compatible: []string{"syscon"}},
			{Name: "foo@7000000", Addr: "7000000", Compatible: []string{"qcom,foo-driver"}},
			{Name: "bar@8000000", Addr: "8000000", Compatible: []string{"qcom,bar-binding"}},
		}},
	}
	g := ComputeSoCGap(tree, p)
	if g == nil || g.Present != 2 || len(g.Missing) != 5 || g.Siblings != 1 {
		t.Fatalf("got %+v", g)
	}
	byAddr := map[string]MissingBlock{}
	for _, m := range g.Missing {
		byAddr[m.Node.Addr] = m
	}
	if s := byAddr["1b3a000"].Sibling; len(s) != 1 || s[0] != "agatti.dtsi" {
		t.Errorf("crypto sibling: %v", s)
	}
	if m := byAddr["61800000"]; len(m.Sibling) != 0 || m.Generic || m.InCode {
		t.Errorf("qseecom is named nowhere: %+v", m)
	}
	for _, a := range []string{"7000000", "8000000"} {
		if m := byAddr[a]; len(m.Sibling) != 0 || !m.InCode {
			t.Errorf("%s is named by a driver or binding: %+v", a, m)
		}
	}
	if m := byAddr["5991008"]; len(m.Sibling) != 0 || !m.Generic {
		t.Errorf("syscon is generic: %+v", m)
	}
	sec := SoCGapSection(g)
	for _, want := range []string{"defines 2 of them; 5 are missing", "2 are named by a driver or binding but no dtsi", "1 carry only a generic compatible", "1 are named nowhere", "a driver or binding only", "generic compatible only", "agatti.dtsi"} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %q:\n%s", want, sec)
		}
	}
	if ComputeSoCGap(tree, Package{}) != nil {
		t.Error("no SoC match, no gap")
	}
}
