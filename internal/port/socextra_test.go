package port

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, text := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A SoC supported outside the tree: a dtsi that includes a mainline one from
// the tree and adds the blocks the new SoC has.
func TestOutOfTreeSoCDtsiIsMatchedAndUsedLikeTheTreesOwn(t *testing.T) {
	tree, extra := t.TempDir(), t.TempDir()
	writeFiles(t, tree, map[string]string{
		"arch/arm64/boot/dts/mediatek/mt8183.dtsi": "/ {\n\tsoc {\n\t\tuart0: serial@11002000 {\n\t\t};\n\t\ti2c0: i2c@11007000 {\n\t\t};\n\t};\n};\n",
	})
	writeFiles(t, extra, map[string]string{
		"mt6768.dtsi": "#include \"mt8183.dtsi\"\n/* mediatek,mt6768 */\n/ {\n\tsoc {\n\t\tmdss_dsi0: dsi@14014000 {\n\t\t\tclocks = <&new_clk>;\n\t\t};\n\t};\n};\n",
	})
	stock := map[string]bool{"11002000": true, "11007000": true, "14014000": true, "13000000": true}

	inTree, err := FindSoCDTSI(tree, stock)
	if err != nil || len(inTree) != 1 || inTree[0].Shared != 2 {
		t.Fatalf("in tree: %+v %v", inTree, err)
	}
	more, err := FindExtraSoCDTSI(tree, []string{extra}, stock)
	if err != nil || len(more) != 1 {
		t.Fatalf("extra: %+v %v", more, err)
	}
	if !filepath.IsAbs(more[0].File) || more[0].Shared != 3 {
		t.Errorf("the out-of-tree file is scored on itself and what it includes (3 of 4 addresses): %+v", more[0])
	}
	ms := MergeSoCMatches(inTree, more)
	if ms[0].File != more[0].File {
		t.Errorf("the closer match ranks first: %+v", ms)
	}

	labels := SoCLabels(tree, ms[0].File)
	if !labels["mdss_dsi0"] || !labels["i2c0"] {
		t.Errorf("labels come from the file and the tree dtsi it includes: %v", labels)
	}
	if got := SoCLabelsByAddr(tree, ms[0].File); got["14014000"] != "mdss_dsi0" || got["11007000"] != "i2c0" {
		t.Errorf("by address: %v", got)
	}
	if f := ReadSoCDTSI(tree, ms[0].File); strings.Join(f.Needs, " ") != "new_clk" {
		t.Errorf("needs %v (new_clk is used and defined nowhere)", f.Needs)
	}

	p := Package{SoC: ms, DT: DT{SoCNodes: []SoCNode{
		{Name: "serial@11002000", Addr: "11002000"}, {Name: "dsi@14014000", Addr: "14014000"}, {Name: "x@13000000", Addr: "13000000"},
	}}}
	g := ComputeSoCGap(tree, p)
	if g == nil || g.Present != 2 || len(g.Missing) != 1 || len(g.Files) != 2 {
		t.Errorf("the gap is against the closure: %+v", g)
	}
}

func TestSoCReportSaysWhenTheBestMatchDoesNotNameTheSoC(t *testing.T) {
	tree := t.TempDir()
	writeFiles(t, tree, map[string]string{
		"arch/arm64/boot/dts/mediatek/mt8183.dtsi": "/ { soc { compatible = \"mediatek,mt8183\"; }; };\n",
		"arch/arm64/boot/dts/mediatek/mt6768.dtsi": "/ { soc { compatible = \"mediatek,mt6768\"; }; };\n",
	})
	ms := []SoCMatch{{File: "arch/arm64/boot/dts/mediatek/mt8183.dtsi", Score: 0.31}}
	if got := SoCReport(tree, ms, "mediatek,MT6768"); !strings.Contains(got, "nothing in it names `mediatek,MT6768`") || !strings.Contains(got, "--soc-dtsi") {
		t.Errorf("a dtsi that does not name the SoC:\n%s", got)
	}
	ms[0].File = "arch/arm64/boot/dts/mediatek/mt6768.dtsi"
	if got := SoCReport(tree, ms, "mediatek,MT6768"); strings.Contains(got, "--soc-dtsi") {
		t.Errorf("a dtsi that names it needs no hint:\n%s", got)
	}
	ms[0].File = "/elsewhere/mt6768.dtsi"
	if got := SoCReport(tree, ms, ""); !strings.Contains(got, "(out of tree) /elsewhere/mt6768.dtsi") {
		t.Errorf("an out-of-tree row is marked:\n%s", got)
	}
}
