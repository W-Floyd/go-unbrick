package port

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectAddrsFindsTheStockFixedClocks(t *testing.T) {
	root := node("", nil,
		node("clocks", nil,
			node("xo-board", map[string]string{"compatible": "fixed-clock\x00"}),
			node("not-a-clock", map[string]string{"compatible": "vendor,thing\x00"})),
		node("__symbols__", map[string]string{"xo_board": "/clocks/xo-board\x00", "other": "/clocks/not-a-clock\x00"}),
	)
	// A clock-frequency cell, as dtc writes it.
	root.Children[0].Children[0].Props["clock-frequency"] = []byte{0x04, 0x93, 0xe0, 0x00} // 76800000 = 0x0493e000
	root.Children[0].Children[0].Keys = append(root.Children[0].Children[0].Keys, "clock-frequency")

	dt := DT{Symbols: map[string]string{}, UnitAddrs: map[string]bool{}, FixedClocks: map[string]FixedClock{}}
	collectAddrs(root, &dt)
	fc, ok := dt.FixedClocks["xo_board"]
	if !ok || fc.Freq != 76800000 || fc.Name != "xo-board" {
		t.Errorf("clocks %+v", dt.FixedClocks)
	}
	if len(dt.FixedClocks) != 1 {
		t.Errorf("only fixed-clock nodes with a frequency count: %+v", dt.FixedClocks)
	}
}

func TestSiblingClockDefsCopiesOnlyClocks(t *testing.T) {
	tree := t.TempDir()
	dir := filepath.Join(tree, "arch", "arm64", "boot", "dts", "qcom")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	text := `/ {
	clocks {
		bi_tcxo_div2: bi-tcxo-div2-clk {
			compatible = "fixed-factor-clock";
			#clock-cells = <0>;
			clocks = <&rpmhcc 0>;
			clock-mult = <1>;
			clock-div = <2>;
		};
		/* sleep_clk: commented-out-clk { compatible = "fixed-clock"; }; */
	};
	soc {
		some_label: not-a-clock@1000 {
			compatible = "vendor,thing";
		};
	};
};
`
	if err := os.WriteFile(filepath.Join(dir, "sm8650.dtsi"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	ms := []SoCMatch{{File: "arch/arm64/boot/dts/qcom/sm8650.dtsi"}}
	got := SiblingClockDefs(tree, ms, []string{"bi_tcxo_div2", "some_label", "sleep_clk", "missing"})
	cd, ok := got["bi_tcxo_div2"]
	if !ok || cd.File != "sm8650.dtsi" || !strings.Contains(cd.Text, "clock-div = <2>") || !strings.HasPrefix(cd.Text, "bi-tcxo-div2-clk {") {
		t.Fatalf("got %+v", got)
	}
	if len(got) != 1 {
		t.Errorf("only a fixed clock is copied (not a device node, a comment, or a missing label): %v", got)
	}
}

func TestNeededLabelsWritesStockClocksCopiesSiblingsAndListsTheRest(t *testing.T) {
	p := Package{
		SoC:      []SoCMatch{{File: "arch/arm64/boot/dts/qcom/kaanapali.dtsi"}},
		SoCFacts: SoCDTSIFacts{Needs: []string{"bi_tcxo_div2", "sleep_clk", "vreg_x"}},
		DT:       DT{FixedClocks: map[string]FixedClock{"sleep_clk": {Label: "sleep_clk", Name: "sleep_clk", Freq: 32000}}},
		ClockDefs: map[string]ClockDef{"bi_tcxo_div2": {Label: "bi_tcxo_div2", File: "sm8650.dtsi",
			Text: "bi-tcxo-div2-clk {\n\t\t\tcompatible = \"fixed-factor-clock\";\n\t\t\tclock-div = <2>;\n\t\t}"}},
	}
	got := p.neededLabels()
	for _, want := range []string{
		"sleep_clk: sleep-clk {", "clock-frequency = <32000>;",
		"bi_tcxo_div2: bi-tcxo-div2-clk {", "clock-div = <2>;", "};", "TODO: copied from sm8650.dtsi",
		"TODO: kaanapali.dtsi refers to labels it does not define", "vreg_x",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "refers to labels it does not define") {
			if strings.Contains(line, "sleep_clk") || strings.Contains(line, "bi_tcxo_div2") || !strings.HasSuffix(line, "vreg_x */") {
				t.Errorf("only the label with no definition may be listed as still needed: %s", line)
			}
		}
	}
}

func TestZeroSizeRegionIsNotAReservation(t *testing.T) {
	n := node("demura_region_0", map[string]string{"reg": "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"})
	r, ok := regionOf(n)
	if !ok || r.Fixed {
		t.Errorf("%+v ok=%v: a reg of <0 0 0 0> is a bootloader placeholder, not a fixed region", r, ok)
	}
}
