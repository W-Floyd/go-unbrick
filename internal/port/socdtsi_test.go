package port

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSoCDTSIFindsWhatTheBoardMustProvideAndInterruptCells(t *testing.T) {
	tree := t.TempDir()
	dir := filepath.Join(tree, "arch", "arm64", "boot", "dts", "qcom")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("soc.dtsi", `#include "base.dtsi"
/ {
	soc {
		tlmm: pinctrl@f100000 {
			gpio-controller;
			#interrupt-cells = <2>;
			child { #interrupt-cells = <9>; };
		};
		spmi_bus: spmi@c40000 {
			#interrupt-cells = <4>;
		};
		clock-controller@100000 {
			clocks = <&bi_tcxo_div2>, <&sleep_clk>, <&gcc 0>;
		};
		/* clocks = <&only_in_a_comment>; */
	};
};
`)
	write("base.dtsi", "/ {\n\tgcc: clock-controller@1400000 {\n\t};\n};\n")

	f := ReadSoCDTSI(tree, "arch/arm64/boot/dts/qcom/soc.dtsi")
	if got := strings.Join(f.Needs, " "); got != "bi_tcxo_div2 sleep_clk" {
		t.Errorf("needs %q (a label defined in an included file or only named in a comment is not a need)", got)
	}
	if f.InterruptCells["tlmm"] != 2 || f.InterruptCells["spmi_bus"] != 4 {
		t.Errorf("interrupt cells %v (a child's #interrupt-cells is not the parent's)", f.InterruptCells)
	}
	labels := SoCLabels(tree, "arch/arm64/boot/dts/qcom/soc.dtsi")
	if !labels["tlmm"] || !labels["gcc"] || labels["sleep_clk"] {
		t.Errorf("labels %v", labels)
	}
}

func TestPinRefProblem(t *testing.T) {
	p := Package{
		SoCLabels: map[string]bool{"tlmm": true, "spmi_bus": true},
		SoCFacts:  SoCDTSIFacts{InterruptCells: map[string]int{"tlmm": 2, "spmi_bus": 4}},
	}
	if why := p.pinRefProblem(PinUse{Kind: PinIRQ, Ctrl: "tlmm"}); why != "" {
		t.Errorf("tlmm: %q", why)
	}
	if why := p.pinRefProblem(PinUse{Kind: PinIRQ, Ctrl: "spmi_bus"}); !strings.Contains(why, "4 interrupt cells") {
		t.Errorf("spmi: %q", why)
	}
	if why := p.pinRefProblem(PinUse{Kind: PinReset, Ctrl: "spmi_bus"}); why != "" {
		t.Errorf("a reset gpio is not an interrupt: %q", why)
	}
	if why := p.pinRefProblem(PinUse{Kind: PinReset, Ctrl: "nowhere"}); !strings.Contains(why, "no label") {
		t.Errorf("unknown label: %q", why)
	}
	if why := (Package{}).pinRefProblem(PinUse{Kind: PinIRQ, Ctrl: "anything"}); why != "" {
		t.Errorf("no dtsi to check: %q", why)
	}
}
