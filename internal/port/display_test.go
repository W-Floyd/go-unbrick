package port

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func displayPackage() Package {
	return Package{
		SoC:       []SoCMatch{{File: "arch/arm64/boot/dts/qcom/sm6225.dtsi"}},
		SoCLabels: map[string]bool{"mdss": true, "mdss_dsi0": true, "mdss_dsi0_out": true, "mdss_dsi0_phy": true, "tlmm": true},
		SoCAddrLabels: map[string]string{
			"5e94000": "mdss_dsi0", "5e94400": "mdss_dsi0_phy",
		},
		DT: DT{
			DisplayNodes: []SoCNode{
				{Name: "qcom,mdss_dsi_ctrl0", Addr: "5e94000", Compatible: []string{"qcom,dsi-ctrl-hw-v2.4"}},
				{Name: "qcom,mdss_dsi_phy0", Addr: "5e94400", Compatible: []string{"qcom,dsi-phy-v2.0"}},
			},
			Panels: []Panel{
				{Name: "tm panel", Referenced: true, Default: true, Reset: PanelGPIO{Ctrl: "tlmm", Pin: 82, Set: true}, BLType: "bl_ctrl_dcs"},
				{Name: "other panel", Referenced: true, Reset: PanelGPIO{Ctrl: "tlmm", Pin: 86, Set: true}},
				{Name: "reference only"},
			},
		},
	}
}

func TestDisplayDTSWiresTheDefaultPanelOnTheDSIControllerByAddress(t *testing.T) {
	got := displayPackage().displayDTS()
	for _, want := range []string{
		"&mdss {", "&mdss_dsi0 {", `compatible = "TODO,tm-panel";`,
		"reset-gpios = <&tlmm 82 GPIO_ACTIVE_LOW>;", "remote-endpoint = <&mdss_dsi0_out>;",
		"&mdss_dsi0_out {", "remote-endpoint = <&panel_in>;", "data-lanes = <0 1 2 3>;", "&mdss_dsi0_phy {",
		"backlight: the stock node says bl_ctrl_dcs",
		`Stock variant, not wired (a unit has one panel): other panel as "TODO,other-panel"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "reference only") || strings.Contains(got, "pin 86") && strings.Contains(got, "reset-gpios = <&tlmm 86") {
		t.Errorf("only referenced panels are candidates and only one is wired:\n%s", got)
	}
}

func TestDisplayDTSFollowsTheLivePanel(t *testing.T) {
	p := displayPackage()
	p.Live = &Live{HaveChosen: true, Chosen: map[string]string{"mmi,panel_name": "other_panel_vid"}}
	p.DT.Panels[0].Name, p.DT.Panels[1].Name = "tm_panel", "other_panel"
	got := p.displayDTS()
	if !strings.Contains(got, `compatible = "TODO,other-panel";`) || !strings.Contains(got, "reset-gpios = <&tlmm 86") {
		t.Errorf("the live panel should be the one wired:\n%s", got)
	}
}

func TestDisplayDTSLeavesWhatTheDtsiLacksAsTODOs(t *testing.T) {
	p := displayPackage()
	delete(p.SoCLabels, "mdss_dsi0_out")
	delete(p.SoCLabels, "tlmm")
	got := p.displayDTS()
	for _, want := range []string{`no label "mdss_dsi0_out"`, `has no label "tlmm"`} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "&mdss_dsi0_out {") || strings.Contains(got, "reset-gpios = <&tlmm") {
		t.Errorf("a label the dtsi does not define must not be referred to:\n%s", got)
	}

	p = displayPackage()
	p.DT.DisplayNodes = nil // no stock DSI controller to place
	if got := p.displayDTS(); !strings.Contains(got, "wire the panel by hand") || strings.Contains(got, "&cpu0") {
		t.Errorf("no controller address must not fall through to a label for address 0:\n%s", got)
	}
	p = displayPackage()
	p.SoCLabels = nil
	if got := p.displayDTS(); !strings.Contains(got, "needs --kernel-tree") {
		t.Errorf("without a tree: %s", got)
	}
}

func TestSoCLabelsByAddrSkipsAddressZero(t *testing.T) {
	tree := t.TempDir()
	dir := filepath.Join(tree, "arch", "arm64", "boot", "dts", "qcom")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dtsi := "/ {\n\tcpus {\n\t\tcpu0: cpu@0 {\n\t\t};\n\t};\n\tsoc {\n\t\tmdss_dsi0: dsi@5e94000 {\n\t\t};\n\t\t/* old: dsi@1000000 { */\n\t};\n};\n"
	if err := os.WriteFile(filepath.Join(dir, "soc.dtsi"), []byte(dtsi), 0o644); err != nil {
		t.Fatal(err)
	}
	got := SoCLabelsByAddr(tree, "arch/arm64/boot/dts/qcom/soc.dtsi")
	if got["5e94000"] != "mdss_dsi0" {
		t.Errorf("got %v", got)
	}
	if _, bad := got[""]; bad || len(got) != 1 {
		t.Errorf("address 0 (a CPU) is no register address, and a commented node is not a node: %v", got)
	}
}

func TestDisplayNodeUsesRegWhenTheNameHasNoAddress(t *testing.T) {
	n := node("qcom,mdss_dsi0_ctrl", map[string]string{
		"compatible": "qcom,dsi-ctrl-hw-v2.4\x00",
		"reg":        "\x05\xe9\x40\x00\x00\x00\x04\x00", // <0x5e94000 0x400>
	})
	dn, ok := displayNode("/soc/qcom,mdss_dsi0_ctrl", n)
	if !ok || dn.Addr != "5e94000" {
		t.Errorf("got %+v ok=%v", dn, ok)
	}
	if _, ok := displayNode("/soc/other", node("other", map[string]string{"compatible": "vendor,thing\x00"})); ok {
		t.Error("only DSI controllers and PHYs are display nodes")
	}
}
