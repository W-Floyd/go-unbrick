package port

import (
	"strings"
	"testing"
)

// bareTodos returns the lines that mark a decision with a TODO not written
// "TODO: ". A line explaining the convention ("Lines marked TODO ...") is prose,
// and a value placeholder (TODO_function, the vendor in "TODO,panel") is not a
// marker; each sits beside a proper "TODO: " comment.
func bareTodos(text string) []string {
	var bad []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "marked TODO") {
			continue
		}
		for i := 0; i+4 <= len(line); i++ {
			if line[i:i+4] != "TODO" {
				continue
			}
			if next := line[i+4:]; !strings.HasPrefix(next, ": ") && !strings.HasPrefix(next, "_") && !strings.HasPrefix(next, ",") {
				bad = append(bad, strings.TrimSpace(line))
				break
			}
		}
	}
	return bad
}

func TestBareTodosFindsOnlyBareMarkers(t *testing.T) {
	for line, bare := range map[string]bool{
		"/* TODO: a decision */":               false,
		"/* TODO a decision */":                true,
		"x = 0 /* TODO */":                     true,
		"# Lines marked TODO need a decision.": false,
		"return TODO_function":                 false,
		"no marker here":                       false,
	} {
		if got := len(bareTodos(line)) > 0; got != bare {
			t.Errorf("%q: bare = %v, want %v", line, got, bare)
		}
	}
}

// Every generated file marks an open decision the same way, so a person (and
// the manifest) can search for it.
func TestGeneratedFilesMarkDecisionsAsTODOColon(t *testing.T) {
	// A part with a supply, an unmapped property and a disabled status, with and
	// without a kernel tree, and a panel with nothing read from its node.
	pt := partWith("acme,thing", "thing@47", "qupv3_se1_i2c",
		"reg", cells(0x47), "vdd-supply", cells(ph), "vendor-prop", cells(7), "acme,irq-gpio", cells(ph, 84, 0))
	pt.Source.Props["status"] = []byte("disabled\x00")
	pt.Source.Keys = append(pt.Source.Keys, "status")
	pt.Overlays = 1

	p := Package{
		Props: map[string]string{"ro.product.vendor.manufacturer": "motorola", "ro.product.vendor.device": "fogona"},
		DT:    DT{Parts: []Part{pt}, Variants: make([]Variant, 4)},
		SoC:   []SoCMatch{{File: "arch/arm64/boot/dts/qcom/sm6225.dtsi", Score: 0.5}, {File: "arch/arm64/boot/dts/qcom/sm6115.dtsi", Score: 0.4}},
	}
	dts, _ := PeripheralDTS(p)
	p.Mainline = map[string]*MainlineDriver{"acme,thing": {}}
	withTree, _ := PeripheralDTS(p)

	for name, text := range map[string]string{
		"peripherals":           dts,
		"peripherals with tree": withTree,
		"board dts":             BoardDTS(p),
		"board dts, no SoC":     BoardDTS(Package{Props: p.Props}),
		"panel driver":          PanelDriver{Name: "bare"}.CSource(),
	} {
		if bad := bareTodos(text); len(bad) > 0 {
			t.Errorf("%s has bare TODO markers: %q", name, bad)
		}
		if !strings.Contains(text, "TODO: ") {
			t.Errorf("%s has no TODO at all, so the check proves nothing", name)
		}
	}
}
