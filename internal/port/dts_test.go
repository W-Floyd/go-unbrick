package port

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

func cells(v ...uint32) []byte {
	b := make([]byte, 4*len(v))
	for i, x := range v {
		binary.BigEndian.PutUint32(b[4*i:], x)
	}
	return b
}

// partWith builds a stock part whose node has the given raw properties, in order.
func partWith(compat, nodeName, bus string, props ...any) Part {
	n := &fdt.Node{Name: nodeName, Props: map[string][]byte{}}
	for i := 0; i < len(props); i += 2 {
		k := props[i].(string)
		n.Props[k] = props[i+1].([]byte)
		n.Keys = append(n.Keys, k)
	}
	return Part{Compatible: compat, Node: nodeName, Bus: bus, Source: n, Overlays: 4, Labels: map[string]string{}}
}

const ph = 0xffffffff // the controller placeholder a stock overlay leaves in a gpio specifier

func TestClassifyPinsByPropertyName(t *testing.T) {
	pt := partWith("acme,thing", "thing@47", "qupv3_se1_i2c",
		"reg", cells(0x47),
		"acme,intr_gpio", cells(ph, 84, 0),
		"acme,intr_gpio_num", cells(84), // a plain number, not a specifier: ignored
		"acme,rst-gpio", cells(ph, 86, 1),
		"acme,en-gpio", cells(ph, 60, 0),
		"unrelated-gpio", cells(ph, 9, 0),
		"vendor-prop", cells(7),
	)
	uses, mapped := ClassifyPins(pt)
	got := map[PinKind]PinUse{}
	for _, u := range uses {
		got[u.Kind] = u
	}
	if got[PinIRQ].Pin != 84 || got[PinReset].Pin != 86 || got[PinEnable].Pin != 60 {
		t.Errorf("pins %+v", uses)
	}
	if got[PinIRQ].TypeKnown {
		t.Error("a vendor gpio property does not give a trigger type")
	}
	if !mapped["acme,rst-gpio"] || mapped["unrelated-gpio"] || mapped["vendor-prop"] {
		t.Errorf("mapped %v", mapped)
	}
	if activeFlag(got[PinReset].Flags) != "GPIO_ACTIVE_LOW" || activeFlag(got[PinEnable].Flags) != "GPIO_ACTIVE_HIGH" {
		t.Error("polarity comes from the specifier's low bit")
	}
}

func TestClassifyPinsInterruptsExtendedAndSplitForm(t *testing.T) {
	ext := partWith("a,b", "x@1", "qupv3_se1_i2c", "interrupts-extended", cells(ph, 96, 8))
	uses, _ := ClassifyPins(ext)
	if len(uses) != 1 || uses[0].Pin != 96 || !uses[0].TypeKnown || irqName(uses[0].Flags) != "IRQ_TYPE_LEVEL_LOW" {
		t.Errorf("interrupts-extended: %+v", uses)
	}
	split := partWith("a,b", "x@1", "qupv3_se1_i2c", "interrupt-parent", cells(ph), "interrupts", cells(106, 2))
	split.Labels["interrupt-parent"] = "tlmm"
	uses, mapped := ClassifyPins(split)
	if len(uses) != 1 || uses[0].Pin != 106 || uses[0].Ctrl != "tlmm" || irqName(uses[0].Flags) != "IRQ_TYPE_EDGE_FALLING" || !mapped["interrupt-parent"] {
		t.Errorf("interrupts + interrupt-parent: %+v mapped %v", uses, mapped)
	}
}

func TestPeripheralDTSMarksAlternativesAndVariantParts(t *testing.T) {
	a := partWith("acme,charger-a", "charger_a@3b", "qupv3_se1_i2c", "reg", cells(0x3b), "acme,irq-gpio", cells(ph, 28, 0))
	b := partWith("acme,charger-b", "charger_b@6a", "qupv3_se1_i2c", "reg", cells(0x6a), "acme,irq-gpio", cells(ph, 28, 0))
	b.Overlays = 2
	p := Package{
		Props: map[string]string{"ro.product.vendor.manufacturer": "motorola", "ro.product.vendor.device": "fogona"},
		DT:    DT{Parts: []Part{a, b}, Variants: make([]Variant, 4)},
	}
	text, notes := PeripheralDTS(p)
	for _, want := range []string{
		"&i2c1 {",
		"charger-a@3b {",
		"charger-b@6a {",
		"interrupts-extended = <&tlmm 28 IRQ_TYPE_NONE>",
		"shares a pin with charger-b@6a (irq pin 28)",
		"in 2 of 4 stock board overlays",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(strings.SplitN(text, "charger-b@6a", 2)[0], "in 2 of 4") {
		t.Error("the overlay-count note belongs to charger-b only")
	}
	if len(notes) == 0 || !strings.Contains(notes[0], "placed 2 of 2") {
		t.Errorf("notes %v", notes)
	}
}

func TestReferencePinsAreReadAndCompared(t *testing.T) {
	ref := ParseReferenceDTS(`
&spi0 {
	touchscreen@0 {
		compatible = "chipone,icnl9916";
		interrupts-extended = <&tlmm 80 IRQ_TYPE_EDGE_FALLING>;
		touchscreen-reset-gpios = <&tlmm 86 GPIO_ACTIVE_LOW>;
		sub {
			reset-gpios = <&tlmm 1 0>;
		};
	};
};
`)
	if len(ref) != 1 || ref[0].Pins[PinIRQ] != 80 || ref[0].Pins[PinReset] != 86 {
		t.Fatalf("reference pins %+v (a sub-node's pins must not count)", ref)
	}
	pt := partWith("novatek,x", "novatek@0", "qupv3_se0_spi", "reg", cells(0),
		"x,irq-gpio", cells(ph, 80, 0), "x,reset-gpio", cells(ph, 87, 0))
	s, agree, differ := comparePins(pt, ref[0])
	if agree != 1 || differ != 1 || !strings.Contains(s, "irq 80 ✓") || !strings.Contains(s, "reset stock 87, reference 86") {
		t.Errorf("summary %q agree %d differ %d", s, agree, differ)
	}
}
