package port

import (
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

func node(name string, props map[string]string, kids ...*fdt.Node) *fdt.Node {
	n := &fdt.Node{Name: name, Props: map[string][]byte{}, Children: kids}
	for k, v := range props {
		n.Props[k] = []byte(v)
		n.Keys = append(n.Keys, k)
	}
	return n
}

// An overlay with: an I2C device, an SPI device, a SoC block on a platform
// target, a third-party platform device, and OEM glue.
func overlay() *fdt.Node {
	frag := func(n string, children ...*fdt.Node) *fdt.Node {
		return node(n, nil, node("__overlay__", nil, children...))
	}
	return node("", nil,
		frag("fragment@1", node("sgm7220@47", map[string]string{"compatible": "sgm,usb_type_c_sgm7220\x00"})),
		frag("fragment@2", node("novatek@0", map[string]string{"compatible": "novatek,NVT-ts-spi\x00"})),
		frag("fragment@3", node("sde-kms", map[string]string{"compatible": "qcom,sde-kms\x00"})),
		frag("fragment@4", node("fpc_fpc1020", map[string]string{"compatible": "fpc,fpc1020\x00"})),
		frag("fragment@5", node("charger", map[string]string{"compatible": "mmi,mmi-charger\x00"})),
		node("__fixups__", map[string]string{
			"qupv3_se1_i2c": "/fragment@1:target:0\x00",
			"qupv3_se0_spi": "/fragment@2:target:0\x00",
			"soc":           "/fragment@3:target:0\x00/fragment@4:target:0\x00/fragment@5:target:0\x00",
		}),
	)
}

func TestFragmentTargets(t *testing.T) {
	got := fragmentTargets(overlay())
	if got["fragment@1"] != "qupv3_se1_i2c" || got["fragment@4"] != "soc" {
		t.Errorf("targets %v", got)
	}
}

func TestOverlayPartsKeepsBusDevicesAndThirdParties(t *testing.T) {
	var got []string
	for _, p := range overlayParts(overlay()) {
		got = append(got, p.Compatible+"@"+p.Bus)
	}
	want := map[string]bool{
		"sgm,usb_type_c_sgm7220@qupv3_se1_i2c": true, // on an I2C controller
		"novatek,NVT-ts-spi@qupv3_se0_spi":     true, // on an SPI controller
		"fpc,fpc1020@soc":                      true, // a third party's compatible
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected part %s", g)
		}
	}
}

func TestFirmwareNamesFromAnyVendorSpelling(t *testing.T) {
	tree := node("", nil,
		node("venus", map[string]string{"vidc,firmware-name": "venus\x00"}),
		node("ipa", map[string]string{"qcom,firmware-name": "ipa_fws\x00", "firmware-names": "ipa_fws\x00"}),
		node("sar", map[string]string{"aw9610x,firmware_name": "aw9610x_0\x00"}),
		node("other", map[string]string{"label": "not-firmware\x00"}),
	)
	got := firmwareNames([]*fdt.Node{tree})
	have := map[string]bool{}
	for _, f := range got {
		have[f.Value] = true
	}
	for _, want := range []string{"venus", "ipa_fws", "aw9610x_0"} {
		if !have[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if have["not-firmware"] {
		t.Error("a property that is not a firmware name was taken")
	}
}
