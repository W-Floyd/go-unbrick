package port

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

// rawPart is a compatible-bearing node of an overlay.
type rawPart struct {
	Compatible, Node, Bus string
}

// socVendors are compatible prefixes that name the SoC's own blocks and the
// OEM's glue, not a part a port has to find a driver for. A compatible with
// any other vendor prefix is a third party's part.
var glueVendor = regexp.MustCompile(`^(qcom|mmi|moto|motorola|android|qualcomm|arm|simple|regulator|gpio|pwm|ramoops|syscon)[,-]`)

// externalBus reports whether a bus controller label names an I2C, I3C or SPI
// controller, as Qualcomm's labels do (qupv3_se1_i2c, qupv3_se0_spi).
func externalBus(label string) bool {
	l := strings.ToLower(label)
	return strings.Contains(l, "i2c") || strings.Contains(l, "i3c") || strings.Contains(l, "spi")
}

// fragmentTargets maps each overlay fragment to the label of the node it
// attaches to, read from the overlay's __fixups__ (label -> "/fragment@N:target:0").
func fragmentTargets(o *fdt.Node) map[string]string {
	out := map[string]string{}
	for _, c := range o.Children {
		if c.Name != "__fixups__" {
			continue
		}
		for _, label := range c.Keys {
			for _, ref := range strings.Split(strings.TrimRight(string(c.Props[label]), "\x00"), "\x00") {
				if frag, rest, ok := strings.Cut(strings.TrimPrefix(ref, "/"), ":"); ok && strings.HasPrefix(rest, "target:") {
					out[frag] = label
				}
			}
		}
	}
	return out
}

// overlayParts finds the board's parts in an overlay: compatible-bearing nodes
// on an external bus, or whose compatible names a third-party vendor. SoC
// blocks and the OEM's own glue drivers are not parts.
func overlayParts(o *fdt.Node) []rawPart {
	targets := fragmentTargets(o)
	var out []rawPart
	for _, frag := range o.Children {
		ov := childNamed(frag, "__overlay__")
		if ov == nil {
			continue
		}
		bus := targets[frag.Name]
		ov.Walk(func(_ string, n *fdt.Node) {
			for _, c := range n.Strs("compatible") {
				if externalBus(bus) || (strings.Contains(c, ",") || strings.Contains(c, "-")) && !glueVendor.MatchString(c) {
					out = append(out, rawPart{Compatible: c, Node: n.Name, Bus: bus})
				}
			}
		})
	}
	return out
}

func childNamed(n *fdt.Node, name string) *fdt.Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// fwNameProp matches the property names vendor device trees give a firmware
// file name under: firmware-name, qcom,firmware-name, vidc,firmware-name,
// aw9610x,firmware_name, firmware-names.
var fwNameProp = regexp.MustCompile(`(?i)(^|[,_-])firmware[-_]?names?$`)

// firmwareNames collects every firmware file name the trees give.
func firmwareNames(trees []*fdt.Node) []FirmwareName {
	var out []FirmwareName
	seen := map[string]bool{}
	for _, t := range trees {
		t.Walk(func(p string, n *fdt.Node) {
			for _, k := range n.Keys {
				if !fwNameProp.MatchString(k) {
					continue
				}
				for _, v := range n.Strs(k) {
					if v == "" || seen[v+"\x00"+k] {
						continue
					}
					seen[v+"\x00"+k] = true
					out = append(out, FirmwareName{Node: p, Prop: k, Value: v})
				}
			}
		})
	}
	return out
}

func (f FirmwareName) String() string { return fmt.Sprintf("%s: %s = %q", f.Node, f.Prop, f.Value) }
