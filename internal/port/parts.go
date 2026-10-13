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
	N                     *fdt.Node
	Labels                map[string]string // property -> label of the node its first phandle names
}

// fixupLabels reads an overlay's __fixups__ (label -> "/path:property:offset"
// entries) into "path:property" -> label, for the phandles that sit at offset
// 0 of a property: the controller a gpio or interrupt specifier names.
func fixupLabels(o *fdt.Node) map[string]string {
	out := map[string]string{}
	for _, c := range o.Children {
		if c.Name != "__fixups__" {
			continue
		}
		for _, label := range c.Keys {
			for _, ref := range strings.Split(strings.TrimRight(string(c.Props[label]), "\x00"), "\x00") {
				parts := strings.Split(strings.TrimPrefix(ref, "/"), ":")
				if len(parts) == 3 && parts[2] == "0" {
					out[parts[0]+":"+parts[1]] = label
				}
			}
		}
	}
	return out
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
// blocks and the OEM's own glue drivers are not parts: that is the compatibles
// of the SoC's own vendor (socVendor, the prefix of the base tree's compatible:
// "qcom", "mediatek"), the glue vendors, and generic bindings with no vendor
// prefix at all ("fixed-factor-clock"), unless they sit on an I2C or SPI bus.
func overlayParts(o *fdt.Node, socVendor string) []rawPart {
	targets := fragmentTargets(o)
	fix := fixupLabels(o)
	var out []rawPart
	for _, frag := range o.Children {
		ov := childNamed(frag, "__overlay__")
		if ov == nil {
			continue
		}
		bus := targets[frag.Name]
		// A node under a chip that is itself a part is one of the chip's own
		// sub-devices (an MFD's regulator, its charger), addressed through the
		// chip, not a client on the bus: it is not a part of its own.
		var rec func(p string, n *fdt.Node, underPart bool)
		rec = func(p string, n *fdt.Node, underPart bool) {
			isPart := false
			for _, c := range n.Strs("compatible") {
				vendor, _, hasVendor := strings.Cut(c, ",")
				ownVendor := socVendor != "" && strings.EqualFold(vendor, socVendor)
				if !underPart && (externalBus(bus) && !strings.Contains(strings.ToLower(bus), "reserved") ||
					hasVendor && !ownVendor && !glueVendor.MatchString(c) && !strings.Contains(strings.ToLower(bus), "reserved")) {
					labels := map[string]string{}
					for _, k := range n.Keys {
						if l, ok := fix[frag.Name+"/"+p+":"+k]; ok {
							labels[k] = l
						}
					}
					out = append(out, rawPart{Compatible: c, Node: n.Name, Bus: bus, N: n, Labels: labels})
					isPart = true
				}
			}
			for _, c := range n.Children {
				rec(p+"/"+c.Name, c, underPart || isPart)
			}
		}
		rec(ov.Name, ov, false)
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
