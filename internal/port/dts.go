package port

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

// busSE reads a Qualcomm serial-engine label: qupv3_se1_i2c is engine 1 as an
// I2C controller. The mainline SoC dtsi names the same controller i2c1.
var busSE = regexp.MustCompile(`(?i)se(\d+)_(i2c|spi)`)

// MainlineBus is the label a mainline SoC dtsi gives the controller a stock
// label names ("qupv3_se1_i2c" -> "i2c1"), assuming mainline numbers the
// engines as the hardware does. ok is false for a bus it cannot map.
func MainlineBus(stock string) (label string, ok bool) {
	m := busSE.FindStringSubmatch(stock)
	if m == nil {
		return "", false
	}
	return strings.ToLower(m[2]) + m[1], true
}

var (
	irqProp    = regexp.MustCompile(`(?i)(^|[,_-])(irq|intr|int|nirq|interrupt)([-_]?gpios?)?$`)
	resetProp  = regexp.MustCompile(`(?i)(^|[,_-])(reset|rst)[-_]?gpios?$`)
	enableProp = regexp.MustCompile(`(?i)(^|[,_-])(en|enable)[-_]?gpios?$`)
)

// irqTypes are the standard interrupt flag cells.
var irqTypes = map[uint32]string{1: "IRQ_TYPE_EDGE_RISING", 2: "IRQ_TYPE_EDGE_FALLING", 3: "IRQ_TYPE_EDGE_BOTH", 4: "IRQ_TYPE_LEVEL_HIGH", 8: "IRQ_TYPE_LEVEL_LOW"}

// gpioSpec reads a stock gpio or interrupt specifier "<&ctrl>, <N flags>":
// a controller placeholder cell, then the pin and its flags.
func gpioSpec(n *fdt.Node, prop string) (pin, flags uint32, ok bool) {
	c := n.U32s(prop)
	if len(c) == 3 && c[0] == 0xffffffff {
		return c[1], c[2], true
	}
	return 0, 0, false
}

// PeripheralDTS drafts the board's I2C and SPI peripheral nodes from the stock
// overlays: the bus, the address, a compatible chosen from what the target
// kernel supports, and the interrupt, reset and enable pins the stock node
// names in standard form. What it cannot place is listed, never guessed.
// notes say how many parts it placed and which it could not.
func PeripheralDTS(p Package) (text string, notes []string) {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	brand, code, name := p.Identity()
	w("// Draft peripheral nodes for %s (%s,%s), from the stock device-tree overlays.", name, strings.ToLower(brand), code)
	w("// Every line marked TODO is a decision the stock package cannot make.")
	w("")
	w("#include <dt-bindings/gpio/gpio.h>")
	w("#include <dt-bindings/interrupt-controller/irq.h>")

	byBus := map[string][]Part{}
	var unplaced []string
	for _, pt := range p.DT.Parts {
		if pt.Source == nil {
			continue
		}
		bus, ok := MainlineBus(pt.Bus)
		if !ok || pt.Node == "" || !strings.Contains(pt.Node, "@") && len(pt.Source.U32s("reg")) == 0 {
			unplaced = append(unplaced, pt.Compatible+" (stock bus "+orNone(pt.Bus)+")")
			continue
		}
		byBus[bus] = append(byBus[bus], pt)
	}
	var buses []string
	for bus := range byBus {
		buses = append(buses, bus)
	}
	sort.Strings(buses)

	placed := 0
	for _, bus := range buses {
		w("")
		w("&%s {", bus)
		w("\tstatus = \"okay\"; /* TODO: the stock label %s is assumed to be mainline's %s */", stockBusOf(byBus[bus]), bus)
		parts := byBus[bus]
		sort.Slice(parts, func(i, j int) bool { return addrOf(parts[i]) < addrOf(parts[j]) })
		for _, pt := range parts {
			w("")
			writeNode(&b, p, pt)
			placed++
		}
		w("};")
	}
	if len(unplaced) > 0 {
		w("")
		w("/* Parts not on an I2C or SPI controller this tool can map to a mainline label:")
		for _, u := range unplaced {
			w(" *   %s", u)
		}
		w(" */")
	}
	notes = append(notes, fmt.Sprintf("dts: placed %d of %d parts on I2C/SPI buses", placed, len(p.DT.Parts)))
	return b.String(), notes
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func stockBusOf(parts []Part) string { return parts[0].Bus }

func addrOf(pt Part) uint32 {
	if c := pt.Source.U32s("reg"); len(c) > 0 {
		return c[0]
	}
	return 0
}

// writeNode writes one part as a node.
func writeNode(b *strings.Builder, p Package, pt Part) {
	w := func(f string, a ...any) { fmt.Fprintf(b, f+"\n", a...) }
	n := pt.Source
	addr := addrOf(pt)
	base := pt.Node
	if i := strings.Index(base, "@"); i >= 0 {
		base = base[:i]
	}
	base = strings.ToLower(strings.ReplaceAll(base, "_", "-"))

	desc := pt.Desc
	if pt.Driver != "" {
		desc = pt.Driver + ": " + pt.Desc
	}
	w("\t/* stock: %s%s */", pt.Compatible, ifNotEmpty(" — ", desc))
	w("\t%s@%x {", base, addr)
	w("\t\tcompatible = %s;", compatibleLine(p, pt))
	w("\t\treg = <0x%x>;", addr)

	mapped := map[string]bool{"compatible": true, "reg": true, "phandle": true, "status": true, "pinctrl-names": true}
	pinUsed := map[string]bool{}
	ctrl := func(prop string) string {
		if l := pt.Labels[prop]; l != "" {
			return l
		}
		return "tlmm"
	}
	for _, k := range n.Keys {
		if mapped[k] {
			continue
		}
		pin, flags, ok := gpioSpec(n, k)
		switch {
		case k == "interrupts-extended" && ok:
			w("\t\tinterrupts-extended = <&%s %d %s>;", ctrl(k), pin, irqName(flags))
			mapped[k], pinUsed["irq"] = true, true
		case irqProp.MatchString(k) && ok && !strings.HasSuffix(k, "_num") && !pinUsed["irq"]:
			w("\t\tinterrupts-extended = <&%s %d IRQ_TYPE_NONE>; /* TODO: trigger type; stock %s gave flags 0x%x */", ctrl(k), pin, k, flags)
			mapped[k], pinUsed["irq"] = true, true
		case resetProp.MatchString(k) && ok && !pinUsed["reset"]:
			w("\t\treset-gpios = <&%s %d %s>; /* stock %s */", ctrl(k), pin, activeFlag(flags), k)
			mapped[k], pinUsed["reset"] = true, true
		case enableProp.MatchString(k) && ok && !pinUsed["enable"]:
			w("\t\tenable-gpios = <&%s %d %s>; /* stock %s */", ctrl(k), pin, activeFlag(flags), k)
			mapped[k], pinUsed["enable"] = true, true
		}
	}
	// interrupts + interrupt-parent is the same specifier split in two.
	if !pinUsed["irq"] {
		if c := n.U32s("interrupts"); len(c) >= 2 {
			w("\t\tinterrupts-extended = <&%s %d %s>;", labelOr(pt.Labels["interrupt-parent"], "tlmm"), c[0], irqName(c[1]))
			mapped["interrupts"], mapped["interrupt-parent"], mapped["interrupt-names"] = true, true, true
		}
	}

	var unmapped, supplies []string
	for _, k := range n.Keys {
		switch {
		case mapped[k]:
		case strings.HasSuffix(k, "-supply"):
			supplies = append(supplies, k)
		case strings.HasPrefix(k, "pinctrl-"):
		default:
			unmapped = append(unmapped, k)
		}
	}
	if len(supplies) > 0 {
		w("\t\t/* TODO supplies the stock node has, as phandles into the stock PMIC tree: %s */", strings.Join(supplies, ", "))
	}
	if len(unmapped) > 0 {
		w("\t\t/* TODO stock properties not mapped: %s */", capList(unmapped, 12))
	}
	var kids []string
	for _, c := range n.Children {
		kids = append(kids, c.Name)
	}
	if len(kids) > 0 {
		w("\t\t/* stock sub-nodes (calibration profiles and the like): %s */", capList(kids, 6))
	}
	if st, ok := n.Str("status"); ok && st != "okay" && st != "ok" {
		w("\t\t/* stock status was %q in the first overlay that has this node */", st)
	}
	w("\t};")
}

// compatibleLine chooses the compatible to write. The stock string stands when
// the target kernel names it (or when there is no tree to ask), with what the
// scan found beside it when it does not.
func compatibleLine(p Package, pt Part) string {
	c := fmt.Sprintf("%q", pt.Compatible)
	md := p.Mainline[pt.Compatible]
	switch {
	case p.Mainline == nil:
		return c + " /* TODO: not checked against a kernel tree (--kernel-tree) */"
	case md != nil && len(md.Sources) > 0:
		return c + " /* " + md.Sources[0] + " */"
	case md != nil && len(md.Similar) > 0:
		return c + " /* TODO: no driver in the tree names this; similar: " + strings.Join(md.Similar, ", ") + " */"
	default:
		return c + " /* TODO: no driver in the tree names this */"
	}
}

func irqName(flags uint32) string {
	if n, ok := irqTypes[flags&0xf]; ok {
		return n
	}
	return fmt.Sprintf("IRQ_TYPE_NONE /* TODO: stock flags 0x%x */", flags)
}

func activeFlag(flags uint32) string {
	if flags&1 != 0 {
		return "GPIO_ACTIVE_LOW"
	}
	return "GPIO_ACTIVE_HIGH"
}

func labelOr(l, def string) string {
	if l == "" {
		return def
	}
	return l
}

func ifNotEmpty(sep, s string) string {
	if s == "" {
		return ""
	}
	return sep + s
}

func capList(ss []string, n int) string {
	if len(ss) <= n {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:n], ", ") + fmt.Sprintf(", … (+%d)", len(ss)-n)
}
