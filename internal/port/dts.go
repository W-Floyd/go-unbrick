package port

import (
	"fmt"
	"path/filepath"
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
		bus, _, ok := p.busLabel(pt.Bus)
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
		if _, verified, _ := p.busLabel(stockBusOf(byBus[bus])); verified {
			w("\tstatus = \"okay\"; /* stock %s: same register address as %s in the SoC dtsi */", stockBusOf(byBus[bus]), bus)
		} else {
			w("\tstatus = \"okay\"; /* TODO: the stock label %s is assumed to be mainline's %s (no SoC dtsi to check) */", stockBusOf(byBus[bus]), bus)
		}
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

	uses, mapped := ClassifyPins(pt)
	for _, u := range uses {
		switch u.Kind {
		case PinIRQ:
			if u.TypeKnown {
				w("\t\tinterrupts-extended = <&%s %d %s>;", u.Ctrl, u.Pin, irqName(u.Flags))
			} else {
				w("\t\tinterrupts-extended = <&%s %d IRQ_TYPE_NONE>; /* TODO: trigger type; stock %s gave flags 0x%x */", u.Ctrl, u.Pin, u.Prop, u.Flags)
			}
		case PinReset:
			w("\t\treset-gpios = <&%s %d %s>; /* stock %s */", u.Ctrl, u.Pin, activeFlag(u.Flags), u.Prop)
		case PinEnable:
			w("\t\tenable-gpios = <&%s %d %s>; /* stock %s */", u.Ctrl, u.Pin, activeFlag(u.Flags), u.Prop)
		}
	}
	if pt.Overlays < len(p.DT.Variants) {
		w("\t\t/* in %d of %d stock board overlays: a part some board variants do not fit */", pt.Overlays, len(p.DT.Variants))
	}
	for _, other := range sharedPins(p, pt, uses) {
		w("\t\t/* shares a pin with %s: likely alternative parts of different board variants; the board fits one */", other)
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
		w("\t\t/* TODO: supplies the stock node has, as phandles into the stock PMIC tree: %s */", strings.Join(supplies, ", "))
	}
	if len(unmapped) > 0 {
		w("\t\t/* TODO: stock properties not mapped: %s */", capList(unmapped, 12))
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

// PinKind says what a stock pin property is for.
type PinKind string

const (
	PinIRQ    PinKind = "irq"
	PinReset  PinKind = "reset"
	PinEnable PinKind = "enable"
)

// PinUse is one pin a stock node names in a recognisable shape.
type PinUse struct {
	Kind  PinKind
	Prop  string // the stock property
	Ctrl  string // the controller label ("tlmm")
	Pin   uint32
	Flags uint32
	// TypeKnown is set when the property is a standard interrupt specifier, so
	// Flags is a trigger type; a vendor gpio property does not say.
	TypeKnown bool
}

// ClassifyPins finds the interrupt, reset and enable pins of a stock node, at
// most one of each, and the set of properties they account for (which a node
// writer will not list as unmapped). The kind comes from the property name; a
// pin is a "<&ctrl>, <N flags>" specifier.
func ClassifyPins(pt Part) (uses []PinUse, mapped map[string]bool) {
	n := pt.Source
	mapped = map[string]bool{"compatible": true, "reg": true, "phandle": true, "status": true, "pinctrl-names": true}
	have := map[PinKind]bool{}
	ctrl := func(prop string) string { return labelOr(pt.Labels[prop], "tlmm") }
	add := func(u PinUse) {
		uses = append(uses, u)
		have[u.Kind] = true
		mapped[u.Prop] = true
	}
	for _, k := range n.Keys {
		pin, flags, ok := gpioSpec(n, k)
		if !ok {
			continue
		}
		switch {
		case k == "interrupts-extended":
			add(PinUse{Kind: PinIRQ, Prop: k, Ctrl: ctrl(k), Pin: pin, Flags: flags, TypeKnown: true})
		case irqProp.MatchString(k) && !strings.HasSuffix(k, "_num") && !have[PinIRQ]:
			add(PinUse{Kind: PinIRQ, Prop: k, Ctrl: ctrl(k), Pin: pin, Flags: flags})
		case resetProp.MatchString(k) && !have[PinReset]:
			add(PinUse{Kind: PinReset, Prop: k, Ctrl: ctrl(k), Pin: pin, Flags: flags})
		case enableProp.MatchString(k) && !have[PinEnable]:
			add(PinUse{Kind: PinEnable, Prop: k, Ctrl: ctrl(k), Pin: pin, Flags: flags})
		}
	}
	// interrupts + interrupt-parent is the same specifier split in two.
	if !have[PinIRQ] {
		if c := n.U32s("interrupts"); len(c) >= 2 {
			uses = append(uses, PinUse{Kind: PinIRQ, Prop: "interrupts", Ctrl: labelOr(pt.Labels["interrupt-parent"], "tlmm"), Pin: c[0], Flags: c[1], TypeKnown: true})
			mapped["interrupts"], mapped["interrupt-parent"], mapped["interrupt-names"] = true, true, true
		}
	}
	return uses, mapped
}

// sharedPins names the other parts on the same bus that use one of the same
// pins. Two parts cannot both drive a pin on a board, so this is evidence that
// they are alternatives fitted on different variants.
func sharedPins(p Package, pt Part, uses []PinUse) []string {
	var out []string
	for _, other := range p.DT.Parts {
		if other.Source == nil || other.Bus != pt.Bus || other.Compatible == pt.Compatible {
			continue
		}
		ou, _ := ClassifyPins(other)
		for _, a := range uses {
			for _, b := range ou {
				if a.Kind == b.Kind && a.Pin == b.Pin && a.Ctrl == b.Ctrl {
					out = append(out, fmt.Sprintf("%s@%x (%s pin %d)", strings.ToLower(strings.ReplaceAll(strings.SplitN(other.Node, "@", 2)[0], "_", "-")), addrOf(other), a.Kind, a.Pin))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// BoardName is the file stem of the board's device tree: "motorola-fogona".
func BoardName(p Package) string {
	brand, code, _ := p.Identity()
	return strings.ToLower(brand) + "-" + code
}

// BoardDTS drafts the board's top-level device tree: the SoC include the
// register-map match chose, the peripherals file, the model and the compatible
// chain. What a package cannot say is a TODO.
func BoardDTS(p Package) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	brand, code, name := p.Identity()
	w("// SPDX-License-Identifier: BSD-3-Clause")
	w("/*")
	w(" * %s", name)
	w(" * Draft from a stock package; lines marked TODO need a decision.")
	w(" */")
	w("")
	w("/dts-v1/;")
	w("")

	soc := ""
	if len(p.SoC) > 0 {
		soc = strings.TrimSuffix(filepath.Base(p.SoC[0].File), ".dtsi")
		w("#include %q", soc+".dtsi")
	} else {
		w("/* TODO: the SoC include; pass --kernel-tree to pick it by register map */")
	}
	w("#include %q", BoardName(p)+"-peripherals.dtsi")
	w("")
	w("/ {")
	w("\tmodel = %q;", name)
	compat := []string{strings.ToLower(brand) + "," + code}
	if soc != "" {
		compat = append(compat, "qcom,"+soc)
	}
	var quoted []string
	for _, c := range compat {
		quoted = append(quoted, fmt.Sprintf("%q", c))
	}
	w("\tcompatible = %s;", strings.Join(quoted, ", "))
	if len(p.SoC) > 1 {
		w("\t/* TODO: the next closest SoC is %s (%.2f against %.2f); a board often lists that family as a fallback compatible */",
			strings.TrimSuffix(filepath.Base(p.SoC[1].File), ".dtsi"), p.SoC[1].Score, p.SoC[0].Score)
	}
	w("\t/* TODO: chassis-type: a package does not say handset or tablet */")
	if p.SoCRegions != nil {
		if board, _ := BoardRegions(p.DT.Reserved, p.SoCRegions); len(board) > 0 {
			w("")
			w("\t/* Reserved regions the stock trees have that %s does not: the board's own. */", filepath.Base(p.SoC[0].File))
			b.WriteString(regionsText(board))
		}
	}
	w("};")
	return b.String()
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
