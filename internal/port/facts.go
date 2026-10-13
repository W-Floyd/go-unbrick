// Package port turns what a stock Android package already holds into the
// ingredients of a Linux port: the boot layout, the board's device-tree parts
// and displays, the screen's shape, and a hardware report. It is
// distribution-neutral; an Emitter (see port.go) turns the result into one
// distribution's packaging.
//
// It reads; it does not guess. A field the package cannot determine is left
// unset or a TODO in the output, never filled with a plausible value.
package port

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

// Boot is the layout a vendor_boot v3/v4 header declares.
type Boot struct {
	HeaderVersion uint32
	PageSize      uint32
	Kernel        uint32 // load addresses; deviceinfo wants offsets from a base
	Ramdisk       uint32
	Tags          uint32
	DTB           uint32
	Cmdline       string
	Source        string // the image the header is from: "vendor_boot" or "boot"
}

// ParseBoot reads the layout from a vendor_boot or a boot image's header, for a
// device that carries its base device tree in whichever it has.
func ParseBoot(b []byte) (Boot, error) {
	if len(b) >= 8 && string(b[:8]) == "VNDRBOOT" {
		return ParseVendorBoot(b)
	}
	if len(b) < 576 || string(b[:8]) != "ANDROID!" {
		return Boot{}, fmt.Errorf("not a boot or vendor_boot image")
	}
	le := binary.LittleEndian
	boot := Boot{HeaderVersion: le.Uint32(b[40:]), PageSize: le.Uint32(b[36:]), Source: "boot"}
	if boot.HeaderVersion >= 3 {
		return boot, fmt.Errorf("boot image header v%d carries no addresses (its layout is in vendor_boot)", boot.HeaderVersion)
	}
	boot.Kernel, boot.Ramdisk, boot.Tags = le.Uint32(b[12:]), le.Uint32(b[20:]), le.Uint32(b[32:])
	end := 64
	for end < 64+512 && b[end] != 0 {
		end++
	}
	boot.Cmdline = string(b[64:end])
	if boot.HeaderVersion >= 2 && len(b) >= 1660 {
		boot.DTB = uint32(le.Uint64(b[1652:]))
	}
	return boot, nil
}

// ParseVendorBoot reads the layout from a vendor_boot image's header.
func ParseVendorBoot(b []byte) (Boot, error) {
	if len(b) < 2112 || string(b[:8]) != "VNDRBOOT" {
		return Boot{}, fmt.Errorf("not a vendor_boot image")
	}
	le := binary.LittleEndian
	end := 28
	for end < 28+2048 && b[end] != 0 {
		end++
	}
	return Boot{
		HeaderVersion: le.Uint32(b[8:]), PageSize: le.Uint32(b[12:]),
		Kernel: le.Uint32(b[16:]), Ramdisk: le.Uint32(b[20:]),
		Tags: le.Uint32(b[2076:]), DTB: uint32(le.Uint64(b[2104:])),
		Cmdline: string(b[28:end]), Source: "vendor_boot",
	}, nil
}

// Panel is one display a board overlay declares.
type Panel struct {
	Name         string
	W, H         uint32
	MMW, MMH     uint32
	Hz           []uint32
	Touch        []string // touch controllers bound to this panel
	OverlayCount int      // how many board overlays carry it
	// Referenced is true for a panel something on the board points at: a touch
	// controller, or the display's default. The rest are Qualcomm reference
	// panels the overlay carries but the board never selects.
	Referenced, Default bool
	// Source is the stock panel node, from the first overlay that has it.
	Source *fdt.Node
	// Reset is the stock reset line, and BLType how the stock node says the
	// backlight is controlled ("bl_ctrl_dcs", "bl_ctrl_pwm", ...).
	Reset  PanelGPIO
	BLType string
}

// PanelGPIO is a GPIO a stock panel node names: the controller's label (as the
// overlay's fixups give it), the line and its stock flags.
type PanelGPIO struct {
	Ctrl  string
	Pin   uint32
	Flags uint32
	Set   bool
}

// Part is one board component a device tree names: a node on an external bus
// (I2C, SPI) or one a third party's compatible names, with the driver in the
// package that binds it when there is one.
type Part struct {
	Compatible string
	Node       string // "sgm7220@47"
	Bus        string // the bus controller the overlay attaches it to, "qupv3_se1_i2c"
	Driver     string // module that binds the compatible, "" if none in the package
	Desc       string // the driver's own description, else the catalog's
	Class      string // optional label from the catalog's dt_parts, cosmetic
	Overlays   int    // how many board overlays carry it

	// Source is the stock node, from the first overlay that has it, and Labels
	// names the controller each of its phandle properties points at ("tlmm").
	Source *fdt.Node
	Labels map[string]string
}

// FirmwareName is a firmware file name a device tree property gives, as the
// vendor DTs do ("firmware-name", "vidc,firmware-name", "aw9610x,firmware_name").
type FirmwareName struct {
	Node, Prop string
	Value      string
}

// Variant is one board overlay: the ids it is selected by and the displays it carries.
type Variant struct {
	BoardIDs [][2]uint32 // {board id, revision}
	Panels   []string
}

// DT is what the device trees say.
type DT struct {
	SoC      string   // base DTB compatible, "qcom,khaje"
	Model    string   // overlay model, "fogona"
	Compat   []string // overlay compatible
	MSMIDs   []uint32 // base DTB soc ids
	Variants []Variant
	Panels   []Panel
	Parts    []Part
	// Unreferenced are panel nodes the overlays define but nothing selects.
	Unreferenced []string
	GPU          string // base DTB qcom,gpu-model, "Adreno610v2"
	// Symbols maps a base DTB label to its node path ("qupv3_se1_i2c" ->
	// "/soc/geniqup@4ac0000/i2c@4a84000"); UnitAddrs holds the unit addresses
	// of its peripherals, lower-case hex, the SoC's register fingerprint.
	Symbols   map[string]string
	UnitAddrs map[string]bool
	// SoCNodes are the base tree's register-addressed peripherals, one per
	// address (see SoCGap).
	SoCNodes []SoCNode
	// DisplayNodes are the DSI controllers and PHYs the board overlays enable.
	DisplayNodes []SoCNode
	// FixedClocks are the base tree's fixed-clock nodes by label ("xo_board").
	FixedClocks   map[string]FixedClock
	FirmwareNames []FirmwareName
	// Reserved are the stock reserved-memory regions, base and overlays.
	Reserved []Region
}

// ReadDT summarizes the base DTBs and the board overlays. Each part is bound to
// its driver through mods' aliases; the catalog's dt_parts, when it has the
// compatible, only adds a label. unknown are parts nothing in the package binds
// and the catalog does not describe.
func ReadDT(base, overlays []*fdt.Node, mods []Module, cat *catalog.Catalog) (dt DT, unknown []string) {
	dt.Symbols, dt.UnitAddrs = map[string]string{}, map[string]bool{}
	dt.FixedClocks = map[string]FixedClock{}
	for _, b := range base {
		if dt.SoC == "" {
			if c := b.Strs("compatible"); len(c) > 0 {
				dt.SoC = c[0]
			}
		}
		collectAddrs(b, &dt)
		if dt.GPU == "" {
			b.Walk(func(_ string, n *fdt.Node) {
				if m, ok := n.Str("qcom,gpu-model"); ok && dt.GPU == "" {
					dt.GPU = m
				}
			})
		}
		if ids := b.U32s("qcom,msm-id"); len(ids) > 0 {
			dt.MSMIDs = append(dt.MSMIDs, ids[0])
		}
	}
	dt.FirmwareNames = firmwareNames(append(append([]*fdt.Node{}, base...), overlays...))
	dt.Reserved = readRegions(base, overlays)
	parts := map[string]*Part{}
	panels := map[string]*Panel{}
	unk := map[string]bool{}
	for _, o := range overlays {
		// The display blocks a board overlay enables (the DSI controller and its
		// PHY), by register address: a base tree often lacks them.
		o.Walk(func(path string, n *fdt.Node) {
			if dn, ok := displayNode(path, n); ok {
				dt.DisplayNodes = appendSoCNode(dt.DisplayNodes, dn)
			}
		})
		if dt.Model == "" {
			dt.Model, _ = o.Str("model")
			dt.Compat = o.Strs("compatible")
		}
		var v Variant
		ids := o.U32s("qcom,board-id")
		for i := 0; i+1 < len(ids); i += 2 {
			v.BoardIDs = append(v.BoardIDs, [2]uint32{ids[i], ids[i+1]})
		}
		seen := map[string]bool{}
		for _, p := range overlayPanels(o) {
			if !p.Referenced {
				dt.Unreferenced = union(dt.Unreferenced, []string{p.Name})
				continue
			}
			v.Panels = append(v.Panels, p.Name)
			if e := panels[p.Name]; e != nil {
				e.OverlayCount++
				e.Touch = union(e.Touch, p.Touch)
			} else {
				p.OverlayCount = 1
				panels[p.Name] = &p
			}
		}
		socVendor, _, _ := strings.Cut(dt.SoC, ",")
		for _, rp := range overlayParts(o, socVendor) {
			if seen[rp.Compatible] {
				continue
			}
			seen[rp.Compatible] = true
			if e := parts[rp.Compatible]; e != nil {
				e.Overlays++
				continue
			}
			p := &Part{Compatible: rp.Compatible, Node: rp.Node, Bus: rp.Bus, Overlays: 1, Source: rp.N, Labels: rp.Labels}
			if m, ok := Binding(mods, rp.Compatible); ok {
				p.Driver, p.Desc = m.Name, m.Description
			}
			if pt, ok := cat.DTPartFor(rp.Compatible); ok {
				p.Class = pt.Class
				if p.Desc == "" {
					p.Desc = pt.Desc
				}
			}
			if p.Desc == "" {
				unk[rp.Compatible] = true
			}
			parts[rp.Compatible] = p
		}
		dt.Variants = append(dt.Variants, v)
	}
	for _, p := range parts {
		dt.Parts = append(dt.Parts, *p)
	}
	sort.Slice(dt.Parts, func(i, j int) bool {
		a, b := dt.Parts[i], dt.Parts[j]
		if a.Bus != b.Bus {
			return a.Bus < b.Bus
		}
		return a.Compatible < b.Compatible
	})
	for _, p := range panels {
		dt.Panels = append(dt.Panels, *p)
	}
	sort.Slice(dt.Panels, func(i, j int) bool { return dt.Panels[i].Name < dt.Panels[j].Name })
	for c := range unk {
		unknown = append(unknown, c)
	}
	sort.Strings(unknown)
	return dt, unknown
}

// overlayPanels finds the DSI panel nodes of one overlay, with the touch
// controllers that point at each through their `panel` phandle.
func overlayPanels(o *fdt.Node) []Panel {
	byPhandle := map[uint32]*Panel{}
	var out []Panel
	var phandles []uint32
	fix := fixupLabels(o)
	o.Walk(func(path string, n *fdt.Node) {
		name, ok := n.Str("qcom,mdss-dsi-panel-name")
		if !ok {
			return
		}
		p := Panel{Name: name, Source: n}
		// The reset line: <&controller pin flags>, the controller's label from
		// the overlay's fixups (the phandle itself is a placeholder).
		if g := n.U32s("qcom,platform-reset-gpio"); len(g) == 3 {
			p.Reset = PanelGPIO{Ctrl: fix[strings.TrimPrefix(path, "/")+":qcom,platform-reset-gpio"], Pin: g[1], Flags: g[2], Set: true}
		}
		p.BLType, _ = n.Str("qcom,mdss-dsi-bl-pmic-control-type")
		for _, c := range n.Children {
			c.Walk(func(_ string, t *fdt.Node) {
				if w := t.U32s("qcom,mdss-dsi-panel-width"); len(w) > 0 && p.W == 0 {
					p.W = w[0]
					if h := t.U32s("qcom,mdss-dsi-panel-height"); len(h) > 0 {
						p.H = h[0]
					}
				}
				if f := t.U32s("qcom,mdss-dsi-panel-framerate"); len(f) > 0 {
					p.Hz = union32(p.Hz, f[0])
				}
			})
		}
		if v := n.U32s("qcom,mdss-pan-physical-width-dimension"); len(v) > 0 {
			p.MMW = v[0]
		}
		if v := n.U32s("qcom,mdss-pan-physical-height-dimension"); len(v) > 0 {
			p.MMH = v[0]
		}
		out = append(out, p)
		ph := n.U32s("phandle")
		if len(ph) == 0 {
			ph = []uint32{0}
		}
		phandles = append(phandles, ph[0])
	})
	for i := range out {
		if phandles[i] != 0 {
			byPhandle[phandles[i]] = &out[i]
		}
	}
	o.Walk(func(_ string, n *fdt.Node) {
		if ph := n.U32s("qcom,dsi-default-panel"); len(ph) == 1 && byPhandle[ph[0]] != nil {
			byPhandle[ph[0]].Referenced, byPhandle[ph[0]].Default = true, true
		}
		ph := n.U32s("panel")
		if len(ph) != 1 {
			return
		}
		if p := byPhandle[ph[0]]; p != nil {
			p.Referenced = true
			if c := n.Strs("compatible"); len(c) > 0 {
				p.Touch = union(p.Touch, c[:1])
			}
		}
	})
	return out
}

func union(a, b []string) []string {
	for _, s := range b {
		found := false
		for _, t := range a {
			found = found || s == t
		}
		if !found {
			a = append(a, s)
		}
	}
	return a
}

func union32(a []uint32, v uint32) []uint32 {
	for _, t := range a {
		if t == v {
			return a
		}
	}
	return append(a, v)
}
