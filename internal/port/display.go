package port

import (
	"fmt"
	"strings"
)

// Wiring the panel: the board dts has to turn on the SoC's display blocks,
// hang a panel node off the DSI controller with its reset line, and connect the
// two endpoints. The labels are the SoC dtsi's, found by the register address of
// the stock controller; a label the dtsi does not define is left as a TODO
// rather than referred to.

// stockNodeAddr is the register address of the lowest-addressed stock node whose
// compatible has the given fragment, "" if none.
func (p Package) stockNodeAddr(fragment string) string {
	best := ""
	for _, n := range append(append([]SoCNode(nil), p.DT.DisplayNodes...), p.DT.SoCNodes...) {
		for _, c := range n.Compatible {
			if strings.Contains(c, fragment) && n.Addr != "" && (best == "" || len(n.Addr) < len(best) || len(n.Addr) == len(best) && n.Addr < best) {
				best = n.Addr
			}
		}
	}
	return best
}

// labelAt is the SoC dtsi's label for the node at a stock address, "" if the
// address is unknown or the dtsi has no node there.
func (p Package) labelAt(addr string) string {
	if addr == "" {
		return ""
	}
	return p.SoCAddrLabels[addr]
}

// displayPanel picks the panel to wire: the one the live device runs, else the
// stock default, else the first the board references. alternatives are the
// other candidates, written as comments.
func (p Package) displayPanel() (chosen Panel, alternatives []Panel, ok bool) {
	var cands []Panel
	for _, pn := range p.DT.Panels {
		if pn.Referenced || pn.Default {
			cands = append(cands, pn)
		}
	}
	if len(cands) == 0 {
		return Panel{}, nil, false
	}
	pick := 0
	if name, found := p.FittedPanel(); found {
		for i, c := range cands {
			if c.Name == name {
				pick = i
			}
		}
	} else {
		for i, c := range cands {
			if c.Default {
				pick = i
				break
			}
		}
	}
	for i, c := range cands {
		if i != pick {
			alternatives = append(alternatives, c)
		}
	}
	return cands[pick], alternatives, true
}

// displayDTS is the display block of the peripherals file, or "" when there is
// nothing to say (no kernel tree to take labels from, no panel).
func (p Package) displayDTS() string {
	pn, alts, ok := p.displayPanel()
	if !ok {
		return ""
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("")
	w("/* Display: the panel on the DSI controller. */")
	if p.SoCLabels == nil {
		w("/* TODO: wiring the panel needs --kernel-tree, for the SoC dtsi's DSI labels */")
		return b.String()
	}
	dsi := p.labelAt(p.stockNodeAddr("dsi-ctrl"))
	phy := p.labelAt(p.stockNodeAddr("dsi-phy"))
	if dsi == "" || !p.SoCLabels[dsi] {
		w("/* TODO: the SoC dtsi has no node at the stock DSI controller's address (%s): wire the panel by hand */", orNone(p.stockNodeAddr("dsi-ctrl")))
		return b.String()
	}
	for _, l := range []string{"mdss", "mdss_mdp"} {
		if p.SoCLabels[l] {
			w("")
			w("&%s {", l)
			w("\tstatus = \"okay\";")
			w("};")
		}
	}
	lanes := 4
	if d, ok := ReadPanelDriver(pn); ok && d.Lanes > 0 {
		lanes = d.Lanes
	}
	var laneList []string
	for i := 0; i < lanes; i++ {
		laneList = append(laneList, fmt.Sprint(i))
	}

	w("")
	w("&%s {", dsi)
	w("\tstatus = \"okay\";")
	w("\t/* TODO: vdda-supply: the stock display regulators are in the stock display node */")
	w("")
	w("\t/* stock: %s */", pn.Name)
	w("\tpanel@0 {")
	w("\t\tcompatible = %q;", PanelCompatible(pn.Name))
	w("\t\treg = <0>;")
	switch {
	case !pn.Reset.Set:
		w("\t\t/* TODO: reset-gpios: the stock node names no reset line */")
	case pn.Reset.Ctrl == "" || !p.SoCLabels[pn.Reset.Ctrl]:
		w("\t\t/* TODO: reset-gpios: stock %s pin %d, but the SoC dtsi has no label %q */", "qcom,platform-reset-gpio", pn.Reset.Pin, pn.Reset.Ctrl)
	default:
		w("\t\treset-gpios = <&%s %d GPIO_ACTIVE_LOW>; /* stock qcom,platform-reset-gpio, flags 0x%x; the driver draft assumes active low */", pn.Reset.Ctrl, pn.Reset.Pin, pn.Reset.Flags)
	}
	w("\t\t/* TODO: the panel's supplies (vddio, and avdd/avee if it has them) */")
	if pn.BLType != "" {
		w("\t\t/* TODO: backlight: the stock node says %s */", pn.BLType)
	}
	w("")
	w("\t\tport {")
	w("\t\t\tpanel_in: endpoint {")
	if p.SoCLabels[dsi+"_out"] {
		w("\t\t\t\tremote-endpoint = <&%s_out>;", dsi)
	} else {
		w("\t\t\t\t/* TODO: remote-endpoint: the SoC dtsi has no label %q */", dsi+"_out")
	}
	w("\t\t\t};")
	w("\t\t};")
	w("\t};")
	w("};")
	if p.SoCLabels[dsi+"_out"] {
		w("")
		w("&%s_out {", dsi)
		w("\tremote-endpoint = <&panel_in>;")
		w("\tdata-lanes = <%s>;", strings.Join(laneList, " "))
		w("};")
	}
	if phy != "" && p.SoCLabels[phy] {
		w("")
		w("&%s {", phy)
		w("\tstatus = \"okay\";")
		w("\t/* TODO: vdds-supply */")
		w("};")
	}
	for _, a := range alts {
		w("")
		w("/* Stock variant, not wired (a unit has one panel): %s as %q */", a.Name, PanelCompatible(a.Name))
	}
	return b.String()
}
