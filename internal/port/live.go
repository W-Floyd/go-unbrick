package port

import (
	"fmt"
	"path"
	"strings"
)

// What a running device can say that a stock package cannot: which of the
// board's alternative parts are really fitted. The package carries every
// variant, and the live device tree keeps all of the I2C ones enabled too (the
// stock kernel probes them all and only the fitted chip answers), so the
// evidence is which clients are bound to a driver, plus the bootloader's
// /chosen properties for the parts a vendor selects by them. Both come from
// the same collection `adb recon` makes (sections "bus-devices" and "chosen").

// LiveDevice is one I2C or SPI client on the running device.
type LiveDevice struct {
	Kind       string // "i2c" or "spi"
	Name       string // "2-0064", "spi0.0"
	Modalias   string
	Driver     string // the bound driver's name, "" when unbound
	ParentAddr string // register address of the controller, from its node path
	Addr       string // unit address of the client's own node
	Node       string // the client's node name, "cw2217"
}

// Live is what the device said.
type Live struct {
	Devices    []LiveDevice
	Chosen     map[string]string // printable properties of /chosen in the live tree
	Cmdline    string
	HaveChosen bool
	Notes      []string // what could not be asked, and why
}

// NewLive reads a recon collection's sections. A section that came back empty
// is a note, not an error: an unrooted shell still lists devices but cannot
// read /chosen.
func NewLive(sections map[string]string, cmdline string) *Live {
	l := &Live{Chosen: map[string]string{}, Cmdline: cmdline}
	if l.Devices = ParseLiveDevices(sections["bus-devices"]); len(l.Devices) == 0 {
		l.Notes = append(l.Notes, "the device lists no I2C or SPI clients (sysfs may be hidden from this shell)")
	}
	for _, line := range strings.Split(sections["chosen"], "\n") {
		if k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t"); ok && k != "" {
			l.Chosen[k] = v
		}
	}
	if l.HaveChosen = len(l.Chosen) > 0; !l.HaveChosen {
		l.Notes = append(l.Notes, "/chosen was not read (it needs root): the panel and the parts a vendor selects by it are not resolved")
	}
	return l
}

// ParseLiveDevices reads the "bus-devices" section.
func ParseLiveDevices(out string) []LiveDevice {
	var devs []LiveDevice
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		d := LiveDevice{Kind: busKindOf(f[0]), Name: f[1], Modalias: f[2]}
		if f[3] != "" {
			d.Driver = path.Base(f[3])
		}
		// The node path ends ".../<controller>@<addr>/<client>@<addr>"; the two
		// addresses identify the slot with no bus numbering involved.
		segs := strings.Split(strings.Trim(f[4], "/"), "/")
		if n := len(segs); n >= 2 {
			d.Node, d.Addr = splitNode(segs[n-1])
			_, d.ParentAddr = splitNode(segs[n-2])
		}
		devs = append(devs, d)
	}
	return devs
}

func busKindOf(dir string) string {
	switch {
	case strings.Contains(dir, "/i2c/"):
		return "i2c"
	case strings.Contains(dir, "/spi/"):
		return "spi"
	}
	return ""
}

// splitNode reads "cw2217@64" as ("cw2217", "64"), the address lower-cased with
// leading zeros dropped so it compares with another source's.
func splitNode(seg string) (name, addr string) {
	name, a, _ := strings.Cut(seg, "@")
	return name, strings.TrimLeft(strings.ToLower(a), "0")
}

// FitState says whether a stock part is fitted on the unit asked.
type FitState int

const (
	FitUnknown FitState = iota // the package has no live evidence for it
	Fitted
	NotFitted
)

// Fit is a part's state with the evidence for it.
type Fit struct {
	State FitState
	Why   string
}

// Fit decides whether a stock part is fitted on the unit the live data came
// from. A vendor condition on the node ("mmi,status") decides it when it can be
// evaluated against /chosen; otherwise a client bound to a driver is a fitted
// chip and one that is not bound is not, or its driver is absent.
func (p Package) Fit(pt Part) Fit {
	if p.Live == nil || pt.Source == nil {
		return Fit{}
	}
	if cond := pt.Source.Strs("mmi,status"); len(cond) >= 3 && p.Live.HaveChosen {
		if ok, why, known := EvalMMIStatus(cond, p.Live.Chosen); known {
			if ok {
				return Fit{Fitted, why}
			}
			return Fit{NotFitted, why}
		}
	}
	if len(p.Live.Devices) == 0 {
		return Fit{}
	}
	busAddr := p.stockBusAddr(pt.Bus)
	node, addr := splitNode(pt.Node)
	if busAddr == "" || addr == "" {
		return Fit{}
	}
	busSeen := false
	for _, d := range p.Live.Devices {
		busSeen = busSeen || d.ParentAddr == busAddr
		if d.ParentAddr == busAddr && d.Addr == addr && d.Node == node {
			if d.Driver != "" {
				return Fit{Fitted, "bound to " + d.Driver}
			}
			// Not conclusive: the chip may be fitted with no driver in the stock
			// kernel.
			return Fit{FitUnknown, "the client exists but no driver is bound (the chip did not answer, or the stock kernel has no driver for it)"}
		}
	}
	if !busSeen {
		return Fit{FitUnknown, "the device lists no clients on this bus at all"}
	}
	return Fit{NotFitted, "the running kernel has no client at this address"}
}

// stockBusAddr is the register address of the controller a stock bus label
// names, from the stock base tree's symbols.
func (p Package) stockBusAddr(label string) string {
	pth := p.DT.Symbols[label]
	if pth == "" {
		return ""
	}
	_, a := splitNode(pth[strings.LastIndex(pth, "/")+1:])
	return a
}

// EvalMMIStatus evaluates a Motorola node condition, ["/chosen", prop, op,
// value] or ["/chosen", prop, value] (equality), against /chosen's properties.
// known is false when the condition names something other than /chosen or an
// operator this does not read.
func EvalMMIStatus(cond []string, chosen map[string]string) (ok bool, why string, known bool) {
	if len(cond) < 3 || cond[0] != "/chosen" {
		return false, "", false
	}
	prop, op, want := cond[1], "equals", cond[2]
	if len(cond) >= 4 {
		op, want = cond[2], cond[3]
	}
	got, has := chosen[prop]
	if !has {
		return false, fmt.Sprintf("/chosen has no %s", prop), true
	}
	switch op {
	case "contains":
		ok = strings.Contains(got, want)
	case "equals", "==":
		ok = got == want
	default:
		return false, "", false
	}
	return ok, fmt.Sprintf("mmi,status: /chosen %s = %q %s %q", prop, got, op, want), true
}

// genericPanelTokens are name parts every panel has; they say nothing about
// which one it is.
var genericPanelTokens = map[string]bool{"vid": true, "cmd": true, "mot": true, "mipi": true, "hd": true, "fhd": true, "video": true, "dsc": true}

// FittedPanel is the stock panel the live /chosen panel name selects: the one
// sharing the most distinctive name parts with it (the live name "tm_icnl9916c_
// 720x1600_652_vid" and the stock "mipi_mot_vid_tm_icnl9916c_hd_720_1600" share
// "tm" and "icnl9916c"). ok is false when nothing shares at least two.
func (p Package) FittedPanel() (name string, ok bool) {
	if p.Live == nil {
		return "", false
	}
	live := panelTokens(p.Live.Chosen["mmi,panel_name"])
	if len(live) == 0 {
		return "", false
	}
	best, bestN := "", 1
	for _, pn := range p.DT.Panels {
		n := 0
		for t := range panelTokens(pn.Name) {
			if live[t] {
				n++
			}
		}
		if n > bestN {
			best, bestN = pn.Name, n
		}
	}
	return best, best != ""
}

func panelTokens(name string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '_' || r == '-' }) {
		if !genericPanelTokens[t] {
			out[t] = true
		}
	}
	return out
}

// LiveSection is the report's account of what the device said and what it
// settled.
func LiveSection(p Package) string {
	if p.Live == nil {
		return ""
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## Live device\n")
	w("Asked over adb: %d I2C/SPI clients listed, %d /chosen properties.\n", len(p.Live.Devices), len(p.Live.Chosen))
	w("| part | bus | state | evidence |")
	w("|---|---|---|---|")
	for _, pt := range p.DT.Parts {
		if pt.Source == nil {
			continue
		}
		f := p.Fit(pt)
		state := [...]string{"unknown", "fitted", "not fitted"}[f.State]
		w("| %s | %s | %s | %s |", pt.Compatible, orNone(pt.Bus), state, f.Why)
	}
	if name, ok := p.FittedPanel(); ok {
		w("\nPanel: %s (live mmi,panel_name %q).", name, p.Live.Chosen["mmi,panel_name"])
	} else {
		w("\nPanel: not resolved — it needs /chosen, which this shell cannot read.")
	}
	for _, n := range p.Live.Notes {
		w("\n- Not asked: %s", n)
	}
	return b.String()
}
