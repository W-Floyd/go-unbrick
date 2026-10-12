package port

import (
	"fmt"
	"strings"
)

// Report renders what the package says about the board as markdown: the
// variants and displays a port must choose between, the parts that need
// drivers, and the stock partition and module picture. extra are sections an
// Emitter appends (its own findings about the package).
func Report(p Package, unknown []string, extra ...string) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }

	w("# Hardware from the stock package\n")
	w("SoC `%s` (msm-id %s); overlay model `%s`, compatible `%s`.", p.DT.SoC, ids(p.DT.MSMIDs), p.DT.Model, strings.Join(p.DT.Compat, "`, `"))
	if p.Kernel != "" {
		w("Stock kernel %s, %d vendor modules.", p.Kernel, len(p.Modules))
	}

	w("\n## Board variants\n")
	w("The bootloader picks one overlay by board id. A port that ships one DTB must choose, or ship all.\n")
	w("| overlay | board id / revision | displays |")
	w("|---|---|---|")
	for i, v := range p.DT.Variants {
		var bi []string
		for _, id := range v.BoardIDs {
			bi = append(bi, fmt.Sprintf("0x%x/0x%x", id[0], id[1]))
		}
		w("| %d | %s | %s |", i, strings.Join(bi, ", "), strings.Join(v.Panels, ", "))
	}

	w("\n## Displays\n")
	w("| panel | mode | size mm | refresh | touch | overlays |")
	w("|---|---|---|---|---|---|")
	for _, d := range p.DT.Panels {
		var hz []string
		for _, f := range d.Hz {
			hz = append(hz, fmt.Sprint(f))
		}
		w("| %s | %dx%d | %dx%d | %s | %s | %d |", d.Name, d.W, d.H, d.MMW, d.MMH, strings.Join(hz, "/"), strings.Join(d.Touch, ", "), d.OverlayCount)
	}
	w("\nWhich panel a given unit has is not in the package; read it from the live device.")
	if len(p.DT.Unreferenced) > 0 {
		w("Defined in the overlays but selected by nothing (Qualcomm reference panels): %s.", strings.Join(p.DT.Unreferenced, "; "))
	}

	w("\n## Parts\n")
	w("Nodes on an I2C or SPI bus, or named by a third party's compatible, with the stock driver that binds each (found through the modules' aliases).\n")
	w("| bus | node | compatible | stock driver | in overlays |")
	w("|---|---|---|---|---|")
	for _, pt := range p.DT.Parts {
		driver := "—"
		if pt.Driver != "" {
			driver = pt.Driver
			if pt.Desc != "" {
				driver += ": " + pt.Desc
			}
		} else if pt.Desc != "" {
			driver = "(no module: built in, or absent) " + pt.Desc
		}
		w("| %s | %s | `%s` | %s | %d of %d |", pt.Bus, pt.Node, pt.Compatible, driver, pt.Overlays, len(p.DT.Variants))
	}
	if len(unknown) > 0 {
		w("\nNo stock module binds, and nothing describes: `%s`. The driver may be built into the stock kernel; a mainline port needs one from elsewhere either way.", strings.Join(unknown, "`, `"))
	}

	if p.Mainline != nil {
		b.WriteString(mainlineSection(p))
	}

	if len(p.Fstab) > 0 {
		w("\n## Stock mounts\n")
		for _, e := range p.Fstab {
			kind := "partition"
			if e.Logical {
				kind = "logical"
			}
			w("- %s %s → %s (%s)", kind, e.Source, e.Mount, e.FS)
		}
	}
	if p.Boot.Cmdline != "" {
		w("\n## Stock cmdline (vendor_boot)\n\n`%s`", p.Boot.Cmdline)
	}
	for _, s := range extra {
		w("\n%s", strings.TrimRight(s, "\n"))
	}
	return b.String()
}

// mainlineSection says what the target kernel tree already supports of the
// board's parts: the porting work list.
func mainlineSection(p Package) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	var driver, bindingOnly, neither int
	for _, pt := range p.DT.Parts {
		md := p.Mainline[pt.Compatible]
		switch {
		case md != nil && len(md.Sources) > 0:
			driver++
		case md != nil && len(md.Bindings) > 0:
			bindingOnly++
		default:
			neither++
		}
	}
	w("\n## Mainline support (%s)\n", p.KernelTree)
	w("Of %d parts: %d have a driver in the tree, %d a binding but no driver, %d neither. The last two are the porting work.\n", len(p.DT.Parts), driver, bindingOnly, neither)
	w("`similar` lists same-vendor compatibles in the tree that share a name prefix, or a small vendor's whole list: somewhere to start, not the same part.\n")
	w("| compatible | driver | binding | firmware the driver names | similar in the tree |")
	w("|---|---|---|---|---|")
	for _, pt := range p.DT.Parts {
		md := p.Mainline[pt.Compatible]
		if md == nil {
			md = &MainlineDriver{}
		}
		w("| `%s` | %s | %s | %s | %s |", pt.Compatible, listOrDash(md.Sources), listOrDash(md.Bindings), listOrDash(md.Firmware), listOrDash(md.Similar))
	}
	return b.String()
}

func listOrDash(ss []string) string {
	if len(ss) == 0 {
		return "—"
	}
	if len(ss) > 3 {
		return strings.Join(ss[:3], ", ") + fmt.Sprintf(" (+%d)", len(ss)-3)
	}
	return strings.Join(ss, ", ")
}

func ids(v []uint32) string {
	var s []string
	for _, x := range v {
		s = append(s, fmt.Sprintf("0x%x", x))
	}
	return strings.Join(s, ", ")
}
