package nura

import (
	"fmt"
	"strings"
)

// Report renders what the package says about the board as markdown: the
// variants and displays a port must choose between, the parts that need
// drivers, and the stock partition and module picture.
func Report(p Package, unknown []string) string {
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
	class := ""
	for _, pt := range p.DT.Parts {
		if pt.Class != class {
			class = pt.Class
			w("\n**%s**\n", class)
		}
		w("- %s (`%s`, in %d of %d overlays)", pt.Desc, pt.Compatible, pt.Overlays, len(p.DT.Variants))
	}
	if len(unknown) > 0 {
		w("\nCompatibles not in the parts table (add to `catalog/dt_parts.yaml`): `%s`.", strings.Join(unknown, "`, `"))
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
	return b.String()
}

func ids(v []uint32) string {
	var s []string
	for _, x := range v {
		s = append(s, fmt.Sprintf("0x%x", x))
	}
	return strings.Join(s, ", ")
}
