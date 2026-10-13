package main

import (
	"fmt"
	"os"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/gitsrc"
	"github.com/W-Floyd/go-unbrick/internal/port"
)

// setKnownTrees records the catalog's trees for the package's SoC: under the
// compatible the stock tree gives and the name of the best matching dtsi.
func setKnownTrees(pkg *port.Package, cat *catalog.Catalog) {
	var best []string
	if len(pkg.SoC) > 0 {
		best = append(best, pkg.SoC[0].File)
	}
	pkg.KnownTrees = port.KnownTrees(cat, port.KnownTreeKeys(pkg.DT.SoC, best))
}

// resolveKernelTrees turns each --kernel-tree value into a directory: a path is
// used as it is, a git URL (optionally "#branch-or-tag") is fetched into the
// cache far enough to match its SoC files. remote maps the directory of each
// fetched tree back to its source.
func resolveKernelTrees(values []string, say func(string, ...any)) (roots []string, remote map[string]gitsrc.Source, err error) {
	remote = map[string]gitsrc.Source{}
	cache, cerr := gitsrc.DefaultCache()
	for _, v := range values {
		src, isURL := gitsrc.Parse(v)
		if !isURL {
			roots = append(roots, v)
			continue
		}
		if cerr != nil {
			return nil, nil, fmt.Errorf("--kernel-tree %s: no cache directory for it: %w", v, cerr)
		}
		say("fetching the kernel tree %s", src)
		dir, err := gitsrc.Ensure(src, cache, gitsrc.DTS, os.Stderr)
		if err != nil {
			return nil, nil, fmt.Errorf("--kernel-tree: %w", err)
		}
		roots = append(roots, dir)
		remote[dir] = src
	}
	return roots, remote, nil
}

// applyKernelTrees reads what the kernel trees say about the package: which
// tree has the best SoC dtsi (that one is the target; a remote one is fetched
// in full), then what the target supports of the board's parts, how its config
// and drivers compare with the stock kernel's, and the SoC work against its dtsi.
// The other trees are searched for drivers the target lacks.
func applyKernelTrees(pkg *port.Package, values, socDTSI []string, cat *catalog.Catalog, say func(string, ...any)) error {
	// "known" stands for every tree the catalog lists for the SoC.
	var plain []string
	wantKnown := false
	for _, v := range values {
		if v == "known" {
			wantKnown = true
		} else {
			plain = append(plain, v)
		}
	}
	roots, remote, err := resolveKernelTrees(plain, say)
	if err != nil {
		return err
	}
	if wantKnown {
		// The best dtsi of the trees already given names the SoC the way the
		// community trees do (sm6225 for the stock "khaje").
		var names []string
		if len(roots) > 0 {
			if ms, _, _, err := port.MatchTrees(roots, socDTSI, pkg.DT.UnitAddrs, pkg.DT.SoC); err == nil && len(ms) > 0 {
				names = append(names, ms[0].File)
			}
		}
		known := port.KnownTrees(cat, port.KnownTreeKeys(pkg.DT.SoC, names))
		if len(known) == 0 {
			fmt.Fprintf(os.Stderr, "port: the catalog lists no known kernel tree for %s\n", pkg.DT.SoC)
		}
		var vals []string
		for _, t := range known {
			vals = append(vals, port.KnownTreeValue(t))
		}
		more, more2, err := resolveKernelTrees(vals, say)
		if err != nil {
			return err
		}
		roots = append(roots, more...)
		for k, v := range more2 {
			remote[k] = v
		}
	}
	if len(roots) == 0 {
		return nil
	}
	ms, target, choices, err := port.MatchTrees(roots, socDTSI, pkg.DT.UnitAddrs, pkg.DT.SoC)
	if err != nil {
		return fmt.Errorf("--kernel-tree: %w", err)
	}
	for i := range choices {
		if src, ok := remote[choices[i].Root]; ok {
			choices[i].Name = src.String()
		}
	}
	// The target is read for its drivers and Kconfig too: a fetched tree has
	// only its device trees so far.
	if src, ok := remote[target]; ok {
		say("fetching the driver and Kconfig files of %s", src)
		cache, _ := gitsrc.DefaultCache()
		if target, err = gitsrc.Ensure(src, cache, gitsrc.Full, os.Stderr); err != nil {
			return fmt.Errorf("--kernel-tree: %w", err)
		}
	}
	pkg.KernelTree, pkg.KernelTrees, pkg.TreeChoices = target, roots, choices

	var compats []string
	for _, pt := range pkg.DT.Parts {
		compats = append(compats, pt.Compatible)
	}
	if pkg.Mainline, err = port.ScanKernelTrees(target, roots, compats); err != nil {
		return fmt.Errorf("--kernel-tree %s: %w", target, err)
	}
	if pkg.KernelConfig != nil {
		d := port.CompareConfig(pkg.KernelConfig, port.KconfigSymbols(target))
		pkg.ConfigDiff = &d
		var items []string
		for _, c := range pkg.ConfigChoices() {
			items = append(items, c.Items...)
		}
		if len(items) > 0 {
			pkg.ChoiceDrivers = port.FindDriversInTrees(target, roots, items)
		}
	}

	pkg.SoC = ms
	if len(ms) == 0 {
		return nil
	}
	best := ms[0]
	if dtsi, err := os.ReadFile(best.Path(target)); err == nil {
		pkg.BusLabels = port.BusLabels(pkg.DT, string(dtsi))
		pkg.SoCRegions = port.ParseDTSRegions(string(dtsi))
	}
	pkg.SoCGap = port.ComputeSoCGap(target, *pkg)
	pkg.SoCLabels = port.SoCLabels(target, best.File)
	pkg.SoCAddrLabels = port.SoCLabelsByAddr(target, best.File)
	pkg.SoCFacts = port.ReadSoCDTSI(target, best.File)
	var unstocked []string
	for _, l := range pkg.SoCFacts.Needs {
		if _, ok := pkg.DT.FixedClocks[l]; !ok {
			unstocked = append(unstocked, l)
		}
	}
	pkg.ClockDefs = port.SiblingClockDefs(target, ms[1:], unstocked)
	return nil
}
