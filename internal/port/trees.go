package port

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Several kernel trees may be on hand: mainline, a vendor or distribution fork,
// a checkout of a patch series. The SoC is whatever dtsi, in any of them, best
// matches the stock register map; that tree is the one to port against, and the
// others are still searched for drivers the target lacks.

// TreeChoice is how one tree fits the stock device tree.
type TreeChoice struct {
	Root   string   // the directory read as a tree
	Name   string   // what to call it in the report (a URL for a fetched tree)
	Best   SoCMatch // its best SoC dtsi
	Has    bool     // false when none of its dtsi shares an address
	Names  bool     // the best one names the stock SoC
	Chosen bool     // the tree to port against
}

// MatchTrees ranks every tree's SoC dtsi files (and the extra files, read
// against each tree's includes) against the stock register map, and picks the
// tree that owns the best match. The stock SoC's name settles close calls (see
// PreferNamed). With no match anywhere the first tree is the target.
func MatchTrees(trees, extra []string, stock map[string]bool, soc string) (ms []SoCMatch, target string, choices []TreeChoice, err error) {
	if len(trees) == 0 {
		return nil, "", nil, fmt.Errorf("no kernel tree")
	}
	seenExtra := map[string]int{} // extra file -> index in all, for the best score
	var all []SoCMatch
	for _, t := range trees {
		own, err := FindSoCDTSI(t, stock)
		if err != nil {
			return nil, "", nil, fmt.Errorf("%s: %w", t, err)
		}
		all = append(all, own...)
		more, err := FindExtraSoCDTSI(t, extra, stock)
		if err != nil {
			return nil, "", nil, err
		}
		for _, m := range more {
			if i, dup := seenExtra[m.File]; dup {
				if m.Score > all[i].Score {
					all[i] = m
				}
				continue
			}
			seenExtra[m.File] = len(all)
			all = append(all, m)
		}
	}
	ms = PreferNamed("", MergeSoCMatches(all), soc)
	target = trees[0]
	if len(ms) > 0 {
		target = ms[0].Root
	}
	model := socModel(soc)
	for _, t := range trees {
		c := TreeChoice{Root: t, Name: t, Chosen: t == target}
		for _, m := range ms {
			if m.Root == t {
				c.Best, c.Has = m, true
				c.Names = model != "" && m.Shared >= minNamedShared && dtsiMentions(t, m.File, model)
				break
			}
		}
		choices = append(choices, c)
	}
	return ms, target, choices, nil
}

// TreesSection is the report's account of which tree was chosen and why; empty
// for a single tree.
func TreesSection(choices []TreeChoice, soc string) string {
	if len(choices) < 2 {
		return ""
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## Kernel trees\n")
	w("The SoC dtsi that best matches the stock device tree, from each tree given. The tree with the best match is the one the port is written against; the others are only searched for drivers.\n")
	w("| tree | closest SoC dtsi | score | names `%s` | |", soc)
	w("|---|---|---|---|---|")
	for _, c := range choices {
		file, score, names := "none shares an address", "—", "—"
		if c.Has {
			file, score = filepath.Base(c.Best.File), fmt.Sprintf("%.2f", c.Best.Score)
			names = map[bool]string{true: "yes", false: "no"}[c.Names]
		}
		chosen := ""
		if c.Chosen {
			chosen = "**chosen**"
		}
		w("| %s | %s | %s | %s | %s |", c.Name, file, score, names, chosen)
	}
	return b.String()
}

// treeLabel names a tree in a path prefix: its directory name.
func treeLabel(root string) string { return filepath.Base(root) }

// ScanKernelTrees scans the target tree for what drives each compatible, and for
// one it lacks, the other trees: a hit there is kept with its paths prefixed by
// the tree's name. The target must be a kernel tree; another that is not (or
// that was only fetched far enough to match its SoC) is skipped.
func ScanKernelTrees(target string, trees, compats []string) (map[string]*MainlineDriver, error) {
	out, err := ScanKernelTree(target, compats)
	if err != nil {
		return nil, err
	}
	for _, t := range trees {
		if t == target {
			continue
		}
		other, err := ScanKernelTree(t, compats)
		if err != nil {
			continue
		}
		for c, md := range out {
			if len(md.Sources) > 0 || len(md.Bindings) > 0 {
				continue
			}
			o := other[c]
			if o == nil || len(o.Sources) == 0 && len(o.Bindings) == 0 {
				continue
			}
			md.Sources = prefixed(treeLabel(t), o.Sources)
			md.Bindings = prefixed(treeLabel(t), o.Bindings)
			if len(md.Firmware) == 0 {
				md.Firmware = o.Firmware
			}
		}
	}
	return out, nil
}

// FindDriversInTrees is FindDriversByName over the target, then the other trees
// for an item the target has no file for, with the other tree's name on the path.
func FindDriversInTrees(target string, trees, items []string) map[string][]string {
	out := FindDriversByName(target, items)
	for _, t := range trees {
		if t == target {
			continue
		}
		var missing []string
		for _, it := range items {
			if len(out[it]) == 0 {
				missing = append(missing, it)
			}
		}
		if len(missing) == 0 {
			break
		}
		for it, ps := range FindDriversByName(t, missing) {
			out[it] = prefixed(treeLabel(t), ps)
		}
	}
	return out
}

func prefixed(label string, paths []string) []string {
	var out []string
	for _, p := range paths {
		out = append(out, label+":"+p)
	}
	return out
}
