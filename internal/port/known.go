package port

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
)

// KnownTreeKeys are the names to look a SoC up under in the catalog's known
// kernel trees: the compatible the stock base tree gives ("qcom,khaje"), and the
// vendor's name for each SoC dtsi the stock tree matched best ("qcom,sm6225" for
// sm6225.dtsi), since a stock tree often knows the SoC by a codename the
// community trees do not use.
func KnownTreeKeys(soc string, bestDtsi []string) []string {
	var keys []string
	add := func(k string) {
		k = strings.ToLower(strings.TrimSpace(k))
		for _, e := range keys {
			if e == k {
				return
			}
		}
		if k != "" {
			keys = append(keys, k)
		}
	}
	add(soc)
	vendor, _, _ := strings.Cut(soc, ",")
	for _, f := range bestDtsi {
		name := strings.TrimSuffix(filepath.Base(f), ".dtsi")
		if vendor != "" && name != "" {
			add(vendor + "," + name)
		}
	}
	return keys
}

// KnownTrees are the catalog's trees for any of the keys, once each.
func KnownTrees(cat *catalog.Catalog, keys []string) []catalog.KnownTree {
	var out []catalog.KnownTree
	seen := map[string]bool{}
	for _, k := range keys {
		for _, t := range cat.SoCTreesFor(k) {
			if id := t.URL + "#" + t.Ref; !seen[id] {
				seen[id] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// KnownTreeValue is a known tree written as a --kernel-tree value.
func KnownTreeValue(t catalog.KnownTree) string {
	if t.Ref == "" {
		return t.URL
	}
	return t.URL + "#" + t.Ref
}

// KnownTreesSection is the report's list of trees the catalog knows for the SoC,
// marking those already among the trees given.
func KnownTreesSection(known []catalog.KnownTree, soc string, given []TreeChoice) string {
	if len(known) == 0 {
		return ""
	}
	used := map[string]bool{}
	for _, g := range given {
		used[g.Name] = true
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## Known kernel trees\n")
	w("The catalog lists these mainline-based trees for `%s` (read from pmaports; a tree is where to start, not a claim the SoC works). Pass one with `--kernel-tree URL[#branch]`, or all of them with `--kernel-tree known`.\n", soc)
	w("| tree | branch | pinned by pmaports | what it is | |")
	w("|---|---|---|---|---|")
	for _, t := range known {
		branch := t.Ref
		if branch == "" {
			branch = "default"
		}
		pinned := t.Pinned
		if pinned == "" {
			pinned = "—"
		}
		mark := ""
		if used[KnownTreeValue(t)] {
			mark = "used"
		}
		w("| %s | %s | %s | %s | %s |", t.URL, branch, pinned, t.Notes, mark)
	}
	return b.String()
}
