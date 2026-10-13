package port

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// What of the stock kernel's configuration a target kernel tree can take. A
// stock option whose symbol the tree's Kconfig still defines can go into the
// port's kernel config as it is; one it does not define is a driver, a feature
// or a vendor patch the target kernel lacks, which is what a kernel port is.

var kconfigSymbolRe = regexp.MustCompile(`(?m)^\s*(?:menu)?config\s+([A-Za-z0-9_]+)\s*$`)

// kconfigDirs are the parts of a kernel tree that define options; walking only
// them keeps the scan to about a second.
var kconfigDirs = []string{"arch/arm64", "arch/arm", "drivers", "sound", "net", "fs", "kernel", "mm", "crypto", "lib", "security", "init", "block", "ipc", "virt", "scripts", "usr", "certs"}

// kconfigTopLevel are directories whose own Kconfig files (not their
// subdirectories') count: the tree's root and arch/, which define the HAVE_*
// and GENERIC_* options every architecture selects.
var kconfigTopLevel = []string{".", "arch"}

// KconfigSymbols are the option names (without CONFIG_) the tree's Kconfig
// files define.
func KconfigSymbols(tree string) map[string]bool {
	out := map[string]bool{}
	read := func(p string) {
		if b, err := os.ReadFile(p); err == nil {
			for _, m := range kconfigSymbolRe.FindAllSubmatch(b, -1) {
				out[string(m[1])] = true
			}
		}
	}
	for _, d := range kconfigTopLevel {
		ents, _ := os.ReadDir(filepath.Join(tree, d))
		for _, e := range ents {
			if !e.IsDir() && strings.HasPrefix(e.Name(), "Kconfig") {
				read(filepath.Join(tree, d, e.Name()))
			}
		}
	}
	for _, d := range kconfigDirs {
		filepath.WalkDir(filepath.Join(tree, d), func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || !strings.HasPrefix(e.Name(), "Kconfig") {
				return nil
			}
			read(p)
			return nil
		})
	}
	return out
}

// ConfigDiff is the stock configuration against a tree's options.
type ConfigDiff struct {
	Fragment string   // the stock options the tree defines, as a config fragment
	Have     int      // how many
	Missing  []string // stock options (set, not "n") the tree does not define
}

// CompareConfig sorts the stock configuration's set options by whether the
// tree defines them. An option stock leaves unset says nothing and is skipped.
func CompareConfig(stock map[string]string, symbols map[string]bool) ConfigDiff {
	var d ConfigDiff
	set := map[string]string{}
	for k, v := range stock {
		if v == "n" {
			continue
		}
		if symbols[strings.TrimPrefix(k, "CONFIG_")] {
			set[k] = v
			d.Have++
		} else {
			d.Missing = append(d.Missing, k)
		}
	}
	sort.Strings(d.Missing)
	d.Fragment = ConfigText(set)
	return d
}

// ConfigDiffSection is the report's account of it: counts, and the families of
// option the tree lacks (QCOM_*, MSM_*, ...), which is where the work is.
func ConfigDiffSection(d *ConfigDiff, tree string) string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## Kernel config against %s\n", tree)
	w("Of the stock config's %d set options, %d are defined by the tree's Kconfig (`kernel/stock.fragment`, to merge into the port's config) and %d are not (`kernel/stock-missing.txt`): vendor patches and drivers the target kernel lacks, and options a newer kernel made unconditional or renamed (check those before treating them as work).\n", d.Have+len(d.Missing), d.Have, len(d.Missing))
	if fam := d.families(); len(fam) > 0 {
		w("Largest families of what is missing: %s.", strings.Join(fam, ", "))
	}
	return b.String()
}

// families groups the missing options by their first word, biggest first.
func (d ConfigDiff) families() []string {
	n := map[string]int{}
	for _, m := range d.Missing {
		w := strings.TrimPrefix(m, "CONFIG_")
		if i := strings.Index(w, "_"); i > 0 {
			w = w[:i]
		}
		n[w]++
	}
	var keys []string
	for k := range n {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if n[keys[i]] != n[keys[j]] {
			return n[keys[i]] > n[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var out []string
	for _, k := range keys {
		if n[k] < 3 || len(out) == 8 {
			break
		}
		out = append(out, fmt.Sprintf("`%s_*` ×%d", k, n[k]))
	}
	return out
}

// driverIndex is the base name (lower case, no extension) of every C source and
// binding schema under the tree's drivers, sound and bindings directories, to
// its paths: where a driver for a part by that name would be.
func driverIndex(tree string) map[string][]string {
	out := map[string][]string{}
	for _, sub := range []string{"drivers", "sound", filepath.Join("Documentation", "devicetree", "bindings")} {
		filepath.WalkDir(filepath.Join(tree, sub), func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			ext := filepath.Ext(p)
			if ext != ".c" && ext != ".yaml" {
				return nil
			}
			rel, _ := filepath.Rel(tree, p)
			name := strings.ToLower(strings.TrimSuffix(e.Name(), ext))
			out[name] = append(out[name], filepath.ToSlash(rel))
			return nil
		})
	}
	return out
}

// partNumbers are the words of a stock item name that look like a part number
// ("gc08a3_mipi_raw" -> gc08a3; "hx83102p_wxga_vdo_incell_boe" -> hx83102p): at
// least five characters, with a letter and a digit.
func partNumbers(item string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(item), func(r rune) bool { return r == '_' || r == '-' || r == ' ' }) {
		letters, digits := false, false
		for _, r := range w {
			letters = letters || r >= 'a' && r <= 'z'
			digits = digits || r >= '0' && r <= '9'
		}
		if len(w) >= 5 && letters && digits {
			out = append(out, w)
		}
	}
	return out
}

// withoutSuffix drops the trailing letters of a part number that follow its last
// digit ("hx83102p" -> "hx83102", "ov13b10txd" -> "ov13b10"): stock names add a
// variant or maker suffix the upstream file leaves off. It returns the number
// unchanged when it already ends in a digit.
func withoutSuffix(pn string) string {
	i := len(pn)
	for i > 0 && pn[i-1] >= 'a' && pn[i-1] <= 'z' {
		i--
	}
	if i == 0 || i == len(pn) || i < 5 {
		return pn
	}
	return pn[:i]
}

// FindDriversByName looks for a driver or binding named for each item's part
// number, as written and then without its suffix letters. It matches names only
// (a file name containing the number); shorter prefixes are not tried, since
// "nt365" would call the nt36523 driver the nt36532's. A hit says a driver for
// that part number exists, not that it supports this variant.
func FindDriversByName(tree string, items []string) map[string][]string {
	idx := driverIndex(tree)
	out := map[string][]string{}
	for _, item := range items {
	next:
		for _, pn := range partNumbers(item) {
			for _, cand := range []string{pn, withoutSuffix(pn)} {
				var paths []string
				for name, ps := range idx {
					if strings.Contains(name, cand) {
						paths = append(paths, ps...)
					}
				}
				if len(paths) > 0 {
					sort.Strings(paths)
					out[item] = firstN(paths, 2)
					break next
				}
			}
		}
	}
	return out
}
