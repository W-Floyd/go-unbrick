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
