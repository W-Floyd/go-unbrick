package port

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MainlineDriver is what a kernel source tree says about a device-tree
// compatible: the drivers whose match tables name it, the bindings that
// document it, and the firmware those drivers' sources name. It is how a port
// learns, with no table of drivers, which of the board's parts the target
// kernel already supports and what firmware names it will ask for.
type MainlineDriver struct {
	Compatible string
	Sources    []string // driver files (relative to the tree) whose of_device_id names it
	Bindings   []string // binding schemas (relative) that list it
	Firmware   []string // file names the driver sources mention
	// Similar are compatibles in the tree from the same vendor whose device
	// name shares a prefix with this one, for a part the tree does not name
	// exactly: a vendor's variant often has a mainline sibling to start from.
	Similar []string // "vendor,device (driver file)"
}

// minSharedPrefix is how much of a device name two compatibles must share to be
// offered as similar.
const minSharedPrefix = 5

var ofMatch = regexp.MustCompile(`\.compatible\s*=\s*"([^"]+)"`)

// ScanKernelTree finds, in the drivers, sound and binding directories of a
// kernel tree at root, what supports each of compats. A compatible nothing
// names is still in the result, with no sources and no bindings: the absence
// is the finding.
func ScanKernelTree(root string, compats []string) (map[string]*MainlineDriver, error) {
	if st, err := os.Stat(filepath.Join(root, "drivers")); err != nil || !st.IsDir() {
		return nil, &fs.PathError{Op: "scan", Path: root, Err: fs.ErrNotExist}
	}
	want := map[string]*MainlineDriver{}
	var quoted []string
	for _, c := range compats {
		if _, dup := want[c]; !dup {
			want[c] = &MainlineDriver{Compatible: c}
			quoted = append(quoted, regexp.QuoteMeta(c))
		}
	}
	if len(want) == 0 {
		return want, nil
	}
	// A binding lists a compatible as a bare YAML scalar: "- const: x", "- x".
	binding := regexp.MustCompile(`(?m)(?:^|[\s'"-])(` + strings.Join(quoted, "|") + `)['"]?\s*$`)

	vendors := map[string]bool{}
	for c := range want {
		if v, _, ok := vendorOf(c); ok {
			vendors[v] = true
		}
	}
	inTree := map[string]string{} // same-vendor compatible -> a driver file

	fwFiles := map[string]map[string]bool{} // compatible -> driver files
	for _, sub := range []string{"drivers", "sound", "Documentation/devicetree/bindings"} {
		dir := filepath.Join(root, sub)
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			isC, isYAML := strings.HasSuffix(p, ".c"), strings.HasSuffix(p, ".yaml")
			if !isC && !isYAML {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			if isC {
				if !bytes.Contains(b, []byte(".compatible")) {
					return nil
				}
				for _, m := range ofMatch.FindAllSubmatch(b, -1) {
					if v, _, ok := vendorOf(string(m[1])); ok && vendors[v] {
						if _, dup := inTree[string(m[1])]; !dup {
							inTree[string(m[1])] = rel
						}
					}
					if d := want[string(m[1])]; d != nil && !contains(d.Sources, rel) {
						d.Sources = append(d.Sources, rel)
						if fwFiles[d.Compatible] == nil {
							fwFiles[d.Compatible] = map[string]bool{}
						}
						fwFiles[d.Compatible][p] = true
					}
				}
				return nil
			}
			for _, m := range binding.FindAllSubmatch(b, -1) {
				if d := want[string(m[1])]; d != nil && !contains(d.Bindings, rel) {
					d.Bindings = append(d.Bindings, rel)
				}
			}
			return nil
		})
	}

	for c, files := range fwFiles {
		seen := map[string]bool{}
		for f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, loc := range firmwareName.FindAllIndex(b, -1) {
				// A source names its firmware as a path or a printf format. What
				// follows a conversion ("a%d_sqe.fw" gives "d_sqe.fw") is a
				// fragment, not a file name.
				// In C source a file name sits in a string literal, right after
				// its quote or a path separator; "cfg.init_data" is a field.
				if loc[0] == 0 || b[loc[0]-1] == '%' || (b[loc[0]-1] != '"' && b[loc[0]-1] != '/') {
					continue
				}
				if name := string(b[loc[0]:loc[1]]); !seen[name] {
					seen[name] = true
					want[c].Firmware = append(want[c].Firmware, name)
				}
			}
		}
		sort.Strings(want[c].Firmware)
	}
	for _, d := range want {
		sort.Strings(d.Sources)
		sort.Strings(d.Bindings)
		if len(d.Sources) == 0 {
			d.Similar = similar(d.Compatible, inTree)
		}
	}
	return want, nil
}

// vendorOf splits a compatible into vendor and device: at the comma
// ("ti,bq25890"), or, when it has none, at the first dash ("chipone-tddi").
func vendorOf(c string) (vendor, dev string, ok bool) {
	if v, d, ok := strings.Cut(c, ","); ok {
		return v, d, true
	}
	if v, d, ok := strings.Cut(c, "-"); ok {
		return v, d, true
	}
	return "", "", false
}

// maxVendorEntries is how few entries a vendor may have in the tree for all of
// them to be offered when no device name is close.
const maxVendorEntries = 4

// similar lists the same-vendor compatibles sharing a device-name prefix with c;
// when none does and the vendor has only a few entries in the tree, those.
func similar(c string, inTree map[string]string) []string {
	vendor, dev, ok := vendorOf(c)
	if !ok {
		return nil
	}
	var near, sameVendor []string
	for other, file := range inTree {
		ov, od, _ := vendorOf(other)
		if ov != vendor || other == c {
			continue
		}
		entry := other + " (" + file + ")"
		sameVendor = append(sameVendor, entry)
		n := 0
		for n < len(dev) && n < len(od) && strings.EqualFold(dev[n:n+1], od[n:n+1]) {
			n++
		}
		if n >= minSharedPrefix {
			near = append(near, entry)
		}
	}
	out := near
	if len(out) == 0 && len(sameVendor) <= maxVendorEntries {
		out = sameVendor
	}
	sort.Strings(out)
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
