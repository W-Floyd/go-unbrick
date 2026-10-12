package port

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// FirmwareRef is firmware something on the board names, with the files in the
// package that would satisfy it. Nothing here comes from a table: a name is
// either in the device tree, in a driver, or on a partition the SoC vendor
// filled.
type FirmwareRef struct {
	Names []string // file names that satisfy it: any one will do
	By    []string // who asks: "driver aw882xx_dlkm", "device tree vidc,firmware-name", ...
	// Where are the package locations ("partition:path") of the first of Names
	// the package carries; empty when none is present.
	Where []string
}

var generation = regexp.MustCompile(`^[a-z](\d{3,4})_`)

// versioned strips a trailing version from a family name of three or more
// letters: cmbtfw10 and cmnv13s group as cmbtfw and cmnv, while a662 (one
// letter) and aw869x (two) stay as they are.
var versioned = regexp.MustCompile(`^([A-Za-z]{3,})\d+[a-z]?$`)

// FirmwareRefs finds the firmware the package's board names:
//
//  1. every firmware file name the device tree gives (a stem like "venus"
//     matches venus.mbn and venus.mdt);
//  2. every file a module names that the package actually carries, which keeps
//     a driver's generic strings out; and
//  3. every remoteproc image (.mdt or .mbn) on the modem partition, the
//     subsystem firmware the SoC vendor shipped for this board.
func FirmwareRefs(p Package) []FirmwareRef {
	r := &refs{index: p.FileIndex, by: map[string]*FirmwareRef{}}

	for _, f := range p.DT.FirmwareNames {
		r.add(r.satisfying(f.Value), "device tree "+f.Prop)
	}

	// A driver lists every hardware generation it supports; the device tree's
	// GPU model ("Adreno610v2") narrows a<NNN>_ names to this board's.
	gen := map[string]bool{}
	for _, m := range regexp.MustCompile(`\d{3,4}`).FindAllString(p.DT.GPU, -1) {
		gen[m] = true
	}
	for _, m := range p.Modules {
		names := m.Firmware
		if len(gen) > 0 {
			var keep []string
			match := false
			for _, n := range names {
				if g := generation.FindStringSubmatch(n); g != nil && gen[g[1]] {
					match = true
				}
			}
			for _, n := range names {
				if g := generation.FindStringSubmatch(n); g != nil && match && !gen[g[1]] {
					continue
				}
				keep = append(keep, n)
			}
			names = keep
		}
		for _, n := range names {
			if len(r.index[n]) > 0 {
				r.add([]string{n}, "driver "+m.Name)
			}
		}
	}

	// What the target kernel's drivers ask for, which is what a port gets
	// (the stock drivers' names are a proxy). Named even when the package does
	// not carry the file: that gap is the finding.
	for _, part := range p.DT.Parts {
		if md := p.Mainline[part.Compatible]; md != nil && len(md.Sources) > 0 {
			for _, n := range md.Firmware {
				r.add(r.satisfying(n), "mainline "+md.Sources[0])
			}
		}
	}

	for _, part := range p.PartFiles {
		if part.Name != "modem" {
			continue
		}
		stems := map[string]bool{}
		for _, f := range part.Files {
			if dir, file := path.Split(f); dir == "image/" && (strings.HasSuffix(file, ".mdt") || strings.HasSuffix(file, ".mbn")) {
				stems[strings.TrimSuffix(strings.TrimSuffix(file, ".mdt"), ".mbn")] = true
			}
		}
		for s := range stems {
			r.add(r.satisfying(s), "shipped in the modem partition")
		}
	}

	var out []FirmwareRef
	for _, ref := range r.by {
		sort.Strings(ref.By)
		out = append(out, *ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Names[0] < out[j].Names[0] })
	return out
}

// FirmwareGroup is a family of shipped firmware files that nothing in the
// package's evidence names.
type FirmwareGroup struct {
	Prefix string   // "bdwlan"
	Files  []string // base names
	Where  string   // where the first of them is, "partition:path"
	// ForThisDevice are the files whose name contains the device's codename: a
	// shared image carries other models' files beside the device's own.
	ForThisDevice []string
}

// UnclaimedFirmware lists what the package ships in the firmware directories
// (image/ and firmware/ of the partitions it carries) that no reference names:
// board data a driver consumes by content (a Wi-Fi BDF), calibration, haptic
// patterns. They are why a clean "all needs covered" is not "nothing else
// matters": something may use a file without ever naming it. Files are grouped
// by the leading word of their name, since a family is one decision.
func UnclaimedFirmware(p Package) []FirmwareGroup {
	claimed := map[string]bool{} // stems and full names a reference covers
	for _, r := range FirmwareRefs(p) {
		for _, n := range r.Names {
			claimed[n] = true
			claimed[strings.TrimSuffix(n, path.Ext(n))] = true
		}
	}
	groups := map[string]*FirmwareGroup{}
	for _, part := range p.PartFiles {
		for _, dir := range []string{"image", "firmware"} {
			for _, f := range p.partDirFiles(part, dir) {
				stem := strings.TrimSuffix(f, path.Ext(f))
				if claimed[f] || claimed[stem] || isSegment(strings.TrimPrefix(path.Ext(f), ".")) {
					continue
				}
				key := f
				if i := strings.IndexAny(f, "_."); i > 0 {
					key = f[:i]
				}
				// A numbered family ("cmbtfw10", "cmnv13s") is one decision.
				if m := versioned.FindStringSubmatch(key); m != nil {
					key = m[1]
				}
				g := groups[key]
				if g == nil {
					g = &FirmwareGroup{Prefix: key, Where: part.Name + p.Slot + ":" + dir + "/" + f}
					groups[key] = g
				}
				g.Files = append(g.Files, f)
			}
		}
	}
	_, code, _ := p.Identity()
	code = strings.ToLower(code)
	var out []FirmwareGroup
	for _, g := range groups {
		sort.Strings(g.Files)
		for _, f := range g.Files {
			if code != "" && strings.Contains(strings.ToLower(f), code) {
				g.ForThisDevice = append(g.ForThisDevice, f)
			}
		}
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// partDirFiles are the names directly inside dir/ of a partition.
func (p Package) partDirFiles(part PartFiles, dir string) []string {
	var out []string
	for _, f := range part.Files {
		if rest, ok := strings.CutPrefix(f, dir+"/"); ok && rest != "" && !strings.Contains(rest, "/") {
			out = append(out, rest)
		}
	}
	return out
}

type refs struct {
	index map[string][]string
	by    map[string]*FirmwareRef
}

// satisfying lists the file names in the package a firmware name could mean:
// the name itself, or, for a stem, each file that is the stem plus an
// extension.
func (r *refs) satisfying(want string) []string {
	var out []string
	if len(r.index[want]) > 0 {
		out = append(out, want)
	}
	for n := range r.index {
		if rest, ok := strings.CutPrefix(n, want+"."); ok && !strings.Contains(rest, ".") && !isSegment(rest) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return []string{want} // named but not in the package
	}
	return out
}

// isSegment reports a PIL segment extension (.b00, .b01): part of a split
// image, not an alternative name for it.
func isSegment(ext string) bool {
	return len(ext) == 3 && ext[0] == 'b' && ext[1] >= '0' && ext[1] <= '9' && ext[2] >= '0' && ext[2] <= '9'
}

func (r *refs) add(names []string, by string) {
	if len(names) == 0 {
		return
	}
	key := strings.Join(names, "|")
	ref := r.by[key]
	if ref == nil {
		ref = &FirmwareRef{Names: names}
		for _, n := range names {
			if w := r.index[n]; len(w) > 0 {
				ref.Where = w[:1]
				break
			}
		}
		r.by[key] = ref
	}
	for _, b := range ref.By {
		if b == by {
			return
		}
	}
	ref.By = append(ref.By, by)
}
