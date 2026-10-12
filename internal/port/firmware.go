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
