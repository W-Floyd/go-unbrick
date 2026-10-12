package nura

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
)

// The msm-firmware-loader rules, from its shell script (1.8.0, with the fsg
// patch) as ported in go-msm-firmware-loader. It mounts these partitions, links
// every file in each one's image/ and firmware/ directories into one flat
// directory (with the files that share a blob's name before its extension),
// and adds a few special cases. This models that on what a stock package holds,
// to say what the loader would expose before the first boot.

// loaderPartitions are the partitions the loader walks, by base name; the A/B
// slot suffix is appended on an A/B device.
var loaderPartitions = []string{"apnhlos", "bluetooth", "dsp", "fsg", "modem", "persist", "vendor"}

// PartFiles is the file list of one partition a package carries.
type PartFiles struct {
	Name  string   // base name, without a slot suffix: "modem"
	Files []string // paths inside the partition: "image/adsp.mdt"
}

// LoaderPlan is what the loader would expose.
type LoaderPlan struct {
	Slot    string
	Mounted []string          // loader partitions the package carries
	Missing []string          // ones it does not (persist is a device partition)
	Target  map[string]string // exposed path -> "partition:path" it links
}

// TopLevel counts the entries directly in the target directory: flat files and
// the directories (qca, fsg, qcom) the loader makes, which is what a listing of
// the real target shows. On fogona's stock package this gives 291, and the
// device's 292 files include qcom/ from persist, which a package does not carry.
func (pl LoaderPlan) TopLevel() int {
	seen := map[string]bool{}
	for k := range pl.Target {
		seen[strings.SplitN(k, "/", 2)[0]] = true
	}
	return len(seen)
}

// PlanLoader simulates the loader over the partitions a package carries.
func PlanLoader(slot string, parts []PartFiles) LoaderPlan {
	pl := LoaderPlan{Slot: slot, Target: map[string]string{}}
	byName := map[string]PartFiles{}
	for _, p := range parts {
		byName[p.Name] = p
	}
	var mounted []string
	for _, n := range loaderPartitions {
		if _, ok := byName[n]; ok {
			mounted = append(mounted, n)
			pl.Mounted = append(pl.Mounted, n+slotFor(n, slot))
		} else {
			pl.Missing = append(pl.Missing, n+slotFor(n, slot))
		}
	}
	sort.Strings(mounted)

	has := func(prefix string) bool {
		for k := range pl.Target {
			if strings.HasPrefix(k, prefix) {
				return true
			}
		}
		return false
	}
	link := func(target, src string) {
		if _, ok := pl.Target[target]; !ok {
			pl.Target[target] = src
		}
	}

	// `mnt/*/image/* mnt/*/firmware/*`: every partition's image/, then every
	// partition's firmware/, each in name order.
	for _, sub := range []string{"image", "firmware"} {
		for _, n := range mounted {
			dir := byName[n].Files
			for _, blob := range directFiles(dir, sub) {
				base := blob
				if i := strings.LastIndex(blob, "."); i >= 0 {
					base = blob[:i]
				}
				if has(base + ".") {
					continue // a blob of that name is already there
				}
				for _, sib := range directFiles(dir, sub) {
					if strings.HasPrefix(sib, base) && !strings.HasPrefix(sib, ".") {
						link(sib, n+":"+sub+"/"+sib)
					}
				}
			}
		}
	}

	if p, ok := byName["persist"]; ok {
		for _, f := range []string{"sensors/sns.reg", "WCNSS_qcom_wlan_nv.bin"} {
			if contains(p.Files, f) {
				link(path.Join("qcom", path.Base(f)), "persist:"+f)
				if path.Base(f) == "WCNSS_qcom_wlan_nv.bin" {
					link(f, "persist:"+f)
				}
			}
		}
	}
	// venus blobs are made available under every directory name a platform's
	// kernel might ask for, but only when there is a venus.mdt to match.
	if _, ok := pl.Target["venus.mdt"]; ok {
		for k, v := range pl.Target {
			if strings.HasPrefix(k, "venus.") {
				link("qcom/venus-x/"+k, v)
			}
		}
	}
	// Bluetooth firmware, which the kernel wants under qca/.
	if bt, ok := byName["bluetooth"]; ok {
		for _, f := range directFiles(bt.Files, "image") {
			link("qca/"+f, "bluetooth"+slotFor("bluetooth", slot)+":image/"+f)
		}
	}
	// The fsg partition as a directory, for the modem's RF configuration.
	if fsg, ok := byName["fsg"]; ok {
		for _, f := range fsg.Files {
			link("fsg/"+f, "fsg"+slotFor("fsg", slot)+":"+f)
		}
	}
	// Some kernels want .mbn where a partition has .mdt.
	for k, v := range pl.Target {
		if strings.HasSuffix(k, ".mdt") && !strings.Contains(k, "/") {
			link(strings.TrimSuffix(k, ".mdt")+".mbn", v+" (as .mbn)")
		}
	}
	return pl
}

// slotFor is the suffix a partition carries: persist is not slotted.
func slotFor(name, slot string) string {
	if name == "persist" || name == "apnhlos" {
		return ""
	}
	return slot
}

// directFiles are the names directly inside dir/ among files, sorted.
func directFiles(files []string, dir string) []string {
	var out []string
	for _, f := range files {
		if rest, ok := strings.CutPrefix(f, dir+"/"); ok && rest != "" && !strings.Contains(rest, "/") {
			out = append(out, rest)
		}
	}
	sort.Strings(out)
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

// Need is firmware something on the board loads.
type Need struct {
	Name  string
	Files []string // each "a|b": either name satisfies it
}

// Status says where a needed file stands against the loader.
type Status string

const (
	ByLoader      Status = "loader"  // the loader would expose it
	OutsideLoader Status = "outside" // the package has it, where the loader will not look
	Absent        Status = "absent"  // the package does not carry it
)

// Coverage is one needed file's standing.
type Coverage struct {
	Need   string
	File   string
	Status Status
	Where  string // the exposed path or where the package holds it
}

var gpuModel = regexp.MustCompile(`(?i)adreno(\d+)`)

// Needs lists the firmware the package's SoC subsystems and board parts load:
// the catalog's subsystem table, the GPU's zap shader named by the device
// tree, and each recognised part's own files.
func Needs(p Package, cat *catalog.Catalog) []Need {
	var out []Need
	for _, s := range cat.FWSubsystems() {
		out = append(out, Need{Name: s.Name, Files: s.Files})
	}
	if m := gpuModel.FindStringSubmatch(p.DT.GPU); m != nil {
		out = append(out, Need{Name: "gpu", Files: []string{fmt.Sprintf("a%s_zap.mbn|a%s_zap.mdt", m[1], m[1])}})
	}
	for _, part := range p.DT.Parts {
		if pt, ok := cat.DTPartFor(part.Compatible); ok && len(pt.Firmware) > 0 {
			out = append(out, Need{Name: pt.Desc, Files: pt.Firmware})
		}
	}
	return out
}

// Check places every needed file against the plan. index maps a file's base
// name to where the package holds it (any partition it carries).
func Check(pl LoaderPlan, needs []Need, index map[string][]string) []Coverage {
	var out []Coverage
	for _, n := range needs {
		for _, alts := range n.Files {
			c := Coverage{Need: n.Name, File: alts, Status: Absent}
			names := strings.Split(alts, "|")
			for _, name := range names {
				if src, ok := pl.Target[name]; ok {
					c.Status, c.Where = ByLoader, name+" <- "+src
					break
				}
			}
			if c.Status == Absent {
				for _, name := range names {
					if where := index[name]; len(where) > 0 {
						c.Status, c.Where = OutsideLoader, where[0]
						break
					}
				}
			}
			out = append(out, c)
		}
	}
	return out
}

// LoaderCheck is the whole answer to "could msm-firmware-loader supply this
// device's firmware?".
type LoaderCheck struct {
	Plan     LoaderPlan
	Coverage []Coverage
	Verdict  string
}

// CheckLoader runs the model over the package's partitions and the firmware its
// SoC and parts need. Nil when the package gave no partition lists.
func CheckLoader(p Package, cat *catalog.Catalog) *LoaderCheck {
	if len(p.LoaderParts) == 0 {
		return nil
	}
	pl := PlanLoader(p.LoaderSlot, p.LoaderParts)
	cov := Check(pl, Needs(p, cat), p.FileIndex)
	return &LoaderCheck{Plan: pl, Coverage: cov, Verdict: Verdict(pl, cov)}
}

// ToShip is the files the package has that the loader will not expose, as
// "partition:path" locations, for a firmware package to carry.
func (c *LoaderCheck) ToShip() []string {
	var out []string
	for _, cv := range c.Coverage {
		if cv.Status == OutsideLoader {
			out = append(out, cv.Where)
		}
	}
	return out
}

// Verdict summarises a check.
func Verdict(pl LoaderPlan, cov []Coverage) string {
	if len(pl.Mounted) == 0 {
		return "msm-firmware-loader has nothing to mount: the package carries none of its partitions"
	}
	var by, outside, absent int
	for _, c := range cov {
		switch c.Status {
		case ByLoader:
			by++
		case OutsideLoader:
			outside++
		default:
			absent++
		}
	}
	s := fmt.Sprintf("msm-firmware-loader would mount %d of its %d partitions, expose %d top-level entries, and cover %d of %d needed files", len(pl.Mounted), len(pl.Mounted)+len(pl.Missing), pl.TopLevel(), by, len(cov))
	if outside+absent > 0 {
		s += fmt.Sprintf("; %d to ship in a firmware package, %d the package does not carry", outside, absent)
	}
	return s
}
