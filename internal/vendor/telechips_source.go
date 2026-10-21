package vendor

import (
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/telechips"
)

// Facts of an LK bootloader source tree (a Telechips SDK's lk, as an OEM ships it
// in a GPL source release): what it builds for, how, and which recovery and
// verification paths it contains.
var (
	// LKSourceTarget is the project's target, platform and board revision.
	LKSourceTarget = facts.Key[string]("lk_source_target")
	// LKSourceBuild is the behaviour its project makefile turns on.
	LKSourceBuild = facts.Key[string]("lk_source_build")
	// LKSourceRecovery is the flashing and verification code the tree contains.
	LKSourceRecovery = facts.Key[string]("lk_source_recovery")
)

// recoveryPaths are suffixes of tree members whose presence says what the
// bootloader can do, with the capability each shows.
var recoveryPaths = []struct{ suffix, what string }{
	{"/app/aboot/fastboot.c", "LK fastboot"},
	{"/u-boot/common/cmd_fastboot.c", "U-Boot fastboot"},
	{"/u-boot/common/cmd_gpt.c", "GPT command"},
	{"/app/aboot/recovery.c", "recovery boot"},
}

// lkRoots finds each LK tree by its project makefiles, <root>/project/<name>.mk:
// root to the project member names under it.
func lkRoots(names map[string]bool) map[string][]string {
	roots := map[string][]string{}
	for n := range names {
		root, rest, ok := strings.Cut(n, "/project/")
		if ok && strings.HasSuffix(rest, ".mk") && !strings.Contains(rest, "/") {
			roots[root] = append(roots[root], n)
		}
	}
	return roots
}

// hasMember reports a member under root whose path ends in suffix.
func hasMember(names map[string]bool, root, suffix string) bool {
	if names[root+suffix] {
		return true
	}
	for n := range names {
		if strings.HasPrefix(n, root+"/") && strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}

// LearnPackage implements PackageLearner: an LK source tree's build and recovery
// facts. A project makefile without a TARGET is not a bootloader's; a package with
// no LK tree adds nothing.
func (tcc) LearnPackage(pkg PackageAccess, bag *facts.Bag) {
	roots := lkRoots(pkg.Names)
	keys := make([]string, 0, len(roots))
	for r := range roots {
		keys = append(keys, r)
	}
	sort.Strings(keys)
	var targets, builds, rec []string
	for _, root := range keys {
		sort.Strings(roots[root])
		found := false
		for _, name := range roots[root] {
			project := pkg.Read(name)
			src, ok := telechips.ParseLKSource(project, nil)
			if !ok {
				continue
			}
			found = true
			src, _ = telechips.ParseLKSource(project, pkg.Read(root+"/target/"+src.Target+"/rules.mk"))
			line := src.Target
			if src.Platform != "" {
				line += " (platform " + src.Platform + ")"
			}
			if src.HWRev != "" {
				line += ", HW_REV " + src.HWRev
				if src.Board != "" {
					line += ": " + strings.Join(strings.Fields(src.Board), " ")
				}
			}
			targets = append(targets, line)
			if d := src.Describe(); len(d) > 0 {
				builds = append(builds, strings.Join(d, ", "))
			}
		}
		if !found {
			continue
		}
		var caps []string
		for _, rp := range recoveryPaths {
			if hasMember(pkg.Names, root, rp.suffix) {
				caps = append(caps, rp.what)
			}
		}
		if strings.Contains(string(pkg.Read(root+"/AndroidBoot.mk")), "TARGET_BOOTIMG_SIGNED") {
			caps = append(caps, "signed boot image switch (TARGET_BOOTIMG_SIGNED)")
		}
		if len(caps) > 0 {
			rec = append(rec, strings.Join(caps, ", "))
		}
	}
	prov := facts.Provenance{Source: "lk project/*.mk, target/*/rules.mk", Authority: facts.Attested}
	for _, f := range []struct {
		key  facts.Fact[string]
		vals []string
	}{{LKSourceTarget, targets}, {LKSourceBuild, builds}, {LKSourceRecovery, rec}} {
		if len(f.vals) > 0 {
			facts.Set(bag, f.key, strings.Join(f.vals, "; "), prov)
		}
	}
}
