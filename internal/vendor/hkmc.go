package vendor

import (
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// hkmc: Hyundai Motor Group head-unit firmware (Kia/Hyundai/Genesis). Only
// package facts are read from it; it has no recovery path.
type hkmc struct{}

func init() { Register(hkmc{}) }

func (hkmc) ID() string                 { return "hkmc" }
func (hkmc) Platform() string           { return "" }
func (hkmc) OEMIDs() []string           { return nil }
func (hkmc) CanIngest(path string) bool { return false }

func (hkmc) IngestDonor(string) (*blankflash.Donor, error) { return nil, ErrUnsupported }
func (hkmc) HarvestStock(TargetSource) (*blankflash.Target, error) {
	return nil, ErrUnsupported
}
func (hkmc) Assemble(*blankflash.Donor, *blankflash.Target, AssembleOptions) (*blankflash.ForgeResult, error) {
	return nil, ErrUnsupported
}

// LearnPackage implements PackageLearner: update.info's build, the modem and
// GPS sheets, and — when a key opens enc_boot.img — the boot image's kernel,
// cmdline and ramdisk default.prop.
func (hkmc) LearnPackage(pkg PackageAccess, bag *facts.Bag) {
	if !pkg.Names["update.info"] {
		return
	}
	if v := ParseUpdateInfo(pkg.Read("update.info")); v != "" {
		facts.Set(bag, facts.SoftwareVersion, v, facts.Provenance{Source: "update.info", Authority: facts.Attested})
	}

	// One entry per distinct modem build, naming the variants that carry it.
	byVersion := map[string][]string{}
	for name := range pkg.Names {
		dir, ok := strings.CutSuffix(name, "/modem_version.txt")
		if !ok || !strings.HasPrefix(dir, "modem/") {
			continue
		}
		if v := ParseModemVersion(pkg.Read(name)); v != "" {
			byVersion[v] = append(byVersion[v], strings.TrimPrefix(dir, "modem/"))
		}
	}
	var modem []string
	for v, variants := range byVersion {
		sort.Strings(variants)
		modem = append(modem, v+" ("+strings.Join(variants, ", ")+")")
	}
	sort.Strings(modem)
	if len(modem) > 0 {
		facts.Set(bag, ModemVersion, strings.Join(modem, "; "), facts.Provenance{Source: "modem/*/modem_version.txt", Authority: facts.Attested})
	}

	var gps []string
	if v := strings.TrimSpace(string(pkg.Read("gps/trimble.txt"))); v != "" {
		gps = append(gps, "Trimble "+v)
	}
	if v := strings.TrimSpace(string(pkg.Read("gps/ublox/ublox.txt"))); v != "" {
		gps = append(gps, "u-blox "+v)
	}
	if len(gps) > 0 {
		facts.Set(bag, GPSFirmware, strings.Join(gps, ", "), facts.Provenance{Source: "gps/*.txt", Authority: facts.Attested})
	}

	const boot = "enc_system/enc_boot.img/boot.img"
	if !pkg.Names["enc_system/enc_boot.img"] {
		return
	}
	hdr := pkg.Read(boot)
	if !pkg.Decrypts() || hdr == nil {
		return
	}
	prov := facts.Provenance{Source: "enc_boot.img", Authority: facts.Attested}
	if im, err := bootimg.Parse(hdr); err == nil && im.Cmdline != "" {
		facts.Set(bag, KernelCmdline, im.Cmdline, prov)
	}
	if v := ZImageKernelVersion(pkg.Read(boot + "/kernel")); v != "" {
		facts.Set(bag, KernelVersion, v, prov)
	}
	if v := propValue(pkg.Read(boot+"/ramdisk/default.prop"), "ro.debuggable"); v != "" {
		facts.Set(bag, DebugBuild, v == "1", prov)
	}
}

// propValue is the value of key in a key=value property file, or "".
func propValue(b []byte, key string) string {
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == key {
			return v
		}
	}
	return ""
}
