package vendor

import (
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/bootelf"
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

	// The modem's boot image carries its own device-tree table; the first
	// variant's stands for all (the others differ in carrier config only).
	for _, name := range slices.Sorted(maps.Keys(pkg.Names)) {
		if strings.HasPrefix(name, "modem/") && strings.HasSuffix(name, "/mdm9607-boot.img") {
			if v := DescribeQCDT(pkg.Read(name + "/dt")); v != "" {
				facts.Set(bag, ModemDeviceTree, v, facts.Provenance{Source: name + "/dt", Authority: facts.Attested})
			}
			break
		}
	}

	// The modem firmware ELF of each variant, joined from its split segments in
	// NON-HLOS; variants that carry the same build are listed together.
	fw := map[string][]string{}
	for name := range pkg.Names {
		dir, ok := strings.CutSuffix(name, "/NON-HLOS.ubi")
		if !ok || !strings.HasPrefix(dir, "modem/") {
			continue
		}
		if v := describeModemELF(pkg.Read(name + "/modem/image/modem.mdt.joined")); v != "" {
			fw[v] = append(fw[v], strings.TrimPrefix(dir, "modem/"))
		}
	}
	var fwList []string
	for v, variants := range fw {
		sort.Strings(variants)
		fwList = append(fwList, v+" ("+strings.Join(variants, ", ")+")")
	}
	sort.Strings(fwList)
	if len(fwList) > 0 {
		facts.Set(bag, ModemFirmware, strings.Join(fwList, "; "), facts.Provenance{Source: "modem/*/NON-HLOS.ubi modem.mdt", Authority: facts.Attested})
	}

	const boot = "enc_system/enc_boot.img/boot.img"
	if !pkg.Names["enc_system/enc_boot.img"] {
		return
	}
	hdr := pkg.Read(boot)
	if !pkg.Decrypts() || hdr == nil {
		return
	}
	if v := DescribeDeviceTree(pkg.Read("enc_system/enc_device_tree.dtb/device_tree.dtb")); v != "" {
		facts.Set(bag, DeviceTree, v, facts.Provenance{Source: "enc_device_tree.dtb", Authority: facts.Attested})
	}
	prov := facts.Provenance{Source: "enc_boot.img", Authority: facts.Attested}
	if im, err := bootimg.Parse(hdr); err == nil && im.Cmdline != "" {
		facts.Set(bag, KernelCmdline, im.Cmdline, prov)
	}
	if v := SummarizeKernelConfig(pkg.Read(boot + "/kernel/config")); v != "" {
		facts.Set(bag, KernelConfig, v, prov)
	}
	if v := ZImageKernelVersion(pkg.Read(boot + "/kernel")); v != "" {
		facts.Set(bag, KernelVersion, v, prov)
	}
	defaultProp := pkg.Read(boot + "/ramdisk/default.prop")
	if v := propValue(defaultProp, "ro.debuggable"); v != "" {
		facts.Set(bag, DebugBuild, v == "1", prov)
	}
	var fstabs [][]byte
	for _, name := range pkg.List(boot + "/ramdisk") {
		if strings.HasPrefix(name, "fstab.") {
			fstabs = append(fstabs, pkg.Read(boot+"/ramdisk/"+name))
		}
	}
	cmdline, _ := facts.Get(bag, KernelCmdline)
	verity := strings.Contains(string(pkg.Read(boot+"/kernel/config")), "CONFIG_DM_VERITY=y")
	if v := SummarizePosture(fstabs, defaultProp, cmdline, verity); v != "" {
		facts.Set(bag, BootPosture, v, prov)
	}

	// lk.rom embedding an OP-TEE TA's UUID means LK's own boot-time
	// verification calls into that TA directly — a hardware-backed check
	// distinct from (and not defeated by) otaagentd's plain-OpenSSL,
	// replaceable-file install-time one.
	if lk := pkg.Read("enc_system/enc_lk.rom/lk.rom"); lk != nil {
		if tas := ReferencedTAs(lk); len(tas) > 0 {
			facts.Set(bag, TAReferences, strings.Join(tas, "; "), facts.Provenance{Source: "enc_lk.rom", Authority: facts.Attested})
		}
	}
}

// describeModemELF reads a firmware ELF's core, variant, build date and signing
// root as one line, or "" when it is not a readable ELF.
func describeModemELF(b []byte) string {
	if b == nil {
		return ""
	}
	info, err := bootelf.Analyze(b)
	if err != nil {
		return ""
	}
	parts := []string{info.Arch}
	if info.Variant != "" {
		parts = append(parts, info.Variant)
	}
	if info.Provenance.BuildDate != "" {
		parts = append(parts, "built "+info.Provenance.BuildDate)
	}
	if id := info.Identity; id != nil && (id.RootCN != "" || id.Root != "") {
		root := id.RootCN
		if root == "" {
			root = id.Root
		}
		parts = append(parts, "signed under "+root)
	}
	return strings.Join(parts, ", ")
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
