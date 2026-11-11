package vendor

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
)

// neusoft: Neusoft-IVI head-unit firmware (seen on the Alpine Halo9
// iLX-F509, Telechips TCC8034/"Dolphin+"), packaged by /usr/bin/updatemgr --
// a zip (named e.g. A.23.D0.05.00.01.00.pak) of individually
// PKWARE-encrypted members sitting beside a plaintext collective_sign_info.dat,
// plus two small members once the zip is open: versions.dat (component
// versions) and rootfs.dat (how many rootfs.pakN parts there are, and each
// one's size, for reassembling the split rootfs image).
//
// The zip password is NOT a vendor-derived candidate here (unlike alpine.go's
// "FBDMI"): the one confirmed sample's password, "0123456789", is a plain
// ascending run of digits -- exactly what internal/carve's
// numericSequenceCandidates tries before any exhaustive search, so brute
// force (--bruteforce-zip-passwords) finds it in a header check's worth of
// time rather than needing it hardcoded.
//
// Each individual firmware payload (a7kernel.pak, rootfs.pak, ...) is then
// separately AES-128-CBC encrypted with a key hardcoded into updatemgr --
// publicly documented as recovered from a physical eMMC dump (NCC Group,
// "Revving Up: The Journey to Pwn2Own Automotive 2024"), but the key bytes
// themselves were redacted in that disclosure. Not reproducible from a
// firmware package alone, so there is no path here to open those payloads --
// recognition and the two plaintext manifests only.
// NeusoftVersion is this file's own cache.VersionFuncs entry
// (cmd_recon_registry.go): raise it whenever ParseNeusoftVersions or
// ParseNeusoftRootfsManifest changes what they'd report for bytes already
// seen.
const NeusoftVersion = 2

// NeusoftPlatformLabel names what versions.dat+rootfs.dat's own distinctive
// shape (ALL_VERSION=/BOOT_VERSION=.../"total count ="/"part size =") has so
// far only been confirmed to come from: the Alpine Halo9 iLX-F509, on a
// Neusoft-IVI-supplied software platform and a Telechips SoC. A different
// product sharing updatemgr's exact package format would report the same
// label even though it isn't this one -- the shape names the *format*, not
// a specific device, the same way an ELF header doesn't name which program
// built it.
const NeusoftPlatformLabel = "Neusoft-IVI (updatemgr), Telechips SoC -- confirmed so far only on the Alpine Halo9 iLX-F509"

type neusoft struct{}

func init() { Register(neusoft{}) }

func (neusoft) ID() string                 { return "neusoft" }
func (neusoft) Platform() string           { return PlatformTelechips }
func (neusoft) OEMIDs() []string           { return nil }
func (neusoft) CanIngest(path string) bool { return false }

func (neusoft) IngestDonor(string) (*blankflash.Donor, error) { return nil, ErrUnsupported }
func (neusoft) HarvestStock(TargetSource) (*blankflash.Target, error) {
	return nil, ErrUnsupported
}
func (neusoft) Assemble(*blankflash.Donor, *blankflash.Target, AssembleOptions) (*blankflash.ForgeResult, error) {
	return nil, ErrUnsupported
}

// NeusoftVersions is versions.dat's own account of the release: one
// "KEY = VALUE" line per component. Fields are the ones seen so far;
// unrecognised keys are ignored.
type NeusoftVersions struct {
	AllVersion    string
	BootVersion   string
	SocVersion    string
	McuVersion    string
	CameraVersion string
}

var neusoftVersionsLine = regexp.MustCompile(`(?m)^\s*([A-Za-z_]+)\s*=\s*(.*?)\s*$`)

// ParseNeusoftVersions reads versions.dat.
func ParseNeusoftVersions(data []byte) NeusoftVersions {
	var v NeusoftVersions
	for _, m := range neusoftVersionsLine.FindAllSubmatch(data, -1) {
		val := string(m[2])
		switch strings.ToUpper(string(m[1])) {
		case "ALL_VERSION":
			v.AllVersion = val
		case "BOOT_VERSION":
			v.BootVersion = val
		case "SOC_VERSION":
			v.SocVersion = val
		case "MCU_VERSION":
			v.McuVersion = val
		case "CAMERA_VERSION":
			v.CameraVersion = val
		}
	}
	return v
}

// NeusoftRootfsManifest is rootfs.dat's own account of how rootfs.pak1,
// rootfs.pak2, ... reassemble into one rootfs image: PartSizes[i] is
// rootfs.pak(i+1)'s size: the part count line names, is not just inferred
// from how many rootfs.pakN members happen to be present.
type NeusoftRootfsManifest struct {
	PartSizes []int64
}

var (
	neusoftTotalCountLine = regexp.MustCompile(`(?m)^\s*total\s+count\s*=\s*(\d+)\s*$`)
	neusoftPartSizeLine   = regexp.MustCompile(`(?m)^\s*part\s+size\s*=\s*(\d+)\s*$`)
)

// ParseNeusoftRootfsManifest reads rootfs.dat. ok is false if it does not
// look like this format at all (no "total count" line); a part count that
// does not match the number of "part size" lines found is not an error --
// PartSizes is just whatever was actually listed.
func ParseNeusoftRootfsManifest(data []byte) (m NeusoftRootfsManifest, ok bool) {
	if !neusoftTotalCountLine.Match(data) {
		return m, false
	}
	for _, line := range neusoftPartSizeLine.FindAllSubmatch(data, -1) {
		n, err := strconv.ParseInt(string(line[1]), 10, 64)
		if err != nil {
			continue
		}
		m.PartSizes = append(m.PartSizes, n)
	}
	return m, true
}
