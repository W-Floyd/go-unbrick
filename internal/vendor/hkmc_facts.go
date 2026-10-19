package vendor

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/fdt"
	"github.com/W-Floyd/go-unbrick/internal/qcdt"
)

// Facts read from a Hyundai/Kia head-unit package's plain-text members and its
// decrypted boot image.
var (
	KernelVersion = facts.Key[string]("kernel_version")
	KernelCmdline = facts.Key[string]("kernel_cmdline")
	// KernelArch is the kernel image's own word size, from its container
	// format (zImage vs Image) — NOT the SoC's capability. A real 64-bit
	// core (e.g. Cortex-A53) can ship running a 32-bit kernel regardless of
	// what the device tree's "compatible" strings claim the core is: the
	// DT names the silicon, not what firmware chose to boot it as. Report
	// this fact, not DeviceTree's compatible string, when the question is
	// what the system actually runs.
	KernelArch = facts.Key[string]("kernel_arch")
	// DebugBuild is ro.debuggable from the ramdisk's default.prop.
	DebugBuild  = facts.Key[bool]("debug_build")
	GPSFirmware = facts.Key[string]("gps_firmware")
	// DeviceTree and ModemDeviceTree name the board each device tree is for:
	// its root model and compatible strings.
	DeviceTree      = facts.Key[string]("device_tree")
	ModemDeviceTree = facts.Key[string]("modem_device_tree")
	// ModemFirmware is the joined modem ELF's identity: core, build, signing root.
	ModemFirmware = facts.Key[string]("modem_firmware")
	// KernelConfig summarises the .config the kernel embeds.
	KernelConfig = facts.Key[string]("kernel_config")
)

// BootPosture is what the boot ramdisk says about how locked down the device
// is: system mount and verity, data encryption, adb and SELinux.
var BootPosture = facts.Key[string]("boot_posture")

// TAReferences is which OP-TEE Trusted Applications a binary embeds the UUID
// of — found in lk.rom itself this names which TA its own boot-time
// verification calls into, as opposed to otaagentd's unrelated plain-OpenSSL
// install-time check (res.dat key, no TEE at all). The same UUID also
// appearing in a userspace client library is how each TA below was identified
// in the first place (vendor/lib/libtsm_secureflash.so, libtsm_securestorage.so,
// libtsm_ask_server.so, libcaHSM.so, against the system.ext4 files under
// vendor/lib/optee_armtz/*.ta).
var TAReferences = facts.Key[string]("ta_references")

// knownTAs maps an OP-TEE TA UUID to the capability it backs, from TAs
// identified in this platform's own system.ext4.
var knownTAs = map[string]string{
	"981fbe6c-bd38-467c-92c6-66b66bbff412": "secure-flash (libtsm_secureflash.so)",
	"14be5fc2-2dca-4f4b-8575-f50cc82716be": "secure-storage (libtsm_securestorage.so, tsmd)",
	"58388e33-8d64-4086-b929-feb722415ae3": "ask-server (libtsm_ask_server.so)",
	"9aec3623-b887-4491-a453-3de7735a3e85": "HSM/crypto — sign/verify, cipher, MAC, KDF, RNG (libcaHSM.so)",
}

// taUUIDBytes is u as a TEEC_UUID: the first three fields byte-swapped to
// little-endian (as ARM TEE client code stores them), the last two as-is.
func taUUIDBytes(u string) []byte {
	p := strings.Split(u, "-")
	if len(p) != 5 {
		return nil
	}
	rev := func(h string) []byte {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil
		}
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return b
	}
	straight := func(h string) []byte {
		b, _ := hex.DecodeString(h)
		return b
	}
	var out []byte
	for i, part := range []func(string) []byte{rev, rev, rev, straight, straight} {
		b := part(p[i])
		if b == nil {
			return nil
		}
		out = append(out, b...)
	}
	return out
}

// ReferencedTAs returns the known TAs whose UUID appears (as a TEEC_UUID
// struct) anywhere in data, each as "label (uuid)", sorted.
func ReferencedTAs(data []byte) []string {
	var out []string
	for u, label := range knownTAs {
		if b := taUUIDBytes(u); b != nil && bytes.Contains(data, b) {
			out = append(out, fmt.Sprintf("%s (%s)", label, u))
		}
	}
	sort.Strings(out)
	return out
}

// fstabEntry is one line of an Android fstab.
type fstabEntry struct{ Dev, Mount, Type, MntFlags, FsMgrFlags string }

func parseFstab(b []byte) []fstabEntry {
	var out []fstabEntry
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || strings.HasPrefix(f[0], "#") || !strings.HasPrefix(f[0], "/") {
			continue
		}
		out = append(out, fstabEntry{f[0], f[1], f[2], f[3], f[4]})
	}
	return out
}

// SummarizePosture reads the ramdisk's fstabs, default.prop and the kernel
// command line. kernelVerity is whether the kernel was built with dm-verity.
func SummarizePosture(fstabs [][]byte, defaultProp []byte, cmdline string, kernelVerity bool) string {
	var parts []string
	var sys *fstabEntry
	var enc []string
	seen := map[string]bool{}
	for _, b := range fstabs {
		es := parseFstab(b)
		for i := range es {
			e := es[i]
			if e.Mount == "/system" && sys == nil {
				sys = &es[i]
			}
			if e.Mount != "/data" && e.Mount != "/securedata" {
				continue
			}
			for _, flag := range strings.Split(e.FsMgrFlags, ",") {
				if k, _, ok := strings.Cut(flag, "="); ok && (k == "encryptable" || k == "forceencrypt") {
					if s := e.Mount + " " + k; !seen[s] {
						seen[s] = true
						enc = append(enc, s)
					}
				}
			}
		}
	}
	if sys != nil {
		verity := "no verify flag"
		if strings.Contains(sys.FsMgrFlags, "verify") {
			verity = "verity enforced"
		} else if kernelVerity {
			verity += " (dm-verity is built into the kernel)"
		}
		mode := "rw"
		if strings.HasPrefix(sys.MntFlags, "ro") {
			mode = "ro"
		}
		parts = append(parts, fmt.Sprintf("/system %s, %s", mode, verity))
	}
	parts = append(parts, enc...)
	props := map[string]string{}
	for _, line := range strings.Split(string(defaultProp), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	if props["ro.adb.secure"] == "1" {
		parts = append(parts, "adb needs authorization")
	}
	switch {
	case props["ro.debuggable"] == "1" && props["ro.secure"] == "1":
		parts = append(parts, "debuggable (adb root permitted)")
	case props["ro.secure"] == "0":
		parts = append(parts, "ro.secure=0 (adbd runs as root)")
	}
	if v := props["persist.sys.usb.config"]; v != "" {
		parts = append(parts, "usb "+v)
	}
	if strings.Contains(cmdline, "androidboot.selinux=disabled") {
		parts = append(parts, "SELinux disabled")
	}
	return strings.Join(parts, "; ")
}

// archCapability matches the generic ARCH_ options a kernel sets for every SoC.
var archCapability = regexp.MustCompile(`^ARCH_(SUPPORTS|HAS|USE|WANT|HAVE|MIGHT|REQUIRE|HIBERNATION|SUSPEND|PHYS|DMA|BINFMT|MULTI|SPARSEMEM|FLATMEM)_|_MAP_`)

// SummarizeKernelConfig names the SoC family and the hardening options a
// kernel .config sets, with the option count.
func SummarizeKernelConfig(cfg []byte) string {
	set := map[string]bool{}
	var arch string
	n := 0
	for _, line := range strings.Split(string(cfg), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(k, "CONFIG_") || v == "n" {
			continue
		}
		n++
		k = strings.TrimPrefix(k, "CONFIG_")
		set[k] = true
		// The SoC option is the most specific ARCH_ one that is not an
		// architecture capability (ARCH_TCC803X over ARCH_TCC, not ARCH_HAS_…).
		if strings.HasPrefix(k, "ARCH_") && v == "y" && !archCapability.MatchString(k) && len(k) > len(arch) {
			arch = k
		}
	}
	if n == 0 {
		return ""
	}
	parts := []string{fmt.Sprintf("%d options", n)}
	if arch != "" {
		parts = append(parts, arch)
	}
	for _, o := range []struct{ key, label string }{
		{"DM_VERITY", "dm-verity"}, {"SECURITY_SELINUX", "SELinux"}, {"MODULE_SIG", "module signing"},
		{"STRICT_DEVMEM", "strict /dev/mem"}, {"IKCONFIG_PROC", "/proc/config.gz"},
	} {
		if set[o.key] {
			parts = append(parts, o.label)
		}
	}
	return strings.Join(parts, ", ")
}

// DescribeDeviceTree reads a DTB's root as "model (compatible, …)".
func DescribeDeviceTree(dtb []byte) string {
	root, err := fdt.Parse(dtb)
	if err != nil {
		return ""
	}
	model, _ := root.Str("model")
	compat := strings.Join(root.Strs("compatible"), ", ")
	switch {
	case model != "" && compat != "":
		return model + " (" + compat + ")"
	case model != "":
		return model
	}
	return compat
}

// DescribeQCDT summarises a Qualcomm DT table: the board family its trees
// share (the SoC-level compatible string), and how many trees it carries.
func DescribeQCDT(table []byte) string {
	es, err := qcdt.Parse(table)
	if err != nil || len(es) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var socs []string
	for _, e := range es {
		root, err := fdt.Parse(e.DTB)
		if err != nil {
			continue
		}
		c := root.Strs("compatible")
		if len(c) == 0 {
			continue
		}
		soc := c[min(1, len(c)-1)]
		if !seen[soc] {
			seen[soc] = true
			socs = append(socs, soc)
		}
	}
	sort.Strings(socs)
	// No model: each tree names its own reference board (CDP, MTP, …), none of
	// which is the device's.
	return fmt.Sprintf("%s, %d trees", strings.Join(socs, ", "), len(es))
}

var swVersionRe = regexp.MustCompile(`(?m)^SWVERSION\s*-\s*(\S+)`)

// ParseUpdateInfo returns the SWVERSION an update.info declares.
func ParseUpdateInfo(b []byte) string {
	if m := swVersionRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// UpdateInfoEntry is one file update.info lists: the directory the package
// member lives under (as the package itself names it, e.g. "modem/bell" —
// not update.info's own un-prefixed names for the enc_* members, see below),
// the file's name, and its HyundaiSHA224 hash.
type UpdateInfoEntry struct {
	Dir, Name, Hash string
}

var updateInfoFileLine = regexp.MustCompile(`^:\s*(\S+):([0-9a-f]{56})$`)

// ParseUpdateInfoEntries reads update.info's own "./dir" then ": name:hash"
// sections. Entries under "./system" and "./micom/..." name the decrypted
// files (e.g. "lk.rom"), not the package's actual "enc_system/enc_lk.rom" —
// a caller matching these against real package members needs its own
// enc_-prefix mapping, or to accept that those specific entries can't be
// found without first decrypting.
func ParseUpdateInfoEntries(b []byte) []UpdateInfoEntry {
	var entries []UpdateInfoEntry
	dir := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "./"):
			dir = strings.TrimPrefix(line, "./")
		case updateInfoFileLine.MatchString(line):
			m := updateInfoFileLine.FindStringSubmatch(line)
			entries = append(entries, UpdateInfoEntry{Dir: dir, Name: m[1], Hash: m[2]})
		}
	}
	return entries
}

// ParseModemVersion reads a modem_version.txt ("boot:01J_BBOOT, modem:01T_WVZW,
// gw:37") as "01T_WVZW [boot 01J_BBOOT, gw 37]": the modem build first, the
// rest of the sheet after it.
func ParseModemVersion(b []byte) string {
	var modem string
	var rest []string
	for _, f := range strings.Split(string(b), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(f), ":")
		switch {
		case !ok:
		case k == "modem":
			modem = v
		default:
			rest = append(rest, k+" "+v)
		}
	}
	if modem == "" {
		return ""
	}
	if len(rest) == 0 {
		return modem
	}
	return modem + " [" + strings.Join(rest, ", ") + "]"
}

// ZImageKernelVersion returns the "Linux version" banner of an ARM zImage's
// kernel, or "".
func ZImageKernelVersion(z []byte) string {
	plain, err := bootimg.ZImagePayload(z)
	if err != nil {
		return ""
	}
	j := bytes.Index(plain, []byte("Linux version "))
	if j < 0 {
		return ""
	}
	banner := plain[j:]
	if k := bytes.IndexAny(banner, "\n\x00"); k >= 0 {
		banner = banner[:k]
	}
	return string(banner)
}

// KernelImageArch reports the word size of a kernel image from its own
// container format, not from the device tree's SoC "compatible" strings
// (see KernelArch's doc comment for why those can disagree).
func KernelImageArch(z []byte) string {
	switch {
	case bootimg.IsZImage(z):
		return "32-bit ARM (zImage)"
	case bootimg.IsAArch64Image(z):
		return "64-bit AArch64 (Image)"
	}
	return ""
}

// abiWordSize maps a ro.product.cpu.abi value to "32-bit"/"64-bit", or "" if
// unrecognized.
func abiWordSize(abi string) string {
	switch {
	case strings.HasPrefix(abi, "arm64"), abi == "x86_64", strings.HasPrefix(abi, "mips64"):
		return "64-bit"
	case strings.HasPrefix(abi, "armeabi"), abi == "x86", strings.HasPrefix(abi, "mips"):
		return "32-bit"
	}
	return ""
}

// SummarizeArch combines the kernel image's own word size with independent
// userspace evidence (ro.product.cpu.abi, /lib64's presence) into one display
// string, flagging any of the three that disagrees with the kernel - which
// would mean the kernel container format alone isn't the whole story, not
// that one of the checks is buggy. abi and sawLib64Check (whether the
// system image was even readable, not what it held) are empty/false when
// that evidence could not be gathered, in which case it's omitted rather
// than reported as agreeing or disagreeing.
func SummarizeArch(kernelArch, abi string, sawLib64Check, hasLib64 bool) string {
	kernelBits := "32-bit"
	if strings.HasPrefix(kernelArch, "64-bit") {
		kernelBits = "64-bit"
	}
	parts := []string{kernelArch}
	if abi != "" {
		note := "cpu.abi=" + abi
		if b := abiWordSize(abi); b != "" && b != kernelBits {
			note += fmt.Sprintf(" — disagrees (%s)", b)
		}
		parts = append(parts, note)
	}
	if sawLib64Check {
		note, bits := "no lib64", "32-bit"
		if hasLib64 {
			note, bits = "has lib64", "64-bit"
		}
		if bits != kernelBits {
			note += " — disagrees"
		}
		parts = append(parts, note)
	}
	return strings.Join(parts, "; ")
}
