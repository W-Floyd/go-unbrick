package vendor

import (
	"bytes"
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
