package transport

// What every shell-reachable route shares. A booted device answers the same
// questions whether the shell is reached over ssh (postmarketOS, Mobian) or
// over adb (Android): /proc/cmdline carries what the bootloader passed,
// /sys/devices/soc0 carries what the silicon says it is, /dev/block/by-name
// carries the whole partition table. Only the identity of the userspace itself
// differs — os-release and a deviceinfo file on one side, getprop on the other
// — so that part is each transport's own and the rest is collected, parsed and
// derived here, once.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CommonShellScript collects what any booted device can answer. It is one
// script rather than a command per question because every question is a procfs
// or sysfs read worth microseconds on the device and a whole round trip from
// the host: batched they cost one, and a recon that is one round trip is one
// that survives a flaky link.
//
// It stays POSIX: the shell is busybox ash on postmarketOS and toybox/mksh on
// Android, so no arrays, no [[, no process substitution. Every read is guarded
// — a device with no device-tree, no soc0 or no by-name directory still yields
// everything else, and a section that reads as empty is a gap the report shows
// rather than an error that loses the rest.
//
// Two rules that are not style, learned from a device that hung forever:
//
//   - Never redirect an unreadable file into a filter (`tr -d '\0' < $f`). When
//     the redirect fails the shell leaves the filter reading the *session's*
//     stdin, which over ssh or adb never closes — so the collection stops dead
//     at the first sysfs file the login cannot read. `cat $f 2>/dev/null
//     </dev/null | tr …` cannot do that, and is what every read here uses.
//   - Ask sysfs for the attributes we actually read, not for whatever the
//     directory holds. /sys/devices/soc0 carries vendor entries that query a
//     subsystem when read, and the neutral facts need fourteen names.
const CommonShellScript = `
u() { printf '\n===unbrick:%s===\n' "$1"; }
u whoami
printf 'uid=%s\nuser=%s\n' "$(id -u 2>/dev/null)" "$(id -un 2>/dev/null)"
u hostname
cat /etc/hostname 2>/dev/null || hostname 2>/dev/null || getprop ro.boot.hostname 2>/dev/null
u elevate
for e in doas sudo su; do command -v "$e" >/dev/null 2>&1 && echo "$e"; done
u elevate-ok
for e in doas sudo; do
	if command -v "$e" >/dev/null 2>&1 && "$e" -n true >/dev/null 2>&1; then echo "$e"; fi
done
if command -v su >/dev/null 2>&1 && su -c id -u 2>/dev/null | grep -q '^0$'; then echo su; fi
u cmdline
cat /proc/cmdline 2>/dev/null
u cpuinfo
grep -iE '^(hardware|model|model name|revision|serial|cpu implementer|cpu part)[[:space:]]*:' /proc/cpuinfo 2>/dev/null | sort -u
u soc0
for f in machine family soc_id revision raw_id hw_platform chip_id platform_version \
	platform_subtype pcode foundry_id image_version image_variant image_crm_version; do
	v=$(cat "/sys/devices/soc0/$f" 2>/dev/null </dev/null | tr -d '\0')
	[ -n "$v" ] && printf '%s=%s\n' "$f" "$v"
done
u dt-model
cat /sys/firmware/devicetree/base/model 2>/dev/null </dev/null | tr -d '\0'
echo
u dt-compatible
cat /sys/firmware/devicetree/base/compatible 2>/dev/null </dev/null | tr '\0' '\n'
u partitions
for l in /dev/block/by-name/* /dev/disk/by-partlabel/*; do
	[ -e "$l" ] || continue
	d=$(readlink -f "$l" 2>/dev/null)
	b=${d##*/}
	s=$(cat "/sys/class/block/$b/size" 2>/dev/null)
	printf '%s\t%s\t%s\n' "${l##*/}" "$d" "${s:-0}"
done
u disks
for d in /sys/class/block/*; do
	if [ -e "$d/device" ]; then printf '%s\t%s\n' "${d##*/}" "$(cat "$d/size" 2>/dev/null)"; fi
done
u mounts
awk '$2=="/"{print $1"\t"$3}' /proc/mounts 2>/dev/null
u storserial
for p in /sys/bus/platform/devices/*.ufshc/string_descriptors/serial_number \
	/sys/devices/platform/soc/*ufs*/string_descriptors/serial_number; do
	[ -f "$p" ] || continue
	v=$(cat "$p" 2>/dev/null </dev/null | tr -d '\r\n\0 \t')
	[ -n "$v" ] && printf 'ufs\t%s\n' "$v" && break
done
u battery
for p in /sys/class/power_supply/*; do
	[ -d "$p" ] || continue
	printf '%s:' "${p##*/}"
	for k in type status capacity voltage_now health technology; do
		v=$(cat "$p/$k" 2>/dev/null)
		[ -n "$v" ] && printf ' %s=%s' "$k" "$v"
	done
	echo
done
`

// ShellRecon is what CommonShellScript brings back: a plain record of what the
// running system said, with the reading of it left to the fact providers.
type ShellRecon struct {
	User string
	// UID is the login's user id, or -1 when the device did not say. Not 0:
	// "unknown" must never read as "root", or a recon that collected nothing
	// would report itself able to read every partition.
	UID      int
	Hostname string

	// Elevate is a privilege helper installed on the device ("doas", "sudo",
	// "su"); ElevateOK one that actually elevates without a password, which is
	// the only kind a session with no tty can use. They are separate because
	// "sudo is installed but wants a password" is a different thing to tell the
	// operator than "there is no sudo".
	Elevate   string
	ElevateOK string

	// Cmdline is /proc/cmdline as key=value. On a phone that boots through the
	// stock Android chain this is where the bootloader's own androidboot.*
	// parameters survive into the running kernel: the slot it picked, the
	// serial, the verified-boot state. CmdlineRaw keeps the line, since
	// valueless parameters are meaningful too.
	Cmdline    map[string]string
	CmdlineRaw string

	CPUInfo map[string]string // the identity lines of /proc/cpuinfo, keys lowercased
	SoC0    map[string]string // /sys/devices/soc0: machine, family, soc_id, revision, …

	DTModel      string   // /proc/device-tree/model
	DTCompatible []string // /proc/device-tree/compatible, most specific first

	Partitions []Partition
	Disks      []Disk
	Storage    string            // "ufs" / "emmc", inferred from the block devices
	RootSource string            // device the running rootfs is mounted from (/proc/mounts)
	RootFS     string            // its filesystem type (ext4, tmpfs, overlay, …)
	StorSerial string            // internal storage (UFS) serial — a stable per-unit id
	Battery    map[string]string // power-supply readings, keyed supply:field

	// Sections is the collection output split by section, for a raw dump. The
	// parsers take what they understand; this keeps what they do not.
	Sections map[string]string
}

// ParseShell reads collection output into the common fields. A transport calls
// it and then fills in whatever its own sections said.
func ParseShell(out string) *ShellRecon {
	secs := SplitSections(out)
	r := &ShellRecon{
		UID:      -1,
		Cmdline:  map[string]string{},
		CPUInfo:  map[string]string{},
		SoC0:     map[string]string{},
		Battery:  map[string]string{},
		Sections: secs,
	}
	for k, v := range ParseKV(secs["whoami"], "=") {
		switch k {
		case "uid":
			if n, err := strconv.Atoi(v); err == nil {
				r.UID = n
			}
		case "user":
			r.User = v
		}
	}
	r.Hostname = FirstLine(secs["hostname"])
	// More than one helper may be installed; the first listed wins, which is
	// the order the script asks in (doas, then sudo, then su).
	if lines := NonEmptyLines(secs["elevate"]); len(lines) > 0 {
		r.Elevate = strings.TrimSpace(lines[0])
	}
	if lines := NonEmptyLines(secs["elevate-ok"]); len(lines) > 0 {
		r.ElevateOK = strings.TrimSpace(lines[0])
	}
	r.CmdlineRaw = FirstLine(secs["cmdline"])
	r.Cmdline = ParseCmdline(r.CmdlineRaw)
	r.CPUInfo = ParseColonFields(secs["cpuinfo"])
	r.SoC0 = ParseKV(secs["soc0"], "=")
	r.DTModel = FirstLine(secs["dt-model"])
	r.DTCompatible = NonEmptyLines(secs["dt-compatible"])
	r.Partitions = ParsePartitionLines(secs["partitions"])
	r.Disks = parseDisks(secs["disks"])
	r.Storage = inferStorage(r.Disks)
	if f := strings.Fields(FirstLine(secs["mounts"])); len(f) == 2 {
		r.RootSource, r.RootFS = f[0], f[1]
	}
	if f := strings.Fields(FirstLine(secs["storserial"])); len(f) == 2 {
		r.StorSerial = f[1] // "ufs\t<serial>"
	}
	r.Battery = parseBattery(secs["battery"])
	return r
}

// Describe names the login for a report: the user and uid, or that the device
// did not say.
func (r *ShellRecon) DescribeLogin() string {
	switch {
	case r.UID < 0:
		return "login unknown"
	case r.User == "":
		return fmt.Sprintf("uid %d", r.UID)
	}
	return fmt.Sprintf("%s (uid %d)", r.User, r.UID)
}

// Slot is the A/B slot the bootloader booted, from the suffix it passed on the
// kernel command line. Empty on a device with no slots, or one whose cmdline
// the installed system replaced wholesale.
func (r *ShellRecon) Slot() string {
	for _, k := range []string{"androidboot.slot_suffix", "androidboot.slot"} {
		if v, ok := r.Cmdline[k]; ok && v != "" {
			return strings.TrimPrefix(strings.ToLower(v), "_")
		}
	}
	return ""
}

// Serial is the device serial the bootloader passed through, if any.
func (r *ShellRecon) Serial() string { return r.Cmdline["androidboot.serialno"] }

// LockState is what the boot chain said about itself on the command line.
// verifiedbootstate is the AVB colour (green: locked and verified, orange:
// unlocked, yellow: locked with a custom key); androidboot.flash.locked is the
// bootloader's own flag. Empty when the cmdline carries neither.
func (r *ShellRecon) LockState() string {
	switch strings.ToLower(r.Cmdline["androidboot.verifiedbootstate"]) {
	case "orange":
		return "unlocked"
	case "green", "yellow", "red":
		return "locked"
	}
	switch r.Cmdline["androidboot.flash.locked"] {
	case "0":
		return "unlocked"
	case "1":
		return "locked"
	}
	return ""
}

// ABDevice reports whether this is an A/B device, judged by the partition table
// rather than by the cmdline: a slot suffix can be absent from a replaced
// cmdline, but a table with xbl_a and xbl_b is not ambiguous.
// BootMedium classifies where the running system booted from, which decides
// whether the device's original OS is still intact on internal storage:
//
//	"ram"       — rootfs is a RAM/initramfs filesystem (tmpfs/overlay/…);
//	              nothing on internal storage was touched.
//	"removable" — rootfs is on an SD card or USB (mmcblk*/sd* that is not the
//	              internal eMMC/UFS); the internal OS is untouched.
//	"internal"  — rootfs is on the internal storage; the OS it replaced (if any)
//	              is gone.
//	""          — unknown (no mount info).
//
// For "ram"/"removable" the on-disk stock partitions (system/product/vendor,
// build.prop) can still be read, so their firmware facts are recoverable even
// though a different OS booted.
func (r *ShellRecon) BootMedium() string {
	switch r.RootFS {
	case "":
		if r.RootSource == "" {
			return ""
		}
	case "tmpfs", "ramfs", "rootfs", "overlay", "squashfs", "initramfs":
		return "ram"
	}
	base := strings.TrimPrefix(r.RootSource, "/dev/")
	base = strings.SplitN(base, "/", 2)[0] // /dev/mmcblk1p2 → mmcblk1p2
	switch {
	case strings.HasPrefix(base, "mmcblk"):
		// An eMMC device is internal; an SD card is removable. On a UFS phone
		// any mmcblk is the SD card, and mmcblk1 is conventionally the SD slot.
		if r.Storage == "ufs" || strings.HasPrefix(base, "mmcblk1") {
			return "removable"
		}
		return "internal"
	case strings.HasPrefix(base, "sd"):
		// A SCSI/USB name: the internal UFS is sd* too, so it is internal unless
		// it is the SD/USB the other way round — indistinguishable by name
		// alone, so treat internal UFS as internal.
		return "internal"
	}
	return ""
}

func (r *ShellRecon) ABDevice() bool {
	return r.Slot() != "" || ABTable(r.Partitions)
}

// ABTable reports whether a partition table is laid out for A/B: some
// partition exists in both slots.
func ABTable(parts []Partition) bool {
	bases := map[string]int{}
	for _, p := range parts {
		if p.Slot() != "" {
			bases[p.Base()]++
		}
	}
	for _, n := range bases {
		if n >= 2 {
			return true
		}
	}
	return false
}

// SoCTokens are the part numbers the running system has for its silicon, most
// authoritative first: the SoC's own sysfs machine name, its device-tree
// platform, and the string the kernel prints in /proc/cpuinfo.
func (r *ShellRecon) SoCTokens() []string {
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		// Only a part number, which is what the catalog can resolve. A mainline
		// kernel puts the board model in soc0/machine ("Motorola Moto G Play
		// (2024) (Tianma ICNL9916C)"), and taking that as a SoC name both reads
		// as nonsense and disagrees with every other source.
		if !LooksLikePartNumber(s) {
			return
		}
		for _, have := range out {
			if strings.EqualFold(have, s) {
				return
			}
		}
		out = append(out, s)
	}
	add(r.SoC0["machine"])
	// The *first* SoC-vendor compatible entry only. A device tree lists the
	// fallbacks it is also compatible with (fogona names sm6225 then sm6115),
	// and those are what a driver may bind to, not further claims about which
	// part this is — reading them as claims manufactures a disagreement.
	for _, comp := range r.DTCompatible {
		if v, soc, ok := strings.Cut(comp, ","); ok && IsSoCVendor(v) {
			add(soc)
			break
		}
	}
	// "Qualcomm Technologies, Inc SM6225" — the part number is the last field.
	if hw := r.CPUInfo["hardware"]; hw != "" {
		if f := strings.Fields(hw); len(f) > 0 {
			add(f[len(f)-1])
		}
	}
	return out
}

// DTCodename is the device codename a mainline device tree names itself by: its
// most specific compatible entry is "<oem>,<codename>".
func (r *ShellRecon) DTCodename() (codename, vendor string) {
	for _, comp := range r.DTCompatible {
		if v, name, ok := strings.Cut(comp, ","); ok && !IsSoCVendor(v) && name != "" {
			return name, strings.ToLower(v)
		}
	}
	return "", ""
}

// Partition returns the named entry of the live table.
func (r *ShellRecon) Partition(name string) (Partition, bool) {
	for _, p := range r.Partitions {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return Partition{}, false
}

// BatteryPercent is the main battery's charge, or -1 if no supply reported one.
func (r *ShellRecon) BatteryPercent() int {
	for _, key := range []string{"battery:capacity", "bms:capacity"} {
		if v, ok := r.Battery[key]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return -1
}

// IsSoCVendor reports whether a device-tree vendor prefix names the SoC vendor
// rather than the phone's OEM — the distinction a codename derivation needs,
// since "qcom,sm6225" is a platform and "motorola,fogona" is a device.
func IsSoCVendor(v string) bool {
	switch strings.ToLower(v) {
	case "qcom", "arm", "linux", "mediatek", "mrvl", "samsung", "exynos", "brcm", "rockchip", "allwinner":
		// samsung is both an OEM and a SoC vendor; its device trees name Exynos
		// SoCs this way, and a Samsung phone's own entry is "samsung,<codename>"
		// — indistinguishable here, so the userspace's own claim is what
		// resolves it.
		return true
	}
	return false
}

// LooksLikePartNumber reports whether a token could be a SoC part number: one
// word, carrying a digit, short. It is a filter on nonsense, not a validator —
// an unknown part still has to get through.
func LooksLikePartNumber(s string) bool {
	if s == "" || len(s) > 20 || strings.ContainsAny(s, " \t()/,") {
		return false
	}
	return strings.ContainsFunc(s, func(r rune) bool { return r >= '0' && r <= '9' })
}

// SplitSections cuts collection output at the section markers.
func SplitSections(out string) map[string]string {
	secs := map[string]string{}
	name := ""
	var body []string
	flush := func() {
		if name != "" {
			secs[name] = strings.Trim(strings.Join(body, "\n"), "\n")
		}
		body = body[:0]
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "===unbrick:") && strings.HasSuffix(t, "===") {
			flush()
			name = strings.TrimSuffix(strings.TrimPrefix(t, "===unbrick:"), "===")
			continue
		}
		if name != "" {
			body = append(body, line)
		}
	}
	flush()
	return secs
}

// ParseCmdline reads /proc/cmdline. Valueless parameters map to "", so a caller
// can test for presence.
func ParseCmdline(s string) map[string]string {
	out := map[string]string{}
	for _, tok := range strings.Fields(s) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			out[tok] = ""
			continue
		}
		out[k] = Unquote(v)
	}
	return out
}

// ParseColonFields reads "Key : value" lines (/proc/cpuinfo, getprop -less
// output), keys lowercased.
func ParseColonFields(s string) map[string]string {
	out := map[string]string{}
	for _, line := range NonEmptyLines(s) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

// ParseKV reads "key<sep>value" lines.
func ParseKV(s, sep string) map[string]string {
	out := map[string]string{}
	for _, line := range NonEmptyLines(s) {
		k, v, ok := strings.Cut(line, sep)
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// ParsePartitionLines reads the "name<TAB>node<TAB>sectors" listing. by-name and
// by-partlabel describe the same table on a device that has both, so the first
// spelling of a name wins and the duplicate is dropped.
func ParsePartitionLines(s string) []Partition {
	seen := map[string]bool{}
	var out []Partition
	for _, line := range NonEmptyLines(s) {
		f := strings.Split(line, "\t")
		if len(f) < 3 || f[0] == "" || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		// sysfs sizes are always 512-byte sectors, whatever the device's own
		// block size is.
		sectors, _ := strconv.ParseUint(strings.TrimSpace(f[2]), 10, 64)
		out = append(out, Partition{Name: f[0], Handle: f[1], SizeBytes: sectors * 512})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parseDisks(s string) []Disk {
	var out []Disk
	for _, line := range NonEmptyLines(s) {
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		sectors, _ := strconv.ParseUint(strings.TrimSpace(f[1]), 10, 64)
		out = append(out, Disk{Name: f[0], SizeBytes: sectors * 512})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// inferStorage names the internal storage from the block devices present. A
// phone's SCSI disks are its UFS LUNs; mmcblk0 is eMMC (a higher-numbered
// mmcblk is the SD card slot, not the internal storage). It is an inference,
// not a report — the bootloader's own storage-type answer outranks it.
func inferStorage(disks []Disk) string {
	for _, d := range disks {
		if strings.HasPrefix(d.Name, "sd") {
			return "ufs"
		}
	}
	for _, d := range disks {
		if d.Name == "mmcblk0" {
			return "emmc"
		}
	}
	return ""
}

// parseBattery reads the power-supply section into "supply:field" keys.
func parseBattery(s string) map[string]string {
	out := map[string]string{}
	for _, line := range NonEmptyLines(s) {
		supply, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		for _, kv := range strings.Fields(rest) {
			if k, v, ok := strings.Cut(kv, "="); ok {
				out[strings.TrimSpace(supply)+":"+k] = v
			}
		}
	}
	return out
}

// FirstLine is the first non-blank line of a section.
func FirstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}

// NonEmptyLines drops the blank lines of a section.
func NonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// Unquote strips the shell quoting an os-release, deviceinfo or getprop value
// may carry.
func Unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
