package adb

// What an Android userspace says about itself: the common shell collection
// every booted route shares, plus the property system, which is Android's
// equivalent of a distribution's device definition and rather more detailed —
// the build fingerprint, the security patch level, the OEM's own name for the
// device, and whatever the bootloader passed through as ro.boot.*.

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/transport"
)

// Recon is one collection round trip.
type Recon struct {
	*transport.ShellRecon
	Serial string
	// Props is the whole property system, keyed as getprop spells it. It is
	// mutable state read from a running system — a rooted device can set any of
	// it — which is why facts from it are Derived.
	Props map[string]string
	// FWImages is the firmware the boot chain actually loaded, from whichever
	// socinfo rendering the kernel offers; FWImagesFrom names it.
	FWImages     []transport.FWImage
	FWImagesFrom string
}

// collectScript is the common collection plus the property dump. getprop with
// no argument prints "[key]: [value]" lines, which is one section and one
// parser.
//
// The socinfo image table falls back to root: soc0/images is often
// selinux-denied to the shell user, and debugfs is root-only and on user
// builds unmounted — mounted here only for the read, and only if it was not.
const collectScript = transport.CommonShellScript + `
u getprop
getprop 2>/dev/null
u root
id -u 2>/dev/null
su -c id -u 2>/dev/null
asroot() {
	if [ "$(id -u 2>/dev/null)" = 0 ]; then sh -c "$1" </dev/null
	elif su -c id -u </dev/null 2>/dev/null | grep -q '^0$'; then su -c "$1" </dev/null
	fi
}
u soc-images
img=$(cat /sys/devices/soc0/images 2>/dev/null </dev/null || asroot 'cat /sys/devices/soc0/images' 2>/dev/null)
printf '%s\n' "$img"
u socinfo-images
[ -z "$img" ] && asroot 'd=/sys/kernel/debug; m=
grep -q " $d debugfs " /proc/mounts || { mount -t debugfs debugfs $d && m=1; }
for i in $d/qcom_socinfo/*/; do
	[ -f "$i/name" ] || continue
	printf "%s\t%s\t%s\t%s\n" "$(basename "$i")" "$(cat "$i/name")" "$(cat "$i/variant")" "$(cat "$i/oem")"
done
[ -n "$m" ] && umount $d' 2>/dev/null
`

// Collect runs the collection and parses it.
func Collect(c *Client) (*Recon, error) {
	out, err := c.Run(collectScript)
	if strings.TrimSpace(out) == "" && err != nil {
		return nil, err
	}
	r := Parse(out)
	r.Serial = c.serial
	c.elevate = r.rootHelper(c.opts.Elevate)
	return r, err
}

// Parse turns collection output into a Recon.
func Parse(out string) *Recon {
	sh := transport.ParseShell(out)
	r := &Recon{ShellRecon: sh, Props: parseGetprop(sh.Sections["getprop"])}
	if im := transport.ParseSoCImages(sh.Sections["soc-images"]); len(im) > 0 {
		r.FWImages, r.FWImagesFrom = im, "soc0/images"
	} else if im := transport.ParseDebugfsImages(sh.Sections["socinfo-images"]); len(im) > 0 {
		r.FWImages, r.FWImagesFrom = im, "debugfs qcom_socinfo"
	}
	return r
}

// parseGetprop reads getprop's "[key]: [value]" listing.
func parseGetprop(s string) map[string]string {
	out := map[string]string{}
	for _, line := range transport.NonEmptyLines(s) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		k = strings.Trim(strings.TrimSpace(k), "[]")
		v = strings.Trim(strings.TrimSpace(v), "[]")
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// rootHelper decides how a partition read will become root: not at all when the
// shell already is (adb root on a userdebug build), else su if it proved it
// works. There is nothing to prompt for — an su that asks its own question
// asks it on the device's screen, where this recon cannot answer.
func (r *Recon) rootHelper(override string) string {
	switch override {
	case "none":
		return ""
	case "su":
		return "su"
	}
	if r.UID == 0 {
		return ""
	}
	if r.ElevateOK == "su" {
		return "su"
	}
	return ""
}

// CanReadPartitions reports whether a partition read can succeed.
func (r *Recon) CanReadPartitions() bool { return r.UID == 0 || r.ElevateOK == "su" }

// BootParams is what the bootloader passed, from whichever source this device
// will show. /proc/cmdline is unreadable to an unrooted adb shell on Android 12
// and later, but the same values survive as ro.boot.* properties — which is the
// *only* place an unrooted recon learns the slot and the verified-boot state.
// The cmdline wins where both answer, since a property is one copy further from
// the bootloader.
func (r *Recon) BootParams() map[string]string {
	out := make(map[string]string, len(r.Cmdline)+8)
	for k, v := range r.Props {
		if rest, ok := strings.CutPrefix(k, "ro.boot."); ok && rest != "" {
			out["androidboot."+rest] = v
		}
	}
	for k, v := range r.Cmdline {
		out[k] = v
	}
	return out
}

// Slot is the booted A/B slot, from the cmdline or the properties that mirror
// it. It shadows the shell recon's own reading for that reason.
func (r *Recon) Slot() string {
	if s := r.ShellRecon.Slot(); s != "" {
		return s
	}
	for _, k := range []string{"ro.boot.slot_suffix", "ro.boot.slot"} {
		if v := r.Props[k]; v != "" {
			return strings.TrimPrefix(strings.ToLower(v), "_")
		}
	}
	return ""
}

// LockState is the verified-boot state, from the cmdline or the properties.
func (r *Recon) LockState() string {
	if s := r.ShellRecon.LockState(); s != "" {
		return s
	}
	switch strings.ToLower(r.Props["ro.boot.verifiedbootstate"]) {
	case "orange":
		return "unlocked"
	case "green", "yellow", "red":
		return "locked"
	}
	switch r.Props["ro.boot.flash.locked"] {
	case "0":
		return "unlocked"
	case "1":
		return "locked"
	}
	return ""
}

// ABDevice reports whether this is an A/B device: the partition table settles
// it, and the slot suffix answers when the table was unreadable.
func (r *Recon) ABDevice() bool { return r.ShellRecon.ABDevice() || r.Slot() != "" }

// Codename is the device codename Android reports — the OEM's own, and the same
// string the bootloader answers `getvar product` with.
func (r *Recon) Codename() string {
	for _, k := range []string{"ro.product.device", "ro.product.vendor.device", "ro.boot.device", "ro.product.name"} {
		if v := r.Props[k]; v != "" {
			return v
		}
	}
	name, _ := r.DTCodename()
	return name
}

// Model is the OEM model number (an "XT2417-2"), which is a different fact from
// the codename and from the marketing name.
func (r *Recon) Model() string {
	return firstProp(r.Props, "ro.product.model", "ro.product.vendor.model", "ro.boot.hardware.sku")
}

// Manufacturer is the OEM as Android names it.
func (r *Recon) Manufacturer() string {
	return firstProp(r.Props, "ro.product.manufacturer", "ro.product.vendor.manufacturer", "ro.product.brand")
}

// Fingerprint is the build's own identity — the string a device also reports
// over fastboot, which is what makes package-vs-device comparable.
func (r *Recon) Fingerprint() string {
	return firstProp(r.Props, "ro.build.fingerprint", "ro.system.build.fingerprint", "ro.vendor.build.fingerprint")
}

// SoCTokens are the part numbers this device has for its silicon: what any
// shell route finds, plus Android's own board platform property.
func (r *Recon) SoCTokens() []string {
	out := r.ShellRecon.SoCTokens()
	seen := map[string]bool{}
	for _, s := range out {
		seen[strings.ToLower(s)] = true
	}
	for _, k := range []string{"ro.board.platform", "ro.hardware", "ro.soc.model"} {
		v := strings.TrimSpace(r.Props[k])
		if v == "" || seen[strings.ToLower(v)] || !transport.LooksLikePartNumber(v) {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	return out
}

// VendorID is the OEM as a catalog vendor id.
func (r *Recon) VendorID() string {
	if m := r.Manufacturer(); m != "" {
		if f := strings.Fields(m); len(f) > 0 {
			return strings.ToLower(f[0])
		}
	}
	_, v := r.DTCodename()
	return v
}

// ReadPartition returns one partition's bytes, bounded by budget — which is the
// partition's size where the device reported one, and the read cap where it did
// not (an unrooted shell cannot read /sys/class/block at all). A read that
// comes back exactly at the bound has hit the cap rather than the end of the
// partition, and is reported as truncated: part of an image is not the image,
// and handing it to the recognizers would have them describe something that
// does not exist.
//
// base64, unlike the ssh route: the adb server's legacy shell service is a text
// channel that has historically translated line endings on some devices, and a
// boot image with a mangled byte is worse than a slower transfer.
func ReadPartition(c *Client, p transport.Partition, budget uint64) ([]byte, error) {
	if p.Handle == "" {
		return nil, fmt.Errorf("%s: no device node", p.Name)
	}
	blocks := (budget + 65535) / 65536
	script := c.elevated(fmt.Sprintf("dd if=%s bs=65536 count=%d 2>/dev/null | base64",
		shellQuote(p.Handle), blocks))
	out, err := c.Run(script)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.Name, err)
	}
	data, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(out), ""))
	if derr != nil {
		// What the shell said instead of base64 is the explanation — an su
		// refusal, a missing node, a selinux denial.
		return nil, fmt.Errorf("reading %s: %s", p.Name, firstMeaningfulLine(out))
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("reading %s: empty — %s", p.Name, rootHint(c))
	}
	if p.SizeBytes == 0 && uint64(len(data)) >= blocks*65536 {
		return nil, fmt.Errorf("reading %s: the device would not report its size and it is larger than the %d-byte cap, so this is a fragment rather than the partition — raise --read-cap, or read as root so sizes are available",
			p.Name, budget)
	}
	return data, nil
}

func rootHint(c *Client) string {
	if c.elevate == "" {
		return "the adb shell is not root (try `adb root` on a userdebug build, or a device with su)"
	}
	return "su ran but the device returned nothing (an selinux denial looks like this)"
}

func firstMeaningfulLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return "no output"
}

// shellFailure is the *reason* out of a shell-command refusal. The first line is
// not always it: `pm disable-user` answers "Exception occurred while executing
// 'disable-user':" and puts the cause — "java.lang.SecurityException: Cannot
// disable a protected package: com.motorola.paks" — on the next line, with a
// stack trace after. Reporting the first line alone told the operator nothing,
// which is how this function came to exist.
func shellFailure(out string) string {
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "at ") { // a stack frame, not a cause
			continue
		}
		if i := strings.Index(t, "Exception: "); i >= 0 {
			return strings.TrimSpace(t[i+len("Exception: "):])
		}
		if strings.HasPrefix(t, "Failure") || strings.HasPrefix(t, "Error") {
			return t
		}
	}
	return firstMeaningfulLine(out)
}

func firstProp(props map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(props[k]); v != "" {
			return v
		}
	}
	return ""
}
