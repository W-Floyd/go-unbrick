package transport

import (
	"strings"
	"testing"
)

// collected is one real-shaped collection from a booted device: a Motorola
// fogona on the stock Qualcomm boot chain, logged in as an unprivileged user
// with a passwordless doas. The sections are what CommonShellScript emits,
// including ones a device may leave empty.
const collected = `
===unbrick:whoami===
uid=1000
user=user
===unbrick:hostname===
fogona
===unbrick:elevate===
doas
sudo
===unbrick:elevate-ok===
doas
===unbrick:cmdline===
console=ttyMSM0,115200n8 androidboot.slot_suffix=_a androidboot.serialno=ZLTEST0001 androidboot.verifiedbootstate=orange androidboot.bootloader=MBM-3.0-fogona-2902df5ac-250618 buildvariant=user
===unbrick:cpuinfo===
Hardware	: Qualcomm Technologies, Inc SM6225
Revision	: 0000
===unbrick:soc0===
family=Snapdragon
machine=SM6225
soc_id=434
===unbrick:dt-model===
Motorola fogona
===unbrick:dt-compatible===
motorola,fogona
qcom,sm6225
===unbrick:partitions===
abl_a	/dev/sde11	2048
abl_b	/dev/sde12	2048
cid	/dev/sdf5	256
super	/dev/sde53	12582912
userdata	/dev/sda1	230686720
vbmeta_a	/dev/sde20	128
vbmeta_b	/dev/sde21	128
xbl_a	/dev/sdd1	8192
xbl_b	/dev/sdd2	8192
===unbrick:disks===
sda	230686720
sdd	16384
sde	25165824
===unbrick:battery===
battery: type=Battery status=Discharging capacity=64 voltage_now=3897000
`

func TestParseShell(t *testing.T) {
	r := ParseShell(collected)

	if r.User != "user" || r.UID != 1000 || r.Hostname != "fogona" {
		t.Errorf("identity = %q/%d/%q", r.User, r.UID, r.Hostname)
	}
	// Both helpers are installed; only one proved it needs no password, and
	// that distinction is what decides whether a read can even be attempted.
	if r.Elevate != "doas" || r.ElevateOK != "doas" {
		t.Errorf("elevate/elevate-ok = %q/%q", r.Elevate, r.ElevateOK)
	}
	if got := r.Slot(); got != "a" {
		t.Errorf("Slot() = %q, want a", got)
	}
	if got := r.Serial(); got != "ZLTEST0001" {
		t.Errorf("Serial() = %q", got)
	}
	// verifiedbootstate=orange is an unlocked bootloader.
	if got := r.LockState(); got != "unlocked" {
		t.Errorf("LockState() = %q, want unlocked", got)
	}
	if !r.ABDevice() {
		t.Error("ABDevice() = false on a table with xbl_a and xbl_b")
	}
	if r.DTModel != "Motorola fogona" {
		t.Errorf("dt model = %q", r.DTModel)
	}
	if r.SoC0["soc_id"] != "434" {
		t.Errorf("soc0 = %+v", r.SoC0)
	}
	if r.Storage != "ufs" {
		t.Errorf("storage = %q, want ufs (SCSI disks are the UFS LUNs)", r.Storage)
	}
	if got := r.BatteryPercent(); got != 64 {
		t.Errorf("battery = %d%%, want 64", got)
	}
	if _, ok := r.Sections["dt-compatible"]; !ok {
		t.Error("raw sections lost dt-compatible")
	}
}

// A device whose cmdline the installed system replaced wholesale has no
// androidboot.* at all; the partition table still settles A/B, and the absent
// facts must not resolve to something invented.
func TestCmdlineReplaced(t *testing.T) {
	r := ParseShell(strings.Replace(collected,
		"androidboot.slot_suffix=_a androidboot.serialno=ZLTEST0001 androidboot.verifiedbootstate=orange androidboot.bootloader=MBM-3.0-fogona-2902df5ac-250618",
		"root=/dev/mapper/root rw", 1))

	if got := r.Slot(); got != "" {
		t.Errorf("Slot() = %q, want empty", got)
	}
	if got := r.LockState(); got != "" {
		t.Errorf("LockState() = %q, want empty", got)
	}
	if !r.ABDevice() {
		t.Error("ABDevice() = false: the _a/_b partition pairs still say A/B")
	}
}

func TestDTCodename(t *testing.T) {
	r := ParseShell(collected)
	name, vendor := r.DTCodename()
	if name != "fogona" || vendor != "motorola" {
		t.Errorf("DTCodename() = %q/%q, want fogona/motorola", name, vendor)
	}
	// The SoC vendor's own entry is a platform, not a device.
	socOnly := ParseShell(strings.Replace(collected, "motorola,fogona\n", "", 1))
	if name, _ := socOnly.DTCodename(); name != "" {
		t.Errorf("DTCodename() = %q from a qcom-only compatible list", name)
	}
}

func TestSoCTokens(t *testing.T) {
	r := ParseShell(collected)
	if got := r.SoCTokens(); len(got) != 1 || got[0] != "SM6225" {
		t.Errorf("SoCTokens() = %v, want [SM6225] (all three sources agree)", got)
	}

	// What a mainline kernel actually reports: soc0/machine is the board model,
	// and the device tree lists the SoC family it also binds to after the part
	// it is. Neither is a second claim about the silicon.
	mainline := ParseShell(strings.NewReplacer(
		"machine=SM6225", "machine=Motorola Moto G Play (2024) (Tianma ICNL9916C)",
		"qcom,sm6225", "qcom,sm6225\nqcom,sm6115",
		"Hardware\t: Qualcomm Technologies, Inc SM6225", "",
	).Replace(collected))
	if got := mainline.SoCTokens(); len(got) != 1 || got[0] != "sm6225" {
		t.Errorf("SoCTokens() = %v, want [sm6225]: the model string is not a part "+
			"number and the fallback compatible is not a second part", got)
	}
}

func TestLooksLikePartNumber(t *testing.T) {
	for _, s := range []string{"SM6225", "sm6225", "msm8953", "SM7435-AB"} {
		if !LooksLikePartNumber(s) {
			t.Errorf("LooksLikePartNumber(%q) = false", s)
		}
	}
	for _, s := range []string{"", "Snapdragon", "Motorola Moto G Play (2024)", "qcom"} {
		if LooksLikePartNumber(s) {
			t.Errorf("LooksLikePartNumber(%q) = true", s)
		}
	}
}

func TestParsePartitionTable(t *testing.T) {
	r := ParseShell(collected)
	if len(r.Partitions) != 9 {
		t.Fatalf("parsed %d partitions, want 9", len(r.Partitions))
	}
	xbl, ok := r.Partition("xbl_a")
	if !ok {
		t.Fatal("xbl_a missing from the table")
	}
	// sysfs sizes are 512-byte sectors whatever the device's block size is.
	if xbl.SizeBytes != 8192*512 {
		t.Errorf("xbl_a size = %d bytes, want %d", xbl.SizeBytes, 8192*512)
	}
	if xbl.Base() != "xbl" || xbl.Slot() != "a" {
		t.Errorf("xbl_a base/slot = %q/%q", xbl.Base(), xbl.Slot())
	}
	if xbl.Handle != "/dev/sdd1" {
		t.Errorf("xbl_a handle = %q", xbl.Handle)
	}
	if cid, _ := r.Partition("cid"); cid.Slot() != "" || cid.Base() != "cid" {
		t.Errorf("slotless partition read as slotted: %+v", cid)
	}
}

func TestIdentityPartitionSelection(t *testing.T) {
	r := ParseShell(collected)
	var names []string
	for _, p := range IdentityPartitions(r.Partitions, r.Slot(), DefaultReadCap) {
		names = append(names, p.Name)
	}
	// The booted slot only, identity partitions only, smallest first — and
	// never super or userdata whatever the cap.
	want := []string{"vbmeta_a", "cid", "abl_a", "xbl_a"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("IdentityPartitions() = %v, want %v", names, want)
	}
	if got := IdentityPartitions(r.Partitions, r.Slot(), 512<<10); len(got) != 2 {
		t.Errorf("under a 512 KiB cap, selected %d partitions, want vbmeta_a and cid", len(got))
	}
}

// A device that answered nothing must parse to an empty recon rather than
// panic: an unprivileged login on a hardened install is a real case.
func TestParseShellEmpty(t *testing.T) {
	r := ParseShell("")
	if r.Slot() != "" || len(r.Partitions) != 0 || r.ABDevice() {
		t.Errorf("empty collection yielded %+v", r)
	}
	if r.BatteryPercent() != -1 {
		t.Error("BatteryPercent() should be -1 when nothing reported one")
	}
	if name, _ := r.DTCodename(); name != "" {
		t.Errorf("DTCodename() = %q off an empty collection", name)
	}
}

func TestBootMedium(t *testing.T) {
	for _, c := range []struct {
		src, fs, storage, want string
	}{
		{"/dev/mmcblk0p2", "ext4", "ufs", "removable"},   // SD card on a UFS phone
		{"overlay", "overlay", "ufs", "ram"},             // live/initramfs
		{"tmpfs", "tmpfs", "emmc", "ram"},                //
		{"/dev/sde54", "ext4", "ufs", "internal"},        // internal UFS LUN
		{"/dev/mmcblk0p1", "ext4", "emmc", "internal"},   // the eMMC itself
		{"/dev/mmcblk1p1", "ext4", "emmc", "removable"},  // SD slot beside eMMC
		{"", "", "ufs", ""},                              // no mount info
	} {
		r := &ShellRecon{RootSource: c.src, RootFS: c.fs, Storage: c.storage}
		if got := r.BootMedium(); got != c.want {
			t.Errorf("BootMedium(%q,%q,%q)=%q want %q", c.src, c.fs, c.storage, got, c.want)
		}
	}
}
