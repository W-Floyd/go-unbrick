package fastboot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/library"
)

const sampleMotorolaGetVarAll = `
(bootloader) version: 0.5
(bootloader) version-bootloader: MBM-3.0-devon-96f143523-221104
(bootloader) product: devon
(bootloader) secure: yes
(bootloader) hwrev: PVT
(bootloader) radio: 1
(bootloader) storage-type: ufs
(bootloader) emmc: false
(bootloader) ufs: 128GB
(bootloader) ram: 4GB
(bootloader) cpu: SM_DIVAR
(bootloader) qcom,soc-id: 0x0000000000000100
(bootloader) cid: 0x0032
(bootloader) channelid: 0x18
(bootloader) uid: 00C0FFEE001B80E1
(bootloader) chipid: 0000043A00C0FFEE
(bootloader) imei: 490154203237518
(bootloader) ro.carrier: retus
(bootloader) frp-state: no protection (0)
(bootloader) verity-state: disabled (0)
(bootloader) securestate: oem_locked
(bootloader) is-userspace: no
(bootloader) current-slot: _a
(bootloader) slot-count: 2
(bootloader) slot-successful:_a: yes
(bootloader) slot-unbootable:_a: no
(bootloader) slot-retry-count:_a: 7
(bootloader) slot-successful:_b: no
(bootloader) slot-unbootable:_b: yes
(bootloader) slot-retry-count:_b: 0
(bootloader) battery-voltage: 4150mV
(bootloader) battery-soc-ok: yes
(bootloader) ro.build.display.id: S2SNS32.34-60-2
(bootloader) ro.build.fingerprint[0]: motorola/devon/devon:12/S2SNS32.
(bootloader) ro.build.fingerprint[1]: 34-60-2/96f14:user/release-keys
(bootloader) version-baseband: M6225_HI433_12.1386.01.60R
(bootloader) partition-size:xbl_a: 0x3E8000
(bootloader) partition-size:abl_a: 0x100000
(bootloader) partition-size:persist: 0x2000000
all: Done.
`

func TestParseGetVarOutput(t *testing.T) {
	recon := ParseGetVarOutput(sampleMotorolaGetVarAll)

	if recon.Product != "devon" {
		t.Errorf("Product: got %q, want devon", recon.Product)
	}
	if recon.HWRev != "PVT" {
		t.Errorf("HWRev: got %q, want PVT", recon.HWRev)
	}
	if recon.CarrierID != "0x0032" {
		t.Errorf("CarrierID: got %q, want 0x0032", recon.CarrierID)
	}
	if recon.UID != "00C0FFEE001B80E1" {
		t.Errorf("UID: got %q, want 00C0FFEE001B80E1", recon.UID)
	}
	if recon.JTAGID != "001B80E1" {
		t.Errorf("JTAGID: got %q, want 001B80E1", recon.JTAGID)
	}
	if recon.IMEI != "490154203237518" {
		t.Errorf("IMEI: got %q, want 490154203237518", recon.IMEI)
	}
	if recon.Carrier != "retus" {
		t.Errorf("Carrier: got %q, want retus", recon.Carrier)
	}
	if recon.FRPState != "no protection (0)" {
		t.Errorf("FRPState: got %q, want 'no protection (0)'", recon.FRPState)
	}
	if recon.VerityState != "disabled (0)" {
		t.Errorf("VerityState: got %q, want 'disabled (0)'", recon.VerityState)
	}
	if recon.StorageType != "ufs" {
		t.Errorf("StorageType: got %q, want ufs", recon.StorageType)
	}
	if recon.CPU != "SM_DIVAR" {
		t.Errorf("CPU: got %q, want SM_DIVAR", recon.CPU)
	}
	if recon.SecureState != "oem_locked" {
		t.Errorf("SecureState: got %q, want oem_locked", recon.SecureState)
	}
	if recon.CurrentSlot != "a" {
		t.Errorf("CurrentSlot: got %q, want a", recon.CurrentSlot)
	}
	if recon.SlotCount != 2 {
		t.Errorf("SlotCount: got %d, want 2", recon.SlotCount)
	}
	if recon.DisplayID != "S2SNS32.34-60-2" {
		t.Errorf("DisplayID: got %q, want S2SNS32.34-60-2", recon.DisplayID)
	}
	wantFP := "motorola/devon/devon:12/S2SNS32.34-60-2/96f14:user/release-keys"
	if recon.Fingerprint != wantFP {
		t.Errorf("Fingerprint: got %q, want %q", recon.Fingerprint, wantFP)
	}

	// Verify slot statuses
	slotA := recon.SlotStatus["a"]
	if slotA == nil || !slotA.Successful || slotA.Unbootable || slotA.RetryCount != 7 {
		t.Errorf("slot a status mismatch: %+v", slotA)
	}

	slotB := recon.SlotStatus["b"]
	if slotB == nil || slotB.Successful || !slotB.Unbootable || slotB.RetryCount != 0 {
		t.Errorf("slot b status mismatch: %+v", slotB)
	}

	// Verify partition sizes
	if sz := recon.PartitionSizes["xbl_a"]; sz != 0x3E8000 {
		t.Errorf("xbl_a size: got 0x%X, want 0x3E8000", sz)
	}
	if sz := recon.PartitionSizes["persist"]; sz != 0x2000000 {
		t.Errorf("persist size: got 0x%X, want 0x2000000", sz)
	}
}

func TestMatchCatalogAndLibrary(t *testing.T) {
	c, err := catalog.Default()
	if err != nil {
		t.Fatalf("Default catalog failed: %v", err)
	}

	recon := &DeviceRecon{
		Product: "devon",
		CPU:     "SM_DIVAR",
	}

	dev, notes := MatchCatalog(c, recon)
	if dev == nil {
		t.Fatalf("expected catalog match for devon, got nil (notes: %v)", notes)
	}
	if dev.Codename != "devon" {
		t.Errorf("matched codename: got %q, want devon", dev.Codename)
	}

	// Test library lookup
	lib := library.Open(t.TempDir())
	match := CheckLibrary(lib, dev, recon)
	if match == nil {
		t.Fatal("expected non-nil match result")
	}
}

func TestCheckLibrarySplitsStockByCID(t *testing.T) {
	c, err := catalog.Default()
	if err != nil {
		t.Fatalf("Default catalog failed: %v", err)
	}
	dev, _ := MatchCatalog(c, &DeviceRecon{Product: "devon", CPU: "SM_DIVAR"})
	if dev == nil {
		t.Fatal("expected catalog match for devon")
	}

	lib := library.Open(t.TempDir())
	mk := func(cid, tag string) *blankflash.Target {
		return &blankflash.Target{
			Parts:    map[string][]byte{"xbl.elf": []byte(tag)},
			FlashMap: map[string]string{"xbl": "xbl.elf"},
			CID:      cid,
		}
	}
	for build, cid := range map[string]string{
		"240823-mine":    "0x0032",
		"250831-foreign": "0x0033",
		"240101-nocid":   "", // hand-assembled dump: classified neither way
	} {
		if _, err := lib.AddStock(dev.Vendor, dev.Codename, build, mk(cid, build)); err != nil {
			t.Fatal(err)
		}
	}

	m := CheckLibrary(lib, dev, &DeviceRecon{Product: "devon", CPU: "SM_DIVAR", CarrierID: "0x0032"})
	if len(m.CIDCompatible) != 1 || m.CIDCompatible[0] != "240823-mine" {
		t.Errorf("CIDCompatible: %v", m.CIDCompatible)
	}
	if len(m.CIDForeign) != 1 || m.CIDForeign[0] != "250831-foreign (0x0033)" {
		t.Errorf("CIDForeign: %v", m.CIDForeign)
	}

	// A device that does not report a CID cannot be told anything about fit.
	m = CheckLibrary(lib, dev, &DeviceRecon{Product: "devon", CPU: "SM_DIVAR"})
	if len(m.CIDCompatible) != 0 || len(m.CIDForeign) != 0 {
		t.Errorf("no device CID should classify nothing: %v %v", m.CIDCompatible, m.CIDForeign)
	}
}

func TestSlotBootableNeedsRetriesOrSuccess(t *testing.T) {
	cases := []struct {
		name string
		info SlotInfo
		want bool
	}{
		{"booted before", SlotInfo{Successful: true}, true},
		{"never booted, retries left", SlotInfo{RetryCount: 3}, true},
		// The case the slot-unbootable flag alone gets wrong: nothing has marked
		// it, but the bootloader has no attempts left to give it.
		{"never booted, no retries", SlotInfo{}, false},
		{"flagged", SlotInfo{Unbootable: true, Successful: true, RetryCount: 7}, false},
	}
	for _, c := range cases {
		if got := c.info.Bootable(); got != c.want {
			t.Errorf("%s: Bootable() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBootChainMatchOnXBLHash(t *testing.T) {
	// Same XBL git hash, built on a different date than the packaged one.
	recon := &DeviceRecon{
		XBLBuild:          "MBM-3.0-fogona-2902df5ac-250618",
		BootloaderVersion: "MBM-3.0-fogona-8a6797a117f-250618-U1TF34.100-35-14-98d43",
		Fingerprint:       "motorola/fogona_g/fogona:14/U1TF34.100-35-14/98d43-1082f4:user/release-keys",
	}
	if matchesStockBuild("250831-2902df5ac", recon) {
		t.Error("differing build date must not count as an exact match")
	}
	if !matchesBootChain("250831-2902df5ac", recon) {
		t.Error("same XBL hash should match the boot chain")
	}
	if matchesBootChain("240823-b2e77d5e", recon) {
		t.Error("another device's XBL hash must not match")
	}
	if matchesBootChain("250831-2902df5ac", &DeviceRecon{}) {
		t.Error("a device that reports no MBM string cannot match anything")
	}
}

// fakeFastboot writes a stub binary that echoes a canned reply, so the getvar
// plumbing can be exercised without a device.
func fakeFastboot(t *testing.T, reply string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fastboot")
	script := "#!/bin/sh\ncat <<'EOF'\n" + reply + "\nEOF\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGetVarSplitsAfterVariableName(t *testing.T) {
	// The variable name contains a colon; splitting at the first one yields
	// "super: raw" instead of "raw".
	c, err := NewClient(fakeFastboot(t, "partition-type:super: raw\nFinished. Total time: 0.001s"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.GetVar("", "partition-type:super")
	if err != nil {
		t.Fatal(err)
	}
	if got != "raw" {
		t.Errorf("GetVar: got %q, want raw", got)
	}
}

func TestProbePartitionsReadsBootloaderFacts(t *testing.T) {
	// The stub answers every variable from one canned block; GetVar picks the
	// line whose name matches what was asked.
	reply := strings.Join([]string{
		"partition-type:system_a: ext4",
		"is-logical:system_a: yes",
		"has-slot:system: yes",
		"partition-size:system_a: 0x1000",
	}, "\n")
	c, err := NewClient(fakeFastboot(t, reply))
	if err != nil {
		t.Fatal(err)
	}
	f := c.ProbePartitions("", []string{"system_a"})["system_a"]
	if f.Type != "ext4" || !f.IsLogical || !f.HasSlot || f.SizeBytes != 0x1000 {
		t.Errorf("facts: %+v", f)
	}
}

func TestComponentBuildsAndMixedChain(t *testing.T) {
	out := `
(bootloader) git:xbl: MBM-3.0-fogona-2902df5ac-250618
(bootloader) git:xbl_config: MBM-3.0-fogona-2902df5ac-250618
(bootloader) git:abl[0]: MBM-3.0-fogona-8a6797a117f-250618-U1TF34.100-35
(bootloader) git:abl[1]: -14-98d43
(bootloader) git:tz: MBM-3.0-fogona-21af199f-240823
(bootloader) ro.build.version.qcom[0]: AU_LINUX_ANDROID_LA.VENDOR.13.2.1
(bootloader) ro.build.version.qcom[1]: .R1.11.00.00.587.093
(bootloader) max-download-size: 784097280
(bootloader) logical-block-size: 0x1000
(bootloader) running-boot-lun: 1
`
	r := ParseGetVarOutput(out)

	// git:xbl_config shares the git:xbl prefix and must not claim XBLBuild.
	if r.XBLBuild != "MBM-3.0-fogona-2902df5ac-250618" {
		t.Errorf("XBLBuild: %q", r.XBLBuild)
	}
	// A value split across lines is rejoined.
	if want := "MBM-3.0-fogona-8a6797a117f-250618-U1TF34.100-35-14-98d43"; r.ComponentBuilds["abl"] != want {
		t.Errorf("abl stamp: %q", r.ComponentBuilds["abl"])
	}
	if want := "AU_LINUX_ANDROID_LA.VENDOR.13.2.1.R1.11.00.00.587.093"; r.QCBaseline != want {
		t.Errorf("QCBaseline: %q", r.QCBaseline)
	}
	if r.MaxDownloadSize != 784097280 || r.LogicalBlockSize != 0x1000 || r.BootLUN != "1" {
		t.Errorf("geometry: %d %d %q", r.MaxDownloadSize, r.LogicalBlockSize, r.BootLUN)
	}

	// tz is a release behind the rest: two groups, which is the partial-flash signal.
	dates := r.BootChainDates()
	if len(dates) != 2 {
		t.Fatalf("expected two release groups, got %v", dates)
	}
	if got := dates["240823"]; len(got) != 1 || got[0] != "tz" {
		t.Errorf("240823 group: %v", got)
	}
	if got := dates["250618"]; len(got) != 3 {
		t.Errorf("250618 group: %v", got)
	}
}

func TestFirstDeviceMessagePrefersBootloader(t *testing.T) {
	// The device's own words beat the host tool's, so an EDL attempt that
	// actually reached the bootloader is not reported as a usage error.
	out := "(bootloader) Command restricted!\nFAILED (remote: '')\nfastboot: error: Command failed\n"
	if got := firstDeviceMessage(out); got != "Command restricted!" {
		t.Errorf("got %q", got)
	}
	// Nothing reached the device: the host tool rejected the target itself.
	hostOnly := "fastboot: usage: unknown reboot target edl\n"
	if got := firstDeviceMessage(hostOnly); got != "fastboot: usage: unknown reboot target edl" {
		t.Errorf("got %q", got)
	}
	if got := firstDeviceMessage("(bootloader) \nrandom noise\n"); got != "" {
		t.Errorf("empty bootloader line should not be reported as a message: %q", got)
	}
}

// The Motorola OEM-command parser tests moved with their code to
// internal/vendor/motorola_fastboot_test.go.
