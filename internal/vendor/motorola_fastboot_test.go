package vendor

import (
	"errors"
	"strings"
	"testing"

	"go-unbrick/internal/fastboot"
)

// sampleOEMHw exercises the utag parser beyond the sensor bits: the value line,
// the `.range` variant space, the hwid `.auto` derivation, and the wrapped
// `.features` list.
const sampleOEMHw = `(bootloader) dualsim/.auto_detected: false
(bootloader) ecompass/.auto_detected: true
(bootloader) esim/.auto_detected: false
(bootloader) fps/.auto_detected: true
(bootloader) nfc/.auto_detected: false
(bootloader) radio/.auto_detected: RET
(bootloader) ram/.auto_detected: 4GB
(bootloader) storage/.auto_detected: 64GB
(bootloader) .version: 0.5
(bootloader) storage/.system: ro.vendor.hw.
(bootloader) storage/.range: 64GB,128GB,256GB
(bootloader) storage/.auto: key=hwprobe;index=__storage
(bootloader) storage: 64GB
(bootloader) ram/.system: ro.vendor.hw.
(bootloader) ram/.range: 4GB,6GB
(bootloader) ram/.auto: key=hwprobe;index=__ram
(bootloader) ram: 4GB
(bootloader) radio/.system: ro.vendor.hw.
(bootloader) radio/.range: ATT,RET
(bootloader) radio/.cmdline: androidboot.
(bootloader) radio/.auto: key=hwid;index=2;map=1:ATT,2:RET
(bootloader) radio: RET
(bootloader) nfc/.system: ro.vendor.hw.
(bootloader) nfc/.range: st,false
(bootloader) nfc/.chosen: mmi,
(bootloader) nfc/.auto: default=false
(bootloader) nfc: false
(bootloader) frontcolor/.system: ro.vendor.hw.
(bootloader) frontcolor/.range: coronetblue,coralcloud,other
(bootloader) frontcolor:
(bootloader) fps/.system: ro.vendor.hw.
(bootloader) fps/.range: true
(bootloader) fps/.chosen: mmi,
(bootloader) fps/.auto: default=true
(bootloader) fps: true
(bootloader) esim/.system: ro.vendor.hw.
(bootloader) esim/.range: true,false
(bootloader) esim/.auto: default=false
(bootloader) esim: false
(bootloader) ecompass/.system: ro.vendor.hw.
(bootloader) ecompass/.range: true
(bootloader) ecompass/.chosen: mmi,
(bootloader) ecompass/.auto: default=true
(bootloader) ecompass: true
(bootloader) dualsim/.system: ro.vendor.hw.
(bootloader) dualsim/.range: true,false
(bootloader) dualsim/.auto: default=false
(bootloader) dualsim: false
(bootloader) .attributes: .range,.cmdline,.chosen,.system,.auto
(bootloader) .features: radio,ram,storage,dualsim,frontcolor,fps,nfc
(bootloader) ,ecompass,esim
OKAY [  0.005s]
Finished. Total time: 0.005s`

func TestParseOEMHwUTags(t *testing.T) {
	hw := ParseOEMHwOutput(sampleOEMHw)
	if hw == nil {
		t.Fatal("expected parsed hw info")
	}
	if !hw.FPS || !hw.ECompass || hw.NFC || hw.ESIM || hw.DualSIM || hw.RadioType != "RET" {
		t.Errorf("sensor bits: %+v", hw)
	}
	byName := map[string]UTag{}
	for _, u := range hw.UTags {
		byName[u.Name] = u
	}
	if got := byName["storage"].Range; len(got) != 3 || got[0] != "64GB" || got[2] != "256GB" {
		t.Errorf("storage range: %v", got)
	}
	if got := byName["ram"]; got.Value != "4GB" || len(got.Range) != 2 {
		t.Errorf("ram: %+v", got)
	}
	if got := byName["radio"].HWIDMap; got != "key=hwid;index=2;map=1:ATT,2:RET" {
		t.Errorf("radio hwid map: %q", got)
	}
	if byName["ram"].HWIDMap != "" {
		t.Errorf("ram should carry no hwid map, got %q", byName["ram"].HWIDMap)
	}
	if _, ok := byName["esim"]; !ok {
		t.Error("esim lost from wrapped .features line")
	}
	if len(hw.UTags) < 9 {
		t.Errorf("expected all 9 declared utags, got %d", len(hw.UTags))
	}
	if hw.UTags[0].Name != "radio" {
		t.Errorf("utags should follow .features order (radio first), got %q", hw.UTags[0].Name)
	}
}

func TestParseOEMPartitionHashOutput(t *testing.T) {
	restricted := "(bootloader) Command restricted!\nFAILED (remote: '')\n"
	if _, err := ParseOEMPartitionHashOutput(restricted, "sha256"); !errors.Is(err, ErrOEMRestricted) {
		t.Errorf("locked device should report ErrOEMRestricted, got %v", err)
	}
	needsMoto := "(bootloader) Latest Motorola fastboot required, download from: \n(bootloader) http://goo.gl/Qyzg2L\n"
	if _, err := ParseOEMPartitionHashOutput(needsMoto, "sha256"); !errors.Is(err, ErrNeedsMotorolaFastboot) {
		t.Errorf("client gate should report ErrNeedsMotorolaFastboot, got %v", err)
	}

	sha := "8a6797a117f0b2e77d5e2902df5ac0011223344556677889900aabbccddeeff0"
	for _, out := range []string{
		"(bootloader) sha256sum: " + sha + "\nOKAY [ 0.9s]\n",
		"(bootloader) sha256: " + sha + "\nOKAY [ 0.9s]\n",
		"(bootloader) cid sha256 = " + sha + "\n",
		"(bootloader) " + sha + "\n",
	} {
		got, err := ParseOEMPartitionHashOutput(out, "sha256")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != sha {
			t.Errorf("digest: got %q want %q", got, sha)
		}
	}

	md5Out := "(bootloader) size:131072, md5:0123456789abcdef0123456789abcdef\n"
	if got, _ := ParseOEMPartitionHashOutput(md5Out, "sha256"); got != "" {
		t.Errorf("md5-length digest accepted as sha256: %q", got)
	}
	if got, _ := ParseOEMPartitionHashOutput(md5Out, "md5"); got != "0123456789abcdef0123456789abcdef" {
		t.Errorf("md5 digest: got %q", got)
	}

	if got, err := ParseOEMPartitionHashOutput("OKAY [ 0.001s]\n", "sha256"); got != "" || err != nil {
		t.Errorf("empty reply: got %q, %v", got, err)
	}
}

func TestParseOEMHw(t *testing.T) {
	raw := `
(bootloader) dualsim: false
(bootloader) ecompass: true
(bootloader) esim: false
(bootloader) fps: true
(bootloader) nfc: false
(bootloader) radio: RET
OKAY [  0.004s]
`
	hw := ParseOEMHwOutput(raw)
	if hw == nil {
		t.Fatal("expected non-nil OEMHardwareInfo")
	}
	if hw.DualSIM != false || !hw.ECompass || hw.ESIM != false || !hw.FPS || hw.NFC != false || hw.RadioType != "RET" {
		t.Errorf("OEMHw fields mismatch: %+v", hw)
	}
}

func TestParseOEMReadSV(t *testing.T) {
	raw := `
(bootloader) NOTE: vbmeta RIL is 0.
(bootloader) RIL #0 = 13
(bootloader) RIL #1 = 0
(bootloader) RIL #2 = 13
(bootloader) XBL = 0x0
(bootloader) ABL = 0x0
OKAY [  0.007s]
`
	sv := ParseOEMReadSVOutput(raw)
	if sv == nil {
		t.Fatal("expected non-nil SecurityVersions")
	}
	if sv.RIL0 != 13 || sv.RIL2 != 13 || sv.VbmetaRIL != 0 {
		t.Errorf("SecurityVersions mismatch: %+v", sv)
	}
}

func TestParseOEMCIDProvReq(t *testing.T) {
	// Real fogona (SM_DIVAR, JTAG 001B80E1) dump: hex blocks, not key/value.
	raw := `
(bootloader) 0003dddddddddddddddd000000000000
(bootloader) 00000000000000000000000000000000
(bootloader) 00000000000000000000000000000000
(bootloader) 00000000000000000000000000000000
(bootloader) 0000b5135a51398bd9aaedf208e70b92
(bootloader) 3f72000100f00002000000705c8e3f58
(bootloader) 001b80e1000000000000000000000000
(bootloader) 00000000000000000000000002000000
(bootloader) 00000000dddddddddddddddd00063131
(bootloader) 31313131313131313131313131313131
(bootloader) 31310000ffffffffffffffffffffffff
(bootloader) ffffffffffffffffffffffffffffffff
(bootloader) ffffffff
OKAY [  0.002s]
Finished. Total time: 0.002s
`
	cp := ParseOEMCIDProvReqOutput(raw)
	if !cp.Supported {
		t.Fatal("expected Supported for a bootloader that answered")
	}
	if len(cp.Raw) != 196 {
		t.Fatalf("expected 196 raw bytes, got %d", len(cp.Raw))
	}
	if cp.SoCID != "001B80E1" {
		t.Errorf("SoCID: got %q, want 001B80E1", cp.SoCID)
	}
	if cp.FormatVersion != 3 {
		t.Errorf("FormatVersion: got %d, want 3", cp.FormatVersion)
	}
	if cp.Digest != "b5135a51398bd9aaedf208e70b923f72" {
		t.Errorf("Digest: got %q", cp.Digest)
	}
}

func TestParseOEMCIDProvReqKeyValue(t *testing.T) {
	cp := ParseOEMCIDProvReqOutput("(bootloader) UFS_ID: 4D543132384742\nOKAY [  0.0s]\n")
	if !cp.Supported || cp.Fields["UFS_ID"] != "4D543132384742" {
		t.Errorf("key/value fallback failed: %+v", cp)
	}
}

func TestParseOEMCIDProvReqUnsupported(t *testing.T) {
	raw := "FAILED (remote: unknown command)\n"
	if cp := ParseOEMCIDProvReqOutput(raw); cp.Supported {
		t.Errorf("expected not Supported for a rejected command, got %+v", cp)
	}
}

func TestParseOEMPartition(t *testing.T) {
	raw := `
(bootloader) hw: offset=128KB, size=8192KB
(bootloader) super: offset=165376KB, size=6553600KB
(bootloader) product_a: offset=165376KB, size=3683728KB
(bootloader) product_b: offset=165376KB, size=0KB
(bootloader) system_a: offset=165376KB, size=638484KB
(bootloader) system_b: offset=165376KB, size=30288KB
OKAY [  0.008s]
`
	parts, unpop, unpopList := ParseOEMPartitionOutput(raw)
	if len(parts) != 6 {
		t.Fatalf("expected 6 partitions, got %d", len(parts))
	}
	if !unpop {
		t.Errorf("expected unpopulated slot b partitions")
	}
	if len(unpopList) != 1 || unpopList[0] != "product_b" {
		t.Errorf("unpopulated list mismatch: %v", unpopList)
	}
	if !parts[2].IsSuper || parts[2].Name != "product_a" {
		t.Errorf("expected product_a to be dynamic in super: %+v", parts[2])
	}
}

func TestMotoUnlockCrossCheck(t *testing.T) {
	// Real fogona challenge: salt = UID 00C0FFEE001B80E1 + zero pad, serial ZLTEST0001.
	const wire = "0123456789ABCDEF#5A4C5445535430303031006D6F746F2067200000#E8495658209B918404261B431DC111E72E3ADA2008FE00AD547FFC704A2B861A#00C0FFEE001B80E10000000000000000"

	bound := &fastboot.DeviceRecon{UID: "00C0FFEE001B80E1", Serial: "ZLTEST0001"}
	if got := motoUnlockCrossCheck(bound, wire, false); !strings.Contains(got, "device-bound") {
		t.Errorf("matching UID+serial should be device-bound, got %q", got)
	}

	// A cid from another unit: UID and serial both differ.
	foreign := &fastboot.DeviceRecon{UID: "AABBCCDD00112233", Serial: "ZY22XXXXXX"}
	got := motoUnlockCrossCheck(foreign, wire, false)
	if !strings.Contains(got, "FOREIGN") {
		t.Errorf("mismatched UID+serial should be flagged FOREIGN, got %q", got)
	}
	// Redacted verdict must not echo the identifiers.
	if r := motoUnlockCrossCheck(foreign, wire, true); strings.Contains(r, "AABBCCDD") || strings.Contains(r, "ZY22") {
		t.Errorf("redacted verdict leaked an identifier: %q", r)
	}
}
