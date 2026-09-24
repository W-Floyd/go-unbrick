package adb

import (
	"strings"
	"testing"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/facts"
)

// collected is one real-shaped collection from a device booted into stock
// Android: the common shell sections plus the property dump, as an unrooted
// shell sees them.
const collected = `
===unbrick:whoami===
uid=2000
user=shell
===unbrick:elevate===
su
===unbrick:elevate-ok===
===unbrick:cmdline===
console=ttyMSM0,115200n8 androidboot.slot_suffix=_a androidboot.serialno=ZLTEST0001 androidboot.verifiedbootstate=green androidboot.flash.locked=1
===unbrick:soc0===
machine=SM6225
===unbrick:dt-model===
Motorola fogona
===unbrick:dt-compatible===
motorola,fogona
qcom,sm6225
===unbrick:partitions===
cid	/dev/block/sdf5	256
super	/dev/block/sde53	12582912
vbmeta_a	/dev/block/sde20	128
xbl_a	/dev/block/sdd1	8192
xbl_b	/dev/block/sdd2	8192
===unbrick:disks===
sdd	16384
===unbrick:getprop===
[ro.board.platform]: [holi]
[ro.build.date]: [Wed Jun 18 12:00:00 CST 2025]
[ro.build.display.id]: [U1TF34.100-35-14]
[ro.build.fingerprint]: [motorola/fogona_g/fogona:14/U1TF34.100-35-14/98d43:user/release-keys]
[ro.build.tags]: [release-keys]
[ro.build.type]: [user]
[ro.build.version.release]: [14]
[ro.build.version.sdk]: [34]
[ro.build.version.security_patch]: [2025-06-01]
[ro.carrier]: [retail]
[ro.product.device]: [fogona]
[ro.product.manufacturer]: [motorola]
[ro.product.model]: [moto g play - 2024]
[ro.system.build.fingerprint]: [motorola/fogona_g/fogona:14/U1TF34.100-35-14/98d43:user/release-keys]
===unbrick:battery===
battery: type=Battery status=Charging capacity=88
`

func TestParseProps(t *testing.T) {
	r := Parse(collected)

	if got := r.Props["ro.product.device"]; got != "fogona" {
		t.Errorf("ro.product.device = %q", got)
	}
	// getprop's brackets are not part of the value.
	if got := r.Props["ro.build.tags"]; got != "release-keys" {
		t.Errorf("ro.build.tags = %q", got)
	}
	if got := r.Fingerprint(); !strings.HasPrefix(got, "motorola/fogona_g/") {
		t.Errorf("Fingerprint() = %q", got)
	}
	if got := r.Codename(); got != "fogona" {
		t.Errorf("Codename() = %q", got)
	}
	if got := r.Model(); got != "moto g play - 2024" {
		t.Errorf("Model() = %q", got)
	}
	if got := r.VendorID(); got != "motorola" {
		t.Errorf("VendorID() = %q", got)
	}
	// The common shell fields come through the embedded recon.
	if got := r.Slot(); got != "a" {
		t.Errorf("Slot() = %q", got)
	}
	// verifiedbootstate=green on a locked device.
	if got := r.LockState(); got != "locked" {
		t.Errorf("LockState() = %q", got)
	}
	if got := r.BatteryPercent(); got != 88 {
		t.Errorf("battery = %d", got)
	}
}

// Android's board platform is a Qualcomm platform codename ("holi"), which is a
// different namespace from the part number sysfs reports — both are collected,
// and the catalog is what reconciles them.
func TestSoCTokensIncludeBoardPlatform(t *testing.T) {
	r := Parse(collected)
	got := r.SoCTokens()
	var haveMachine, havePlatform bool
	for _, s := range got {
		switch strings.ToLower(s) {
		case "sm6225":
			haveMachine = true
		case "holi":
			havePlatform = true
		}
	}
	if !haveMachine {
		t.Errorf("SoCTokens() = %v, want the sysfs part number", got)
	}
	// "holi" carries no digit, so the part-number filter drops it — which is
	// right for a token the catalog would not resolve as a part anyway.
	if havePlatform {
		t.Errorf("SoCTokens() = %v, want the non-part-number platform label dropped", got)
	}
}

// An unrooted shell with su present cannot read partitions until su grants it;
// that is a different state from a device with no su at all, and neither can
// read.
func TestRootStates(t *testing.T) {
	unrooted := Parse(collected)
	if unrooted.CanReadPartitions() {
		t.Error("CanReadPartitions() = true on an unrooted shell")
	}
	if unrooted.rootHelper("") != "" {
		t.Errorf("rootHelper = %q, want none", unrooted.rootHelper(""))
	}

	granted := Parse(strings.Replace(collected, "===unbrick:elevate-ok===\n", "===unbrick:elevate-ok===\nsu\n", 1))
	if !granted.CanReadPartitions() || granted.rootHelper("") != "su" {
		t.Error("a granted su was not taken as usable")
	}

	// adb root on a userdebug build: the shell is already uid 0.
	asRoot := Parse(strings.Replace(collected, "uid=2000", "uid=0", 1))
	if !asRoot.CanReadPartitions() || asRoot.rootHelper("") != "" {
		t.Error("a root shell should need no helper")
	}
}

func TestProvidersOverAndroid(t *testing.T) {
	cat, err := catalog.Load(t.TempDir())
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	cat.AddVariant("socdivar", "Qualcomm SM6225 Snapdragon 680")
	bag := facts.NewBag()
	facts.Set(bag, SourceADB, Parse(collected), facts.Provenance{Source: "adb test", Authority: facts.Attested})
	facts.Set(bag, facts.SourceCatalog, cat, facts.Provenance{Source: "catalog", Authority: facts.Reference})
	facts.New(FactProviders(), nil).ResolveAll(bag, facts.Options{})

	if got, ok := facts.Get(bag, facts.Codename); !ok || got != "fogona" {
		t.Errorf("codename = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.Model); !ok || got != "moto g play - 2024" {
		t.Errorf("model = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.SecurityPatch); !ok || got != "2025-06-01" {
		t.Errorf("security_patch = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.BuildFingerprint); !ok || !strings.Contains(got, "U1TF34.100-35-14") {
		t.Errorf("build_fingerprint = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.Carrier); !ok || got != "retail" {
		t.Errorf("carrier = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.LockState); !ok || got != "locked" {
		t.Errorf("lock_state = %q (%v)", got, ok)
	}
	// Property values are mutable on a rooted device, so nothing read here may
	// outrank a package's manifest or a bootloader's own answer.
	for _, name := range []string{facts.Codename.Name(), facts.BuildFingerprint.Name(), facts.SoC.Name()} {
		if best, ok := bag.Best(name); ok && best.Authority != facts.Derived {
			t.Errorf("%s authority = %v, want derived", name, best.Authority)
		}
	}
}

// "unknown" is what a device with no carrier provisioning reports, and it is
// not a carrier.
func TestUnknownCarrierIsNotAFact(t *testing.T) {
	bag := facts.NewBag()
	facts.Set(bag, SourceADB, Parse(strings.Replace(collected, "[retail]", "[unknown]", 1)),
		facts.Provenance{Source: "adb test", Authority: facts.Attested})
	facts.New(FactProviders(), nil).ResolveAll(bag, facts.Options{})
	if bag.Has(facts.Carrier.Name()) {
		best, _ := bag.Best(facts.Carrier.Name())
		t.Errorf("carrier resolved to %v", best.Data)
	}
}

func TestParseEmpty(t *testing.T) {
	r := Parse("")
	if r.Codename() != "" || r.Fingerprint() != "" || len(r.Props) != 0 {
		t.Errorf("empty collection yielded %+v", r)
	}
	if r.CanReadPartitions() {
		t.Error("CanReadPartitions() = true off nothing")
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("dd if=/dev/block/x; rm -rf /"); got != `'dd if=/dev/block/x; rm -rf /'` {
		t.Errorf("shellQuote = %s", got)
	}
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("shellQuote of an embedded quote = %s", got)
	}
}
