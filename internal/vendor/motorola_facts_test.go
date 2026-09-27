package vendor

import (
	"archive/zip"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/fastboot"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
)

// stockZip writes a minimal Motorola stock package carrying just the members
// the derivations read.
func stockZip(t *testing.T, members map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "XT2429-1_FOGONA_RETUS.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

const testSigningInfo = `HAB_PRODUCT fogona
HAB_SECURITY_VERSION 18
HAB_CID 50
HAB_CUSTOMER_REGION Retail
OTA_KEY motorola/security/certs/ota.x509.pem
This build is customer signed.
Retail                => 50
RetailLocked          => 51
enforce_anti_rollback_check_in_ota=true
[anti_rollback_version_begin]
xbl.elf=0x00
tz.mbn=0x02
[anti_rollback_version_end]`

// resolveZip ingests a package the way recon does — nothing is told where to
// look, the recognizers decide what each member is — and then resolves.
func resolveZip(t *testing.T, path string, opts facts.Options) (*facts.Bag, *facts.Result) {
	t.Helper()
	b := facts.NewBag()
	ingest(t, b, path)
	return b, FactGraph().ResolveAll(b, opts)
}

func ingest(t *testing.T, b *facts.Bag, path string) {
	t.Helper()
	rs := append(imgfacts.Recognizers(), Recognizers()...)
	if err := imgfacts.Ingest(b, rs, path, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFactsFromStockPackage(t *testing.T) {
	path := stockZip(t, map[string]string{
		"flashfile.xml":    `<flashfile><header><phone_model model="XT2429-1"/><cid_value value="0x0033"/><software_version version="fogona_retail-user-15-U1TF34.100-35-14"/></header></flashfile>`,
		"signing-info.txt": testSigningInfo,
		"vbmeta.img":       "AVB0\x00HAB_META\x00fogona_50\x00",
		"slcf_ccaws.nvm":   "",
	})
	b, res := resolveZip(t, path, facts.Options{})

	if v, ok := facts.Get(b, facts.CID); !ok || v != 0x0033 {
		t.Errorf("cid = 0x%04X %v, want 0x0033 from flashfile.xml", v, ok)
	}
	// The HAB signing CID legitimately differs from the carrier CID. They are
	// different facts, so that difference must not be reported as a disagreement.
	if v, ok := facts.Get(b, facts.SigningCID); !ok || v != 50 {
		t.Errorf("signing_cid = %d %v, want 50", v, ok)
	}
	if v, _ := facts.Get(b, facts.Codename); v != "fogona" {
		t.Errorf("codename = %q", v)
	}
	if v, _ := facts.Get(b, facts.SecurityVersion); v != 18 {
		t.Errorf("security_version = %d", v)
	}
	if v, _ := facts.Get(b, facts.Region); v != "Retail" {
		t.Errorf("region = %q", v)
	}
	if v, _ := facts.Get(b, facts.CustomerSigned); !v {
		t.Error("customer_signed = false")
	}
	if v, _ := facts.Get(b, facts.AntiRollbackTable); len(v) != 2 || v["tz.mbn"] != 2 {
		t.Errorf("anti_rollback_table = %v", v)
	}
	if v, ok := facts.Get(b, SubsidyLock); !ok || v.Locked {
		t.Errorf("subsidy_lock = %+v, want an unlocked (empty) config", v)
	}
	if len(res.Findings) != 0 {
		t.Errorf("clean package should raise nothing: %+v", res.Findings)
	}
}

// Ingestion asks each member what it is. A package that spells its members
// differently — and every OEM eventually does — still yields the same facts.
func TestRecognitionIsNameBlind(t *testing.T) {
	path := stockZip(t, map[string]string{
		"pkg/manifest.txt":  `<cid_value value="0x0033"/><software_version version="x"/>`,
		"pkg/hab-stamp.dat": testSigningInfo,
		"pkg/vb.bin":        "AVB0\x00HAB_META\x00fogona_50\x00",
	})
	b, _ := resolveZip(t, path, facts.Options{})
	if v, ok := facts.Get(b, facts.CID); !ok || v != 0x0033 {
		t.Errorf("cid = 0x%04X %v", v, ok)
	}
	if v, _ := facts.Get(b, facts.SecurityVersion); v != 18 {
		t.Errorf("security_version = %d", v)
	}
	if v, _ := facts.Get(b, facts.Codename); v != "fogona" {
		t.Errorf("codename = %q", v)
	}
}

// An image is not a source of facts merely for being inside a package: a
// package holds dozens, and "the signing chain" of a package is not one chain.
func TestImagesInAPackageAreNotOneImage(t *testing.T) {
	path := stockZip(t, map[string]string{"abl.elf": "\x7fELF" + strings.Repeat("\x00", 64)})
	b, _ := resolveZip(t, path, facts.Options{})
	if b.Has(imgfacts.SourceImage.Name()) {
		t.Error("a member image should not become source:image")
	}
}

// A real package carries two manifests (flashfile.xml + servicefile.xml) and
// two AVB images (vbmeta.img + vbmeta_system.img). Both of each kind are
// recognized as one source, which must not read as a disagreement — a source is
// an input, not a claim — and the fact must still resolve from whichever member
// actually holds it, regardless of order.
func TestMultipleMembersOfOneKindAreNotAConflict(t *testing.T) {
	path := stockZip(t, map[string]string{
		// vbmeta_system has the AVB-ish magic but no HAB_META; the real vbmeta does.
		"vbmeta_system.img": "AVB0\x00no hab meta here\x00",
		"vbmeta.img":        "AVB0\x00HAB_META\x00fogona_50\x00",
		"servicefile.xml":   `<flashfile><cid_value value="0x0033"/></flashfile>`,
		"flashfile.xml":     `<flashfile><cid_value value="0x0033"/><software_version version="x"/></flashfile>`,
	})
	b, res := resolveZip(t, path, facts.Options{})

	for _, f := range res.Findings {
		t.Errorf("no finding expected, got: %s", f.Message)
	}
	if v, ok := facts.Get(b, facts.Codename); !ok || v != "fogona" {
		t.Errorf("codename = %q %v — must resolve from the vbmeta that has HAB_META", v, ok)
	}
	if v, ok := facts.Get(b, facts.SigningCID); !ok || v != 50 {
		t.Errorf("signing_cid = %d %v", v, ok)
	}
	if v, ok := facts.Get(b, facts.CID); !ok || v != 0x0033 {
		t.Errorf("cid = 0x%04X %v", v, ok)
	}
}

// The build-request sheet yields the fingerprint (the same namespace as a
// device's getvar), the marketing name, and the A/B and build-date properties.
func TestFactsFromBuildInfoSheet(t *testing.T) {
	sheet := "BUILD REQUEST INFO:\n" +
		"Build Fingerprint: motorola/fogona_g/fogona:14/U1TFS34.100-35-14-1-21/e7791-698bc2:user/release-keys\n" +
		"Modem Version: HA12_26.35.01.61R\n" +
		"MBM Version: MBM-3.0-fogona-abc-260723-U1TFS34\n" +
		"Model Number: moto g play - 2024\n" +
		"Build Date: Thu Jul 23 13:23:45 CDT 2026\n" +
		"AB Update Enabled: False\n"
	path := stockZip(t, map[string]string{"whatever.info.txt": sheet})
	b, _ := resolveZip(t, path, facts.Options{})

	if v, ok := facts.Get(b, facts.BuildFingerprint); !ok || !strings.HasPrefix(v, "motorola/fogona_g") {
		t.Errorf("build_fingerprint = %q %v", v, ok)
	}
	if v, _ := facts.Get(b, MarketingName); v != "moto g play - 2024" {
		t.Errorf("marketing_name = %q", v)
	}
	if v, ok := facts.Get(b, facts.ABEnabled); !ok || v {
		t.Errorf("ab_enabled = %v %v, want false", v, ok)
	}
	if v, _ := facts.Get(b, ModemVersion); v != "HA12_26.35.01.61R" {
		t.Errorf("modem_version = %q", v)
	}
}

// Integrity: the flashfile's per-member digests are verified only under Verify,
// and a mismatch is an Error.
func TestPackageIntegrityCheck(t *testing.T) {
	good := "hello"
	sum := md5.Sum([]byte(good))
	ff := `<flashfile><header>` +
		`<step MD5="` + hex.EncodeToString(sum[:]) + `" filename="a.img" operation="flash" partition="a"/>` +
		`<step MD5="ffffffffffffffffffffffffffffffff" filename="b.img" operation="flash" partition="b"/>` +
		`</header></flashfile>`
	path := stockZip(t, map[string]string{"flashfile.xml": ff, "a.img": good, "b.img": "wrong"})

	// Default (no verify): the heavy check does not run.
	if _, res := resolveZip(t, path, facts.Options{}); len(res.Findings) != 0 {
		t.Fatalf("integrity must not run without --verify: %+v", res.Findings)
	}
	// Verify: a.img matches, b.img does not → one Error.
	_, res := resolveZip(t, path, facts.Options{Verify: true})
	var errs int
	for _, f := range res.Findings {
		if f.Severity == facts.Error && strings.Contains(f.Message, "b.img") {
			errs++
		}
	}
	if errs != 1 {
		t.Fatalf("want one integrity error for b.img, got %+v", res.Findings)
	}
}

// signing-info and vbmeta both carry the HAB CID; equal values corroborate.
func TestSigningCIDCorroborates(t *testing.T) {
	path := stockZip(t, map[string]string{
		"signing-info.txt": testSigningInfo,
		"vbmeta.img":       "AVB0\x00HAB_META\x00fogona_50\x00",
	})
	b, res := resolveZip(t, path, facts.Options{})
	if got := b.Agreeing(facts.SigningCID.Name()); len(got) != 2 {
		t.Fatalf("both sources should corroborate, got %v", got)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("agreement is not a finding: %+v", res.Findings)
	}
}

// A vbmeta signed for a different base CID than signing-info declares is a real
// disagreement about one fact — the planner finds it with no check written.
func TestSigningCIDDisagreementIsFound(t *testing.T) {
	path := stockZip(t, map[string]string{
		"signing-info.txt": testSigningInfo,
		"vbmeta.img":       "AVB0\x00HAB_META\x00fogona_51\x00",
	})
	b, res := resolveZip(t, path, facts.Options{})
	if v, _ := facts.Get(b, facts.SigningCID); v != 50 {
		t.Errorf("signing_cid = %d, want the attested signing-info value", v)
	}
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Message, "signing_cid disagrees") {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// A HAB_CID that is not the region's CID means mismatched signing inputs — a
// relationship between two facts, so a declared check rather than a conflict.
func TestRegionCIDCheck(t *testing.T) {
	si := strings.Replace(testSigningInfo, "HAB_CID 50", "HAB_CID 51", 1)
	path := stockZip(t, map[string]string{"signing-info.txt": si})
	_, res := resolveZip(t, path, facts.Options{})
	if len(res.Findings) != 1 || res.Findings[0].Severity != facts.Error ||
		!strings.Contains(res.Findings[0].Message, "does not match region Retail") {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// A cid partition dump is writable, so it loses to the package manifest and the
// transplant still shows up.
func TestCIDDumpLosesToManifestButIsSurfaced(t *testing.T) {
	path := stockZip(t, map[string]string{
		"flashfile.xml": `<cid_value value="0x0033"/>`,
	})
	b := facts.NewBag()
	ingest(t, b, path)
	facts.Set(b, SourceCIDDump, CIDBuild(0x0032), facts.Provenance{Source: "cid partition dump", Authority: facts.Attested})
	res := FactGraph().ResolveAll(b, facts.Options{})

	if v, _ := facts.Get(b, facts.CID); v != 0x0033 {
		t.Errorf("cid = 0x%04X, want the attested package value", v)
	}
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Message, "cid disagrees") {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if !strings.Contains(strings.Join(facts.Explain(b, facts.CID.Name()), "\n"), "cid partition") {
		t.Error("--why should still show the losing source")
	}
}

// deviceGraph is what a recon command builds: the neutral device providers plus
// the vendor contributions.
func deviceGraph() *facts.Graph {
	return facts.New(append(fastboot.FactProviders(), Providers()...), Checks())
}

func TestFactsFromDevice(t *testing.T) {
	r := &fastboot.DeviceRecon{
		Serial: "ZLTEST0001", Product: "fogona", SKU: "XT2429-1",
		CarrierID: "0x0032", ChannelID: "RETUS", CurrentSlot: "a",
		CPU: "SM6375", SecureState: "oem_locked",
	}
	r.Set(keyReadSV, &SecurityVersions{VbmetaRIL: 18})

	b := facts.NewBag()
	facts.Set(b, fastboot.SourceRecon, r, facts.Provenance{Source: "getvar all", Authority: facts.Attested})
	res := deviceGraph().ResolveAll(b, facts.Options{})

	if v, ok := facts.Get(b, facts.CID); !ok || v != 0x0032 {
		t.Errorf("cid = 0x%04X %v", v, ok)
	}
	if v, _ := facts.Get(b, facts.Codename); v != "fogona" {
		t.Errorf("codename = %q", v)
	}
	if v, _ := facts.Get(b, facts.Channel); v != "RETUS" {
		t.Errorf("channel = %q", v)
	}
	if v, _ := facts.Get(b, facts.SecurityVersion); v != 18 {
		t.Errorf("security_version = %d", v)
	}
	if v, _ := facts.Get(b, facts.Slot); v != "a" {
		t.Errorf("slot = %q", v)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
}

// A device whose cid partition was transplanted: the package it came from says
// one CID, the bootloader reports another, and the package wins the display.
func TestDeviceCIDLosesToPackage(t *testing.T) {
	path := stockZip(t, map[string]string{"flashfile.xml": `<cid_value value="0x0033"/>`})
	b := facts.NewBag()
	ingest(t, b, path)
	facts.Set(b, fastboot.SourceRecon, &fastboot.DeviceRecon{CarrierID: "0x0032"},
		facts.Provenance{Source: "getvar all", Authority: facts.Attested})
	res := deviceGraph().ResolveAll(b, facts.Options{})

	if v, _ := facts.Get(b, facts.CID); v != 0x0033 {
		t.Errorf("cid = 0x%04X, want the package value", v)
	}
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Message, "cid disagrees") {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// The unlock challenge is bound to this unit's UID and serial; one minted for
// another board comes back as a check failure, not a report-line suffix.
func TestUnlockBindingCheck(t *testing.T) {
	const wire = "0123456789ABCDEF#5A4C5445535430303031006D6F746F2067200000#E8495658209B918404261B431DC111E72E3ADA2008FE00AD547FFC704A2B861A#00C0FFEE001B80E10000000000000000"
	run := func(r *fastboot.DeviceRecon) *facts.Result {
		r.Set(keyUnlockData, wire)
		b := facts.NewBag()
		facts.Set(b, fastboot.SourceRecon, r, facts.Provenance{Source: "getvar all", Authority: facts.Attested})
		return deviceGraph().ResolveAll(b, facts.Options{})
	}

	if res := run(&fastboot.DeviceRecon{UID: "00C0FFEE001B80E1", Serial: "ZLTEST0001"}); len(res.Findings) != 0 {
		t.Fatalf("a device-bound challenge is not a finding: %+v", res.Findings)
	}
	res := run(&fastboot.DeviceRecon{UID: "AABBCCDD00112233", Serial: "ZY22XXXXXX"})
	if len(res.Findings) != 1 || res.Findings[0].Severity != facts.Error ||
		!strings.Contains(res.Findings[0].Message, "FOREIGN cid") {
		t.Fatalf("findings = %+v", res.Findings)
	}
	// The message names the fields, never the identifiers — recon masks those.
	if m := res.Findings[0].Message; strings.Contains(m, "AABBCCDD") || strings.Contains(m, "ZY22") {
		t.Errorf("finding leaked an identifier: %q", m)
	}
}

func TestCarrierFromCatalogIsChained(t *testing.T) {
	cat, err := catalog.Default()
	if err != nil || cat == nil {
		t.Skip("no catalog available")
	}
	path := stockZip(t, map[string]string{"flashfile.xml": `<cid_value value="0x0032"/>`})
	b := facts.NewBag()
	ingest(t, b, path)
	facts.Set(b, facts.SourceCatalog, cat, facts.Provenance{Source: "catalog", Authority: facts.Reference})
	FactGraph().ResolveAll(b, facts.Options{})

	name, ok := facts.Get(b, facts.Carrier)
	if !ok {
		t.Fatal("carrier should chain cid → catalog")
	}
	why := strings.Join(facts.Explain(b, facts.Carrier.Name()), "\n")
	if !strings.Contains(why, "from cid") {
		t.Errorf("--why carrier should show the chain:\n%s", why)
	}
	t.Logf("carrier %q", name)
}
