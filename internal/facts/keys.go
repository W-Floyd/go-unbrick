package facts

// The neutral fact keys, declared once. A fact name is bound to its value type
// in exactly one place; a second key with the same name and a different type is
// the one way to defeat the typing, and it is grep-obvious. Keys for a vendor's
// own formats and types are declared beside that vendor's parsers instead — the
// one-place rule holds, the place is just behind the seam.

import (
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
)

// Leaf sources that are not any one vendor's: a container every OEM ships a zip
// of, an AOSP image format, and the reference data itself. A source is an input
// expressed as the fact you already hold: it resolves to itself, and providers
// name it in Requires like any other fact. Byte-valued sources carry the
// member's contents; source:stock.zip carries the package path, so a provider
// reads only the member it needs. A vendor's own formats are its own sources.
var (
	SourceStockZip = Key[string]("source:stock.zip")
	SourceVBMeta   = Key[[]byte]("source:vbmeta.img", Fmt(ByteLen))

	// SourceCatalog is the reference data itself: keeping it in the Bag is what
	// lets a lookup provider (cid → carrier) stay a pure function of its inputs.
	SourceCatalog = Key[*catalog.Catalog]("source:catalog", Fmt(func(*catalog.Catalog) string { return "(catalog)" }))
)

// Identity and security facts.
var (
	// CID is the carrier CID the bootloader matches a package against.
	CID = Key[uint16]("cid", Fmt(hexCID))
	// SigningCID is the HAB signing/base CID, constant across a device's carrier
	// variants. It is a different fact from CID, not a disagreeing one.
	SigningCID = Key[uint16]("signing_cid", Fmt(hexCID))

	Carrier  = Key[string]("carrier")
	Channel  = Key[string]("channel")
	Codename = Key[string]("codename")
	Model    = Key[string]("model")
	// SKU is the hardware SKU / model number ("XT2413V"), which distinguishes
	// carrier/region variants of one model — unlike Model, the shared consumer
	// name ("moto g play - 2024"). A different fact, not a disagreeing one.
	SKU = Key[string]("sku")
	// SoC is the part the silicon is, named the way the catalog names it.
	// Case-insensitive, since spellings differ by source; a genuinely different
	// part number is worth surfacing.
	SoC = Key[string]("soc", Eq(strings.EqualFold))
	// Platform is what the bootloader calls its own platform ("SM_DIVAR 1.0").
	// A separate fact from SoC on purpose: it is a different namespace for the
	// same silicon, so pairing them would manufacture a conflict out of two
	// correct answers.
	Platform = Key[string]("platform")

	Region          = Key[string]("region")
	CustomerSigned  = Key[bool]("customer_signed")
	SecurityVersion = Key[int]("security_version")
	SoftwareVersion = Key[string]("software_version")

	BuildFingerprint = Key[string]("build_fingerprint")
	// SystemFingerprint is ro.system.build.fingerprint from a partition's
	// build props — the system image's own identity, which in a Treble build is a
	// different namespace from the product BuildFingerprint and legitimately names
	// a different release, so it is a separate fact rather than a disagreement.
	SystemFingerprint = Key[string]("system_fingerprint")
	// SecurityPatch is ro.build.version.security_patch (YYYY-MM-DD): the Android
	// security-patch level the build claims.
	SecurityPatch   = Key[string]("security_patch")
	BuildDate       = Key[string]("build_date")
	ABEnabled       = Key[bool]("ab_enabled")
	LockState       = Key[string]("lock_state")
	Slot            = Key[string]("slot")
	UnlockChallenge = Key[string]("unlock_challenge")
	OTAKey          = Key[string]("ota_key")

	// AVBKey is the SHA-256 of the vbmeta signing (root) public key — the
	// verified-boot key domain, which a device anchors to its fused ROT.
	AVBKey = Key[string]("avb_key")
	// AVBRollbackIndex is the vbmeta rollback index (AVB anti-rollback), distinct
	// from the HAB SecurityVersion though they often track together.
	AVBRollbackIndex = Key[int]("avb_rollback_index")

	// AntiRollbackTable is the per-image anti-rollback version table; all-zero is
	// the shipping baseline.
	AntiRollbackTable = Key[map[string]int]("anti_rollback_table",
		Eq(maps.Equal[map[string]int, map[string]int]), Fmt(rollbackSummary))
	// EnforceAntiRollback is whether the OTA path enforces that table.
	EnforceAntiRollback = Key[bool]("enforce_anti_rollback")
)

// Qualcomm secure-boot identity: what the PBL enforces against every signed
// image. The same three facts come from fuses (Sahara) and from a signed image's
// cert chain, so a device and an image meet here without comparison code.
var (
	// JTAGID is the fused MSM hardware id, uppercase 8 hex ("0016F0E1").
	JTAGID = Key[string]("jtag_id", Eq(strings.EqualFold))
	// OEMID is the OEM signing id, uppercase 4 hex ("02E8" is Motorola).
	OEMID = Key[string]("oem_id", Eq(strings.EqualFold))
	// RootKeyHash is the OEM_PK_HASH: the hash of the signing root certificate,
	// SHA-256 or SHA-384 depending on the SoC generation. Hashes of different
	// lengths are different algorithms, not a disagreement.
	RootKeyHash = Key[string]("root_key_hash", Eq(func(a, b string) bool {
		return len(a) != len(b) || strings.EqualFold(a, b)
	}))
)

func hexCID(v uint16) string { return fmt.Sprintf("0x%04X", v) }

// ByteLen is the rendering for a byte-valued source: how much of it there is.
// Exported because every vendor's own sources want the same one.
func ByteLen(b []byte) string { return fmt.Sprintf("%d bytes", len(b)) }

// rollbackSummary names the bumped images, since the table's whole meaning is
// which images have moved off the baseline.
func rollbackSummary(t map[string]int) string {
	var bumped []string
	for name, v := range t {
		if v != 0 {
			bumped = append(bumped, name)
		}
	}
	if len(bumped) == 0 {
		return fmt.Sprintf("%d images at 0x00 (baseline)", len(t))
	}
	sort.Strings(bumped)
	return fmt.Sprintf("%d images, bumped: %s", len(t), strings.Join(bumped, ", "))
}

// Bumped lists the images an anti-rollback table has moved off the baseline.
func Bumped(t map[string]int) []string {
	var out []string
	for name, v := range t {
		if v != 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
