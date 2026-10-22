package facts

// The neutral fact keys, declared once. A fact name is bound to its value type
// in exactly one place; a second key with the same name and a different type is
// the one way to defeat the typing, and it is grep-obvious. Keys for a vendor's
// own formats and types are declared beside that vendor's parsers instead — the
// one-place rule holds, the place is just behind the seam.

import (
	"fmt"
	"maps"
	"slices"
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
	// AVBProtected is the partitions the package's vbmeta descriptors cover (hash,
	// hash tree, or chained to another key), sorted and joined with ", ". A
	// partition not among them is never verified by AVB, whenever it is loaded.
	AVBProtected = Key[string]("avb_protected")

	// AntiRollbackTable is the per-image anti-rollback version table; all-zero is
	// the shipping baseline.
	AntiRollbackTable = Key[map[string]int]("anti_rollback_table",
		Eq(maps.Equal[map[string]int, map[string]int]), Fmt(rollbackSummary))
	// EnforceAntiRollback is whether the OTA path enforces that table.
	EnforceAntiRollback = Key[bool]("enforce_anti_rollback")
)

// What a build's partition images state about the device and how it is
// secured: vendor and odm build props, the vendor fstab, the SELinux signer
// map.
var (
	// SKUModels maps each hardware SKU a build serves (the odm per-SKU prop
	// file's name) to its model number, the one on the device's label.
	SKUModels = Key[map[string]string]("sku_models", Eq(maps.Equal[map[string]string, map[string]string]), Fmt(skuSummary))
	// BoardPlatform is ro.board.platform, the SoC family the vendor image is
	// built for ("bengal"). A third namespace beside SoC and Platform.
	BoardPlatform = Key[string]("board_platform")
	// BluetoothFirmware is the Bluetooth chip families a build ships firmware
	// for. The HAL picks among them from the chip's own version at runtime, so
	// this bounds the chip rather than naming it.
	BluetoothFirmware = Key[string]("bluetooth_firmware")
	// FirstAPILevel is the API level the device launched with.
	FirstAPILevel = Key[int]("first_api_level")
	// VendorRelease and VendorSecurityPatch are the vendor image's own Android
	// version and patch level, which can trail the system image's: a
	// frozen-vendor build updates only system.
	VendorRelease       = Key[string]("vendor_release")
	VendorSecurityPatch = Key[string]("vendor_security_patch")
	// DataEncryption is how userdata is encrypted: the fstab's fileencryption=
	// (file-based) value, or "full-disk" for forceencrypt.
	DataEncryption = Key[string]("data_encryption")
	// MetadataEncryption is whether filesystem metadata is encrypted too.
	MetadataEncryption = Key[bool]("metadata_encryption")
	// GSIKeys are the GSI public keys system verifies against beside the
	// build's own (avb_keys), which is what lets a generic system image boot.
	GSIKeys = Key[[]string]("gsi_keys", Eq(slices.Equal[[]string, string]), Fmt(func(k []string) string { return strings.Join(k, ", ") }))
	// PlatformCert is the SHA-256 of the cert system apps are signed with
	// (the "platform" signer); PlatformSigner is its subject's CN.
	PlatformCert   = Key[string]("platform_cert", Eq(strings.EqualFold))
	PlatformSigner = Key[string]("platform_signer")
	// AOSPTestKeys names the SELinux signer roles whose cert is one of AOSP's
	// public test keys, with which anyone can sign as that role.
	AOSPTestKeys = Key[[]string]("aosp_test_keys", Eq(slices.Equal[[]string, string]), Fmt(func(k []string) string { return strings.Join(k, ", ") }))
)

// skuSummary lists model numbers with the SKUs that share each.
func skuSummary(m map[string]string) string {
	by := map[string][]string{}
	for sku, model := range m {
		by[model] = append(by[model], sku)
	}
	var out []string
	for model, skus := range by {
		sort.Strings(skus)
		out = append(out, fmt.Sprintf("%s (%s)", model, strings.Join(skus, ", ")))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

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
