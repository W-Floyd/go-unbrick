package vendor

// Motorola's contribution to the fact-derivation graph: which fact each of its
// parsers can produce, from which source, at what cost and authority. The
// parsers themselves are unchanged — a rule is only an edge declaration with the
// parser as its body, which is what lets the planner chain them, cross-check a
// fact two sources both produce, and explain how it got there.

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/fastboot"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// Motorola's own leaf sources and vendor-typed facts. They are declared here,
// beside the parsers that read them, rather than in the neutral key file: the
// package manifest, the HAB signing stamp, the subsidy config and the cid
// partition are Motorola formats, and the core has no business naming them.
// facts.Key still binds each name to one type, across the seam.
var (
	SourceFlashfile   = facts.Key[[]byte]("source:flashfile.xml", facts.Fmt(facts.ByteLen))
	SourceSigningInfo = facts.Key[[]byte]("source:signing-info.txt", facts.Fmt(facts.ByteLen))
	SourceSLCF        = facts.Key[[]byte]("source:slcf", facts.Fmt(facts.ByteLen))
	SourceCIDDump     = facts.Key[[]byte]("source:cid.dump", facts.Fmt(facts.ByteLen))
	SourceBuildInfo   = facts.Key[[]byte]("source:info.txt", facts.Fmt(facts.ByteLen))

	SubsidyLock = facts.Key[*SLCFConfig]("subsidy_lock", facts.Eq(slcfEqual), facts.Fmt(slcfSummary))
	// MarketingName is the consumer product name ("moto g play - 2024"). A
	// separate fact from model (the XT SKU) and codename (fogona): three names
	// for one device in three namespaces, so pairing them would be a false
	// conflict, not a corroboration.
	MarketingName = facts.Key[string]("marketing_name")
	// ModemVersion and MBMVersion are the shipped component versions the info.txt
	// sheet records — the baseband and the bootloader (MBM) builds.
	ModemVersion = facts.Key[string]("modem_version")
	MBMVersion   = facts.Key[string]("mbm_version")
	// SubsidyLockName is the config a package says it provisions; SubsidyLock is
	// what that config turned out to contain. A package can state the first
	// without shipping the second.
	SubsidyLockName = facts.Key[string]("subsidy_lock_name")
)

// FactProviders implements FactDeriver.
func (motorola) FactProviders() []facts.Provider {
	return append(motoDeriveRules(), motoDeviceRules()...)
}

// FactRecognizers implements FactRecognizer: what Motorola's own formats look
// like. Each one is decided by handing the bytes to the parser that claims them
// — a manifest is a manifest because ParseFlashfile finds a manifest in it, not
// because a member is called flashfile.xml. Names only break ties that content
// cannot (an empty subsidy config is an empty file).
func (motorola) FactRecognizers() []facts.Recognizer {
	return []facts.Recognizer{func(b *facts.Bag, f facts.File) []string {
		set := func(k facts.Fact[[]byte]) []string {
			facts.Set(b, k, f.Data, facts.Provenance{Source: f.From, Authority: facts.Attested})
			return []string{k.Name()}
		}
		switch {
		case isText(f.Data) && ParseSigningInfo(f.Data) != nil:
			return set(SourceSigningInfo)
		case isText(f.Data) && looksLikeFlashfile(f.Data):
			return set(SourceFlashfile)
		case isCIDImage(f.Data):
			return set(SourceCIDDump)
		case looksLikeSLCF(f.Name, f.Data):
			return set(SourceSLCF)
		case isText(f.Data) && ParseBuildInfo(f.Data) != nil:
			return set(SourceBuildInfo)
		}
		return nil
	}}
}

// isText gates the text recognizers, which would otherwise line-split every
// image in a package to learn nothing. A manifest is small and has no NULs.
func isText(data []byte) bool {
	if len(data) == 0 || len(data) > 1<<20 {
		return false
	}
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	return !bytes.ContainsRune(head, 0)
}

// looksLikeFlashfile reports whether the bytes are a Motorola package manifest —
// judged by whether the manifest parser gets anything out of them, since what
// makes it one is what it declares, not its root element or its filename.
func looksLikeFlashfile(data []byte) bool {
	ff := ParseFlashfile(data)
	if ff.CIDValue != "" || ff.SoftwareVersion != "" || ff.SubsidyLock != "" || ff.CIDTemplate != "" {
		return true
	}
	// A manifest that only lists flash steps is still a manifest — and its
	// per-member digests are what the integrity check verifies.
	return len(FlashfileDigests(data)) > 0
}

// isCIDImage reports whether the bytes are a cid partition image of either
// version — the 0x00F0 magic, sized as the version-0 template or longer.
func isCIDImage(data []byte) bool {
	v, ok := CIDVersion(data)
	return ok && (v >= 2 || len(data) == CIDSize)
}

// looksLikeSLCF reports whether the bytes are a subsidy config. An empty .nvm is
// the retail default — no content to recognize, so the extension decides — while
// a locked one is hex NV-write records that must parse.
func looksLikeSLCF(name string, data []byte) bool {
	if !strings.HasSuffix(strings.ToLower(name), ".nvm") {
		return false
	}
	cfg, err := ParseSLCF(data)
	return err == nil && cfg != nil
}

// motoDeviceRules read Motorola's own answers off a collected recon: the CID and
// channel the bootloader reports, and what its OEM probes returned. The paced
// round trips were already spent to produce source:device.recon, so these price
// as the field reads they are.
func motoDeviceRules() []facts.Provider {
	return []facts.Provider{
		// getvar cid reports the cid *partition*, which is writable. It is the
		// device's own claim, not an attestation: a package manifest outranks it,
		// which is exactly what makes a transplanted cid visible.
		fromDevice(facts.CID, facts.Derived, "getvar cid",
			func(r *fastboot.DeviceRecon) (uint16, bool) {
				if r.CarrierID == "" {
					return 0, false
				}
				v, err := parseCIDValue(r.CarrierID)
				return v, err == nil
			}),
		fromDevice(facts.Channel, facts.Attested, "getvar channelid",
			func(r *fastboot.DeviceRecon) (string, bool) { return r.ChannelID, r.ChannelID != "" }),
		// The anti-rollback index the running firmware enforces, against which a
		// package's HAB_SECURITY_VERSION is the baseline it was signed at.
		fromDevice(facts.SecurityVersion, facts.Derived, "oem read_sv (vbmeta RIL)",
			func(r *fastboot.DeviceRecon) (int, bool) {
				sv := MotoSecurityVersions(r)
				return svOrZero(sv), sv != nil && sv.VbmetaRIL >= 0
			}),
		fromDevice(facts.UnlockChallenge, facts.Attested, "oem get_unlock_data",
			func(r *fastboot.DeviceRecon) (string, bool) {
				w := MotoUnlockData(r)
				return w, w != ""
			}),
	}
}

func svOrZero(sv *SecurityVersions) int {
	if sv == nil {
		return 0
	}
	return sv.VbmetaRIL
}

// fromDevice is a rule reading one field off the collected recon.
func fromDevice[T any](out facts.Fact[T], level facts.Level, source string,
	fn func(*fastboot.DeviceRecon) (T, bool)) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{fastboot.SourceRecon.Name()}, Price: 1, Level: level,
		Fn: func(b *facts.Bag) (bool, error) {
			r, ok := facts.Get(b, fastboot.SourceRecon)
			if !ok || r == nil {
				return false, nil
			}
			v, ok := fn(r)
			if !ok {
				return false, nil
			}
			facts.Set(b, out, v, facts.Provenance{Source: source, Authority: level})
			return true, nil
		},
	}
}

func motoDeriveRules() []facts.Provider {
	return []facts.Provider{
		// flashfile.xml: the manifest the bootloader matches a package against.
		parse(facts.CID, SourceFlashfile, facts.Attested, "flashfile.xml cid_value",
			func(b *facts.Bag, data []byte) (uint16, bool) {
				v := ParseFlashfile(data).CIDValue
				if v == "" {
					return 0, false
				}
				n, err := parseCIDValue(v)
				return n, err == nil
			}),
		parse(facts.SoftwareVersion, SourceFlashfile, facts.Attested, "flashfile.xml software_version",
			func(b *facts.Bag, data []byte) (string, bool) {
				v := ParseFlashfile(data).SoftwareVersion
				return v, v != ""
			}),
		// Which subsidy config the package provisions, by name. A package that
		// ships no slcf member still says here that it locks one.
		parse(SubsidyLockName, SourceFlashfile, facts.Attested, "flashfile.xml subsidy_lock_config",
			func(b *facts.Bag, data []byte) (string, bool) {
				v := ParseFlashfile(data).SubsidyLock
				return v, v != ""
			}),

		// vbmeta HAB_META: the device binding the build was signed for. Its CID is
		// the signing/base value, a different fact from the carrier CID — not a
		// disagreeing one. HAB_PRODUCT in signing-info is deliberately not a second
		// codename source: it is the HAB product name, a different namespace, and
		// pairing them would manufacture a conflict out of two correct values.
		parse(facts.Codename, facts.SourceVBMeta, facts.Attested, "vbmeta HAB_META",
			func(b *facts.Bag, data []byte) (string, bool) {
				m, ok := ParseHABMeta(data)
				return m.Codename, ok
			}),
		parse(facts.SigningCID, facts.SourceVBMeta, facts.Derived, "vbmeta HAB_META",
			func(b *facts.Bag, data []byte) (uint16, bool) {
				m, ok := ParseHABMeta(data)
				return m.CID, ok
			}),

		// signing-info.txt: the HAB binding and the anti-rollback baseline.
		parse(facts.SigningCID, SourceSigningInfo, facts.Attested, "signing-info.txt HAB_CID",
			func(b *facts.Bag, data []byte) (uint16, bool) {
				si := ParseSigningInfo(data)
				if si == nil || si.HABCID < 0 {
					return 0, false
				}
				return uint16(si.HABCID), true
			}),
		parse(facts.SecurityVersion, SourceSigningInfo, facts.Attested, "signing-info.txt HAB_SECURITY_VERSION",
			func(b *facts.Bag, data []byte) (int, bool) {
				si := ParseSigningInfo(data)
				if si == nil || si.SecurityVersion < 0 {
					return 0, false
				}
				return si.SecurityVersion, true
			}),
		parse(facts.Region, SourceSigningInfo, facts.Attested, "signing-info.txt HAB_CUSTOMER_REGION",
			func(b *facts.Bag, data []byte) (string, bool) {
				si := ParseSigningInfo(data)
				if si == nil || si.Region == "" {
					return "", false
				}
				return si.Region, true
			}),
		parse(facts.CustomerSigned, SourceSigningInfo, facts.Attested, "signing-info.txt",
			func(b *facts.Bag, data []byte) (bool, bool) {
				si := ParseSigningInfo(data)
				return si != nil && si.CustomerSigned, si != nil
			}),
		parse(facts.OTAKey, SourceSigningInfo, facts.Attested, "signing-info.txt OTA_KEY",
			func(b *facts.Bag, data []byte) (string, bool) {
				si := ParseSigningInfo(data)
				if si == nil || si.OTAKey == "" {
					return "", false
				}
				return si.OTAKey, true
			}),
		parse(facts.AntiRollbackTable, SourceSigningInfo, facts.Attested, "signing-info.txt anti_rollback_version",
			func(b *facts.Bag, data []byte) (map[string]int, bool) {
				si := ParseSigningInfo(data)
				if si == nil || len(si.Rollback) == 0 {
					return nil, false
				}
				return si.Rollback, true
			}),
		parse(facts.EnforceAntiRollback, SourceSigningInfo, facts.Attested, "signing-info.txt enforce_anti_rollback_check_in_ota",
			func(b *facts.Bag, data []byte) (bool, bool) {
				si := ParseSigningInfo(data)
				return si != nil && si.EnforceOTARoll, si != nil
			}),

		// A cid partition dump, any version. Derived, not Attested, on purpose: the
		// partition is writable and a v2 record's signature is not checked offline,
		// so a transplanted cid loses to a package's attested value while still
		// surfacing as a disagreement.
		parse(facts.CID, SourceCIDDump, facts.Derived, "cid partition",
			func(b *facts.Bag, data []byte) (uint16, bool) {
				return CIDCarrier(data)
			}),

		// What the CID means. The package-attested table is the answer; the
		// vendor-claimed forum table only speaks where that one is silent, so it
		// cannot contradict it.
		lookup(facts.Attested, "catalog carrier_ids", func(cid string, c *catalogLookup) string {
			return c.name(cid)
		}),
		lookup(facts.Reference, "catalog cid_reference (vendor-claimed)", func(cid string, c *catalogLookup) string {
			if c.name(cid) != "" {
				return "" // attested wins outright; a fallback is not a second opinion
			}
			return c.reference(cid)
		}),

		// The subsidy lock the package provisions.
		parse(SubsidyLock, SourceSLCF, facts.Attested, "slcf_*.nvm",
			func(b *facts.Bag, data []byte) (*SLCFConfig, bool) {
				cfg, err := ParseSLCF(data)
				return cfg, err == nil
			}),

		// The build-request sheet: the one member that carries the AOSP build
		// fingerprint in the clear (the same identity a device reports over
		// getvar), plus the marketing name and component versions.
		parse(facts.BuildFingerprint, SourceBuildInfo, facts.Attested, "info.txt Build Fingerprint",
			func(b *facts.Bag, data []byte) (string, bool) {
				bi := ParseBuildInfo(data)
				return bi.Fingerprint, bi != nil && bi.Fingerprint != ""
			}),
		parse(MarketingName, SourceBuildInfo, facts.Attested, "info.txt Model Number",
			func(b *facts.Bag, data []byte) (string, bool) {
				bi := ParseBuildInfo(data)
				return bi.MarketingName, bi != nil && bi.MarketingName != ""
			}),
		parse(ModemVersion, SourceBuildInfo, facts.Attested, "info.txt Modem Version",
			func(b *facts.Bag, data []byte) (string, bool) {
				bi := ParseBuildInfo(data)
				return bi.Modem, bi != nil && bi.Modem != ""
			}),
		parse(MBMVersion, SourceBuildInfo, facts.Attested, "info.txt MBM Version",
			func(b *facts.Bag, data []byte) (string, bool) {
				bi := ParseBuildInfo(data)
				return bi.MBM, bi != nil && bi.MBM != ""
			}),
		parse(facts.BuildDate, SourceBuildInfo, facts.Attested, "info.txt Build Date",
			func(b *facts.Bag, data []byte) (string, bool) {
				bi := ParseBuildInfo(data)
				return bi.BuildDate, bi != nil && bi.BuildDate != ""
			}),
		parse(facts.ABEnabled, SourceBuildInfo, facts.Attested, "info.txt AB Update Enabled",
			func(b *facts.Bag, data []byte) (bool, bool) {
				bi := ParseBuildInfo(data)
				if bi == nil || bi.ABUpdate == "" {
					return false, false
				}
				return strings.EqualFold(bi.ABUpdate, "true"), true
			}),
	}
}

// parse is a rule whose body is one parser over one byte-valued source. It tries
// every member that was recognized as that source and takes the first that
// yields, so a package carrying two manifests or two vbmeta partitions still
// resolves from the one that actually holds the field — the others simply
// decline, they do not conflict.
func parse[T any](out facts.Fact[T], in facts.Fact[[]byte], level facts.Level, source string,
	fn func(*facts.Bag, []byte) (T, bool)) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{in.Name()}, Price: 1, Level: level,
		Fn: func(b *facts.Bag) (bool, error) {
			for _, data := range facts.GetAll(b, in) {
				if v, ok := fn(b, data); ok {
					facts.Set(b, out, v, facts.Provenance{Source: source, Authority: level})
					return true, nil
				}
			}
			return false, nil
		},
	}
}

// catalogLookup is the CID→name side of the catalog, bound to this vendor.
type catalogLookup struct{ name, reference func(string) string }

// lookup is a rule that names a CID from reference data. Both the CID and the
// catalog are facts, so the rule stays a pure function of its inputs.
func lookup(level facts.Level, source string, fn func(cid string, c *catalogLookup) string) facts.Rule {
	return facts.Rule{
		Out: facts.Carrier.Name(),
		In:  []string{facts.CID.Name(), facts.SourceCatalog.Name()},
		// A map lookup, but only after the CID itself was derived.
		Price: 1, Level: level,
		Fn: func(b *facts.Bag) (bool, error) {
			cid, ok := facts.Get(b, facts.CID)
			if !ok {
				return false, nil
			}
			cat, ok := facts.Get(b, facts.SourceCatalog)
			if !ok || cat == nil {
				return false, nil
			}
			id := motorola{}.ID()
			name := fn(fmt.Sprintf("0x%04X", cid), &catalogLookup{
				name:      func(c string) string { return cat.CarrierIDName(id, c) },
				reference: func(c string) string { return cat.CarrierIDReference(id, c) },
			})
			if name == "" {
				return false, nil
			}
			facts.Set(b, facts.Carrier, name, facts.Provenance{Source: source, Authority: level})
			return true, nil
		},
	}
}

// FactChecks implements FactChecker.
func (motorola) FactChecks() []facts.Check {
	return []facts.Check{
		// Package integrity: the flashfile declares an MD5/SHA1 for every member it
		// flashes. Verifying them means hashing the whole package (gigabytes), so
		// it is Heavy — it runs only under --verify. A mismatch means a corrupt or
		// tampered download; the boot chain it would write is not the signed one.
		facts.CheckFunc{
			On:    []string{facts.SourceStockZip.Name(), SourceFlashfile.Name()},
			Heavy: true,
			Fn:    verifyPackageIntegrity,
		},
		// The unlock challenge is minted against this unit's UID and serial. A
		// challenge that does not match them came from another board's cid record,
		// so the code it yields would not unlock this device. Field names only —
		// the identifiers themselves are per-device and the report masks them.
		facts.CheckFunc{
			On: []string{facts.UnlockChallenge.Name(), fastboot.SourceRecon.Name()},
			Fn: func(b *facts.Bag) []facts.Finding {
				r, _ := facts.Get(b, fastboot.SourceRecon)
				wire, _ := facts.Get(b, facts.UnlockChallenge)
				if r == nil {
					return nil
				}
				_, foreign := motoUnlockBinding(r, wire)
				if len(foreign) == 0 {
					return nil
				}
				fields := make([]string, 0, len(foreign))
				for _, f := range foreign {
					fields = append(fields, f.Field)
				}
				v, _ := b.Best(facts.UnlockChallenge.Name())
				return []facts.Finding{{
					Severity: facts.Error,
					Facts:    []string{facts.UnlockChallenge.Name(), facts.CID.Name()},
					Message: "FOREIGN cid — the unlock challenge is provisioned for another device (" +
						strings.Join(fields, ", ") + " mismatch); a code minted from it will not unlock this one",
					Values: []facts.Value{v},
				}}
			},
		},
		// signing-info states both the customer region and the region→CID map it
		// was signed under; a HAB_CID that is not the map's entry for that region
		// means the package was assembled from mismatched signing inputs.
		facts.CheckFunc{
			On: []string{facts.SigningCID.Name(), facts.Region.Name(), SourceSigningInfo.Name()},
			Fn: func(b *facts.Bag) []facts.Finding {
				data, _ := facts.Get(b, SourceSigningInfo)
				si := ParseSigningInfo(data)
				if si == nil || len(si.RegionCIDs) == 0 {
					return nil
				}
				region, _ := facts.Get(b, facts.Region)
				want, ok := si.RegionCIDs[region]
				got, _ := facts.Get(b, facts.SigningCID)
				if !ok || want == int(got) {
					return nil
				}
				v, _ := b.Best(facts.SigningCID.Name())
				return []facts.Finding{{
					Severity: facts.Error,
					Facts:    []string{facts.SigningCID.Name(), facts.Region.Name()},
					Message: fmt.Sprintf("signing CID 0x%04X does not match region %s, which signing-info maps to 0x%04X",
						got, region, want),
					Values: []facts.Value{v},
				}}
			},
		},
	}
}

// verifyPackageIntegrity hashes every member the flashfile names and compares it
// to the declared digest. A mismatch or a missing member is an Error; a clean
// pass is a single Info so --verify says so out loud rather than silently.
func verifyPackageIntegrity(b *facts.Bag) []facts.Finding {
	path, ok := facts.Get(b, facts.SourceStockZip)
	if !ok {
		return nil
	}
	var digests []MemberDigest
	for _, data := range facts.GetAll(b, SourceFlashfile) {
		digests = FlashfileDigests(data)
		if len(digests) > 0 {
			break
		}
	}
	if len(digests) == 0 {
		return nil
	}
	var findings []facts.Finding
	ok0 := 0
	for _, d := range digests {
		_, data, err := srcfile.Open(path, d.Name)
		if err != nil {
			findings = append(findings, facts.Finding{
				Severity: facts.Error,
				Facts:    []string{facts.SourceStockZip.Name()},
				Message:  fmt.Sprintf("integrity: %s is named in the manifest but not in the package", d.Name),
			})
			continue
		}
		got := hashHex(d.Algo, data)
		if got != d.Hex {
			findings = append(findings, facts.Finding{
				Severity: facts.Error,
				Facts:    []string{facts.SourceStockZip.Name()},
				Message: fmt.Sprintf("integrity: %s %s is %s, manifest declares %s — corrupt or tampered",
					d.Name, strings.ToUpper(d.Algo), got, d.Hex),
			})
			continue
		}
		ok0++
	}
	if len(findings) == 0 {
		findings = append(findings, facts.Finding{
			Severity: facts.Info,
			Facts:    []string{facts.SourceStockZip.Name()},
			Message:  fmt.Sprintf("integrity: all %d members match the manifest digests", ok0),
		})
	}
	return findings
}

func hashHex(algo string, data []byte) string {
	switch algo {
	case "sha1":
		s := sha1.Sum(data)
		return hex.EncodeToString(s[:])
	default:
		s := md5.Sum(data)
		return hex.EncodeToString(s[:])
	}
}

// slcfEqual compares two subsidy configs by what the lock means — its state,
// control-key length and locked networks — not by parse incidentals.
func slcfEqual(a, b *SLCFConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Locked != b.Locked || a.ControlKeyDigits != b.ControlKeyDigits || len(a.PLMNs) != len(b.PLMNs) {
		return false
	}
	for i := range a.PLMNs {
		if a.PLMNs[i] != b.PLMNs[i] {
			return false
		}
	}
	return true
}

func slcfSummary(c *SLCFConfig) string {
	if c == nil || !c.Locked {
		return "none (retail)"
	}
	nets := make([]string, 0, len(c.PLMNs))
	for _, p := range c.PLMNs {
		nets = append(nets, p.String())
	}
	return fmt.Sprintf("LOCKED, %d-digit key, networks: %s", c.ControlKeyDigits, strings.Join(nets, ", "))
}

// parseCIDValue reads a flashfile cid_value ("0x0033" or "51").
func parseCIDValue(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s, base = s[2:], 16
	}
	n, err := strconv.ParseUint(s, base, 16)
	return uint16(n), err
}
