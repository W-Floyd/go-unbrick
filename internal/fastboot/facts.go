package fastboot

// The device as a source of facts: what a neutral `getvar all` establishes,
// declared as derivations so it resolves, cross-checks and explains itself the
// same way a firmware package does. Vendor verbs (a CID, an OEM probe) are not
// here — they are declared behind the vendor seam, over this same source.

import (
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// SourceRecon is the collected result of one `getvar all` (plus whatever vendor
// probes have since stored on it). The key lives here, beside its type, so the
// fact core stays free of the fastboot layer.
//
// It costs one paced round trip to *obtain*, which the caller has already paid
// by the time it is in the Bag; the rules below only read the struct, so they
// price as the field reads they are.
var SourceRecon = facts.Key[*DeviceRecon]("source:device.recon",
	facts.Fmt(func(r *DeviceRecon) string { return "getvar all (" + r.Serial + ")" }))

// FactProviders returns the vendor-neutral device derivations.
func FactProviders() []facts.Provider {
	return []facts.Provider{
		fromRecon(facts.Codename, facts.Attested, "getvar product",
			func(r *DeviceRecon) (string, bool) { return r.Product, r.Product != "" }),
		fromRecon(facts.SKU, facts.Attested, "getvar sku",
			func(r *DeviceRecon) (string, bool) { return r.SKU, r.SKU != "" }),
		fromRecon(facts.BuildFingerprint, facts.Attested, "getvar fingerprint",
			func(r *DeviceRecon) (string, bool) { return r.Fingerprint, r.Fingerprint != "" }),
		fromRecon(facts.Slot, facts.Attested, "getvar current-slot",
			func(r *DeviceRecon) (string, bool) { return r.CurrentSlot, r.CurrentSlot != "" }),
		fromRecon(facts.LockState, facts.Attested, "getvar securestate/unlocked",
			func(r *DeviceRecon) (string, bool) {
				if r.SecureState != "" {
					return r.SecureState, true
				}
				if r.Unlocked {
					return "unlocked", true
				}
				return "locked", true
			}),
		// The bootloader's own platform label, which is not the SoC fact: qboot
		// says "SM_DIVAR 1.0" where the catalog says "Qualcomm SM6225".
		fromRecon(facts.Platform, facts.Attested, "getvar cpu",
			func(r *DeviceRecon) (string, bool) { return r.CPU, r.CPU != "" }),
		fromRecon(facts.JTAGID, facts.Attested, "getvar JTAG id",
			func(r *DeviceRecon) (string, bool) { return strings.ToUpper(r.JTAGID), r.JTAGID != "" }),
		// The JTAG id is burned into the die, so the catalog's name for it is what
		// the silicon is.
		facts.Rule{
			Out:   facts.SoC.Name(),
			In:    []string{SourceRecon.Name(), facts.SourceCatalog.Name()},
			Price: 1, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				r, ok := facts.Get(b, SourceRecon)
				cat, ok2 := facts.Get(b, facts.SourceCatalog)
				if !ok || !ok2 || cat == nil || r.JTAGID == "" {
					return false, nil
				}
				soc, found := cat.SoCByJTAG(r.JTAGID)
				if !found || soc == "" {
					return false, nil
				}
				facts.Set(b, facts.SoC, soc, facts.Provenance{
					Source: "catalog JTAG_ID " + r.JTAGID, Authority: facts.Attested})
				return true, nil
			},
		},
	}
}

// fromRecon is a rule reading one field of the collected recon.
func fromRecon[T any](out facts.Fact[T], level facts.Level, source string,
	fn func(*DeviceRecon) (T, bool)) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{SourceRecon.Name()}, Price: 1, Level: level,
		Fn: func(b *facts.Bag) (bool, error) {
			r, ok := facts.Get(b, SourceRecon)
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
