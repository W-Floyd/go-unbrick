package adb

// The Android userspace as a source of facts. Everything here is read from a
// running system whose property values a rooted process can set, so it is
// Derived: a package's manifest or a bootloader's own answer outranks it on a
// conflict, while the disagreement still surfaces — which is exactly what one
// wants when the question is "is this device running what it claims to be".
//
// What any shell-reachable route derives (slot, lock state, SoC, A/B, the
// device tree's codename) comes from internal/transport; what is here is what
// only Android's property system says.

import (
	"strings"

	"go-unbrick/internal/facts"
	"go-unbrick/internal/transport"
)

// SourceADB is one collected adb recon.
var SourceADB = facts.Key[*Recon]("source:device.adb",
	facts.Fmt(func(r *Recon) string { return "adb " + r.Serial }))

// FactProviders returns the derivations over a booted Android userspace.
func FactProviders() []facts.Provider {
	shell := transport.ShellProviders("adb", SourceADB.Name(),
		func(b *facts.Bag) (*transport.ShellRecon, bool) {
			r, ok := facts.Get(b, SourceADB)
			if !ok || r == nil {
				return nil, false
			}
			return r.ShellRecon, true
		}, facts.Derived)

	return append(shell,
		fromADB(facts.Codename, "getprop ro.product.device",
			func(r *Recon) (string, bool) {
				v := firstProp(r.Props, "ro.product.device", "ro.product.vendor.device", "ro.boot.device")
				return v, v != ""
			}),
		fromADB(facts.Model, "getprop ro.product.model",
			func(r *Recon) (string, bool) { return r.Model(), r.Model() != "" }),
		// The bootloader's own parameters, which survive as properties. The
		// shared shell providers read them from /proc/cmdline where that is
		// readable; on Android 12 and later it is not, and these are the only
		// source. Where both answer they agree, and agreement is corroboration.
		fromADB(facts.Slot, "getprop ro.boot.slot_suffix",
			func(r *Recon) (string, bool) { return r.Slot(), r.Slot() != "" }),
		fromADB(facts.LockState, "getprop ro.boot.verifiedbootstate",
			func(r *Recon) (string, bool) { return r.LockState(), r.LockState() != "" }),
		fromADB(facts.ABEnabled, "getprop ro.boot.slot_suffix",
			func(r *Recon) (bool, bool) { return r.ABDevice(), r.Slot() != "" }),
		fromADB(facts.BuildFingerprint, "getprop ro.build.fingerprint",
			func(r *Recon) (string, bool) {
				v := firstProp(r.Props, "ro.build.fingerprint")
				return v, v != ""
			}),
		// A Treble build's system image has its own identity, which legitimately
		// names a different release from the product fingerprint — a separate
		// fact, not a disagreement.
		fromADB(facts.SystemFingerprint, "getprop ro.system.build.fingerprint",
			func(r *Recon) (string, bool) {
				v := firstProp(r.Props, "ro.system.build.fingerprint")
				return v, v != ""
			}),
		fromADB(facts.SecurityPatch, "getprop ro.build.version.security_patch",
			func(r *Recon) (string, bool) {
				v := firstProp(r.Props, "ro.build.version.security_patch")
				return v, v != ""
			}),
		fromADB(facts.BuildDate, "getprop ro.build.date",
			func(r *Recon) (string, bool) {
				v := firstProp(r.Props, "ro.build.date")
				return v, v != ""
			}),
		fromADB(facts.Carrier, "getprop ro.carrier",
			func(r *Recon) (string, bool) {
				v := firstProp(r.Props, "ro.carrier")
				// "unknown" is what a device with no carrier provisioning says,
				// and it is not a carrier.
				if v == "" || strings.EqualFold(v, "unknown") {
					return "", false
				}
				return v, true
			}),
		// Android's own name for the board, resolved to the catalog's spelling
		// so it corroborates the sysfs and device-tree answers rather than
		// reading as a third opinion.
		facts.Rule{
			Out: facts.SoC.Name(), In: []string{SourceADB.Name(), facts.SourceCatalog.Name()},
			Price: 1, Level: facts.Derived,
			Fn: func(b *facts.Bag) (bool, error) {
				r, ok := facts.Get(b, SourceADB)
				cat, ok2 := facts.Get(b, facts.SourceCatalog)
				if !ok || !ok2 || r == nil {
					return false, nil
				}
				tok := firstProp(r.Props, "ro.board.platform", "ro.soc.model", "ro.hardware")
				if !transport.LooksLikePartNumber(tok) {
					return false, nil
				}
				name, src := transport.SoCName(cat, tok)
				if name == "" {
					return false, nil
				}
				facts.Set(b, facts.SoC, name, facts.Provenance{
					Source: "adb " + src + " " + tok, Authority: facts.Derived})
				return true, nil
			},
		},
	)
}

// fromADB is a rule reading one field of the collected recon. Everything the
// property system says is Derived — see the package comment.
func fromADB[T any](out facts.Fact[T], source string, fn func(*Recon) (T, bool)) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{SourceADB.Name()}, Price: 1, Level: facts.Derived,
		Fn: func(b *facts.Bag) (bool, error) {
			r, ok := facts.Get(b, SourceADB)
			if !ok || r == nil {
				return false, nil
			}
			v, ok := fn(r)
			if !ok {
				return false, nil
			}
			facts.Set(b, out, v, facts.Provenance{Source: source, Authority: facts.Derived})
			return true, nil
		},
	}
}
