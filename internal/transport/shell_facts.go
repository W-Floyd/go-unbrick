package transport

// The derivations true of any shell-reachable device, declared once and
// registered by each transport over its own source key. What the running system
// says about the hardware and the boot state is the same fact whether it came
// over ssh or over adb; only the provenance differs, and that is a string.
//
// Authority is the transport's to declare, and both shell routes declare
// Derived: everything here passed through a mutable userspace and a kernel
// command line the installed system may have replaced, so a bootloader's or a
// package's version of the same fact must win the display while the
// disagreement still surfaces.

import (
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// ShellProviders returns the common derivations over one transport's shell
// recon. source names the route for provenance ("ssh", "adb"); get pulls the
// recon back out of the Bag, which is the transport's own typed key.
func ShellProviders(source string, key string, get func(*facts.Bag) (*ShellRecon, bool), level facts.Level) []facts.Provider {
	rule := func(out string, price int, fn func(*facts.Bag, *ShellRecon) bool) facts.Rule {
		return facts.Rule{
			Out: out, In: []string{key}, Price: price, Level: level,
			Fn: func(b *facts.Bag) (bool, error) {
				r, ok := get(b)
				if !ok || r == nil {
					return false, nil
				}
				return fn(b, r), nil
			},
		}
	}
	prov := func(what string) facts.Provenance {
		return facts.Provenance{Source: source + " " + what, Authority: level}
	}

	return []facts.Provider{
		rule(facts.Slot.Name(), 1, func(b *facts.Bag, r *ShellRecon) bool {
			if r.Slot() == "" {
				return false
			}
			facts.Set(b, facts.Slot, r.Slot(), prov("cmdline androidboot.slot_suffix"))
			return true
		}),
		rule(facts.LockState.Name(), 1, func(b *facts.Bag, r *ShellRecon) bool {
			if r.LockState() == "" {
				return false
			}
			facts.Set(b, facts.LockState, r.LockState(), prov("cmdline androidboot.verifiedbootstate"))
			return true
		}),
		rule(facts.ABEnabled.Name(), 1, func(b *facts.Bag, r *ShellRecon) bool {
			if len(r.Partitions) == 0 {
				return false
			}
			facts.Set(b, facts.ABEnabled, r.ABDevice(), prov("live partition table"))
			return true
		}),
		// A mainline device tree names the device "<oem>,<codename>" in its most
		// specific compatible entry. The userspace's own claim (a deviceinfo
		// file, a build prop) is a separate provider behind each transport, so
		// the two corroborate or disagree on the record.
		rule(facts.Codename.Name(), 1, func(b *facts.Bag, r *ShellRecon) bool {
			name, _ := r.DTCodename()
			if name == "" {
				return false
			}
			facts.Set(b, facts.Codename, name, prov("device-tree compatible"))
			return true
		}),
		// The silicon's own name for itself, spelled the way the catalog spells
		// it. Every token the kernel offers is resolved and set separately, so
		// agreeing sources read as corroboration rather than one guess.
		facts.Rule{
			Out: facts.SoC.Name(), In: []string{key, facts.SourceCatalog.Name()},
			Price: 1, Level: level,
			Fn: func(b *facts.Bag) (bool, error) {
				r, ok := get(b)
				cat, ok2 := facts.Get(b, facts.SourceCatalog)
				if !ok || !ok2 || r == nil {
					return false, nil
				}
				any := false
				var unresolved string
				for _, tok := range r.SoCTokens() {
					name, src := SoCName(cat, tok)
					if name == "" {
						if unresolved == "" {
							unresolved = tok
						}
						continue
					}
					facts.Set(b, facts.SoC, name, prov(src+" "+tok))
					any = true
				}
				// A device the catalog does not know still has a part number,
				// and the raw token is the useful answer. Only when nothing
				// resolved, so a known SoC never yields both spellings and a
				// bogus conflict.
				if !any && unresolved != "" {
					facts.Set(b, facts.SoC, unresolved, prov("sysfs/device-tree (uncatalogued)"))
					any = true
				}
				return any, nil
			},
		},
	}
}

// SoCName resolves a part number the running kernel reported ("SM6225",
// "sm6225") into the catalog's spelling of that SoC, so a fact derived here
// compares equal to the same fact derived from a fused JTAG id. Returns the
// name and where it came from, or "" when the catalog has never seen the part.
func SoCName(cat *catalog.Catalog, token string) (string, string) {
	if cat == nil || token == "" {
		return "", ""
	}
	if soc := cat.ResolveVariant(token, token); soc != "" {
		return soc, "catalog variant"
	}
	// The variant table is keyed by platform codename ("socdivar"), so a part
	// number that is not itself a key is looked up in what the table and the
	// device list *say*: an entry naming this exact part is the catalog's
	// spelling of it.
	for _, soc := range cat.Variants() {
		if namesPart(soc, token) {
			return soc, "catalog variant"
		}
	}
	for _, d := range cat.AllDevices() {
		if d.SoC != "" && namesPart(d.SoC, token) {
			return d.SoC, "catalog device " + d.Codename
		}
	}
	return "", ""
}

// namesPart reports whether a SoC description names exactly this part —
// word-wise, so "SM6225" matches "Qualcomm SM6225 Snapdragon 680" without
// "SM622" matching anything.
func namesPart(desc, token string) bool {
	for _, f := range strings.FieldsFunc(desc, func(r rune) bool {
		return r == ' ' || r == '/' || r == ',' || r == '(' || r == ')'
	}) {
		if strings.EqualFold(f, token) {
			return true
		}
	}
	return false
}
