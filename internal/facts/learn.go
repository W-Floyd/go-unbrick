package facts

import "strings"

// notLearnable are facts that are not shared model/SoC/firmware knowledge,
// for one of two reasons:
//
//   - they name or single out one physical unit, or are per-unit transient
//     state (serial, IMEI and hostname are not facts — they live on the route's
//     recon struct — so only the ones that are facts appear here);
//   - they describe the OS someone installed on the device (an aftermarket
//     Linux distro and its kernel), which is the owner's choice, not a trait of
//     the model. The stock OEM firmware facts (fingerprint, patch level, build)
//     are kept: those enumerate the real firmware that ships for the model.
var notLearnable = map[string]bool{
	"unlock_challenge": true, // a per-unit, time-varying secret
	"slot":             true, // which slot this unit booted right now
	"lock_state":       true, // this unit's current lock state, not a model trait
	"device_os":        true, // the installed distribution (postmarketOS, Mobian, …)
	"kernel_release":   true, // the installed kernel's uname -r
}

// Learnable renders the facts worth remembering about a device *model* — its
// silicon, signing domain, carrier variant and stock-firmware baseline — as a
// name→value map. It keeps only what the device or its artifacts stated
// *raw*, dropping:
//
//   - per-unit identifiers, transient state and installed-OS facts (notLearnable);
//   - the source:* byte blobs;
//   - anything that is our interpretation rather than the device's own value —
//     a fact whose winning value could only be produced by a rule that consulted
//     the catalog (the SoC's marketing name, a CID's carrier description). The
//     raw inputs behind those (the CID, the raw carrier code, the JTAG) are
//     learned; our gloss of them is not.
//
// Keeping only raw values makes the store reproducible and route-independent: a
// carrier reads the same over adb and fastboot, since neither stores our
// catalog spelling of it.
func Learnable(b *Bag) map[string]string {
	out := map[string]string{}
	for _, name := range b.Names() {
		if notLearnable[name] || strings.HasPrefix(name, "source:") {
			continue
		}
		v, ok := b.Best(name)
		if !ok || interpreted(b, name, v) {
			continue
		}
		if s := strings.TrimSpace(b.Show(name, v.Data)); s != "" {
			out[name] = s
		}
	}
	return out
}

// interpreted reports whether a fact's winning value is our interpretation
// rather than a raw device/artifact read: every derivation that produced it
// consulted the catalog. A value with any catalog-free derivation, or one set
// directly with no rule behind it (a source fact), is raw.
func interpreted(b *Bag, name string, best Value) bool {
	producing := false
	for _, s := range b.Trace(name) {
		if !b.Equal(name, s.Value.Data, best.Data) {
			continue
		}
		producing = true
		if !usedCatalog(s.Inputs) {
			return false // a raw derivation exists for this value
		}
	}
	return producing
}

func usedCatalog(inputs []string) bool {
	for _, in := range inputs {
		if in == SourceCatalog.Name() {
			return true
		}
	}
	return false
}
