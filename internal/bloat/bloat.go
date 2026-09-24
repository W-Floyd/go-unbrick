// Package bloat decides which preloaded packages a device can lose, from a
// table rather than from code.
//
// Which packages ship on a phone is a property of the carrier channel and the
// build, so it is data (catalog/bloat.yaml) for the same reason the device
// catalog and the distro profiles are: a new channel's junk should be an entry,
// not a release. What is *here* is the part that must not be a list: the rules
// about what may never be offered for removal, and the refusal to guess about
// a package nothing in the table names.
//
// The safety model, in one line: everything this package proposes is a per-user
// `pm uninstall --user 0`, which touches no partition and is undone by
// `install-existing` or a factory reset. Nothing here justifies flashing.
package bloat

import (
	"fmt"
	"sort"
	"strings"
)

// Category groups what a package is *for*, which is what decides whether losing
// it is a service or a fault.
type Category string

const (
	// Ads is the delivery machinery itself — the agents that install the games
	// and push notifications for more. Removing one stops re-delivery, which is
	// why it is worth more than removing what it delivered.
	Ads Category = "ads"
	// Preload is a third-party app the channel shipped: games, shopping,
	// social. The user did not choose it and can reinstall it from the store.
	Preload Category = "preload"
	// CarrierForeign is another carrier's client on this unit — an OMADM for a
	// network the device is not on, a launcher overlay for a different brand.
	CarrierForeign Category = "carrier-foreign"
	// CarrierOwn is this unit's *own* carrier software that is an app rather
	// than plumbing: a deals app, a diagnostics agent, a self-service portal.
	// Its own category because "TracFone's" is not the same claim as "another
	// carrier's" (safe to drop) or "provisioning" (protected) — a diagnostics
	// agent may participate in self-service flows, so it is offered but never
	// by default.
	CarrierOwn Category = "carrier"
	// OEMExtra is the manufacturer's own optional software.
	OEMExtra Category = "oem-extra"
	// Updates is the OTA machinery. Its own category because removing it is a
	// real decision: the phone stops receiving security updates.
	Updates Category = "updates"
	// Protected is never offered. Telephony, IMS, provisioning, setup, the
	// carrier-unlock client — the things whose removal costs calls, data,
	// activation, or the ability to ever carrier-unlock the device.
	Protected Category = "protected"
	// Unknown is what the table does not name. Reported, never selected: a
	// recon that guesses at 400 packages is how a phone loses its modem.
	Unknown Category = "unknown"
)

// Risk is how much a removal is likely to cost, for the categories that are
// offered at all.
type Risk string

// The definitions are deliberately narrow, because a loose one makes the label
// unreproducible. "A feature goes away" was the first attempt at Caution and it
// was useless: every optional app is a feature, so it put Family Space in
// Caution and Moto Unplugged in Safe for no reason anyone could restate.
const (
	// Safe: nothing else depends on it and no capability is lost. An optional
	// app belongs here even though someone somewhere uses it — the plan lists
	// every package with what it is, and removal is per-user and reversible.
	// Any data the app held goes with it, as with any uninstall.
	Safe Risk = "safe"
	// Caution: removing it costs a *capability* that nothing else on the device
	// exposes — the FM tuner, face unlock, tap-to-pay, the only route to a
	// settings surface — or the entry is not well enough understood to promise
	// otherwise. Not "an app you might miss": that is Safe.
	Caution Risk = "caution"
	// Invasive: it may touch activation, updates or a carrier feature, where the
	// cost is not a capability on the device but a relationship with a service.
	Invasive Risk = "invasive"
)

// rank orders the risks, so a selection can say "nothing worse than this".
func (r Risk) rank() int {
	switch r {
	case Caution:
		return 1
	case Invasive:
		return 2
	}
	return 0 // Safe, and the empty value, which means the same
}

// AtMost reports whether this risk is within a cutoff.
func (r Risk) AtMost(cutoff Risk) bool { return r.rank() <= cutoff.rank() }

// ParseRisk reads a --max-risk value.
func ParseRisk(s string) (Risk, error) {
	switch Risk(strings.ToLower(strings.TrimSpace(s))) {
	case Safe, "":
		return Safe, nil
	case Caution:
		return Caution, nil
	case Invasive:
		return Invasive, nil
	}
	return "", fmt.Errorf("unknown risk %q (have: safe, caution, invasive)", s)
}

// Rule is one entry of the table.
type Rule struct {
	// Exactly one of these matches a package name.
	Name   string `yaml:"name,omitempty"`   // exact package name
	Prefix string `yaml:"prefix,omitempty"` // name prefix, e.g. com.aura.
	// Vendor scopes a rule to one OEM's devices, as a catalog vendor id
	// ("motorola"). Empty means any device, which is right for the Android
	// platform, for Google's packages, and for the delivery agents and games
	// that ship on everyone's phones.
	//
	// A com.motorola.* rule on a Samsung is not merely useless: it would name
	// something the maintainer has never seen on that device and cannot vouch
	// for. So an out-of-scope rule is dropped rather than applied, and the
	// package falls to "unknown", which is the honest answer.
	Vendor string `yaml:"vendor,omitempty"`
	// Category and Risk say what it is and what losing it costs.
	Category Category `yaml:"category"`
	Risk     Risk     `yaml:"risk,omitempty"`
	// Note is what the report prints: what the package does, and what stops
	// working without it. An entry with no note is an entry nobody can audit.
	Note string `yaml:"note,omitempty"`
	// Blocked marks a package the *device* refuses to part with: one in the
	// build's protected-packages list, which answers both `pm uninstall --user
	// 0` and `pm disable-user` with "Cannot disable a protected package". It is
	// still classified — it is bloat, and saying so is useful — but proposing it
	// again every run would be proposing a failure, so it is reported instead.
	Blocked bool `yaml:"blocked,omitempty"`
}

func (r Rule) matches(pkg string) bool {
	switch {
	case r.Name != "":
		return pkg == r.Name
	case r.Prefix != "":
		return strings.HasPrefix(pkg, r.Prefix)
	}
	return false
}

// specificity ranks a match: an exact name beats a prefix, and a longer prefix
// beats a shorter one, so a protected package inside an otherwise-removable
// family is still protected.
func (r Rule) specificity() int {
	if r.Name != "" {
		return 1000 + len(r.Name)
	}
	return len(r.Prefix)
}

// Table is the loaded rule set, with the protections held apart from
// everything else.
//
// They are a separate list rather than higher-priority entries in one list
// because priority is comparative and protection must not be: an exact-name
// rule out-specifies a prefix rule, so a catalog entry naming
// com.motorola.tracfone.rsu would have beaten the built-in prefix that protects
// it, and the device would have lost its route to a carrier unlock. Protections
// are checked first, always, whoever wrote them.
type Table struct {
	protect []Rule
	rules   []Rule
	vendor  string
}

// New builds a table for a device of this vendor (a catalog vendor id, or ""
// to keep every rule) from catalog entries plus the built-in floor. A catalog
// entry may add a protection; none can remove one.
func New(entries []Rule, vendor string) *Table {
	t := &Table{vendor: vendor}
	for _, r := range append(builtin(), entries...) {
		if !vendorMatches(r.Vendor, vendor) {
			continue
		}
		if r.Category == Protected {
			t.protect = append(t.protect, r)
		} else {
			t.rules = append(t.rules, r)
		}
	}
	// Most specific first within each list, so Classify takes the first match.
	bySpecificity := func(rs []Rule) {
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].specificity() > rs[j].specificity() })
	}
	bySpecificity(t.protect)
	bySpecificity(t.rules)
	return t
}

// Builtin is the table without a catalog: the protections only. The floor is
// deliberately all-protective — a tool that ships with an empty catalog should
// propose nothing, not propose everything.
func Builtin() *Table { return New(nil, "") }

// vendorMatches reports whether a rule scoped to `want` applies on a device of
// vendor `have`. An unscoped rule applies everywhere; an unknown device vendor
// keeps every rule, since narrowing on a guess would silently hide knowledge
// the report should show.
func vendorMatches(want, have string) bool {
	return want == "" || have == "" || strings.EqualFold(want, have)
}

// Vendor is the device vendor this table was scoped to.
func (t *Table) Vendor() string {
	if t == nil {
		return ""
	}
	return t.vendor
}

// Rules returns every rule, protections first, each group most specific first.
func (t *Table) Rules() []Rule {
	if t == nil {
		return nil
	}
	return append(append([]Rule{}, t.protect...), t.rules...)
}

// Classify returns the rule that governs a package, and whether the table
// named it at all. Protections are consulted before anything else.
func (t *Table) Classify(pkg string) (Rule, bool) {
	if t == nil {
		return Rule{Category: Unknown}, false
	}
	for _, r := range t.protect {
		if r.matches(pkg) {
			return r, true
		}
	}
	for _, r := range t.rules {
		if r.matches(pkg) {
			return r, true
		}
	}
	return Rule{Category: Unknown, Risk: Caution,
		Note: "not in catalog/bloat.yaml — nothing is known about it, so nothing is proposed"}, false
}

// builtin is the protected set: the packages whose removal costs something a
// phone cannot get back from the Play Store. It lives in code rather than the
// catalog because a table a user edits should not be able to *unprotect*
// telephony by deleting a line — the catalog can add protections and name
// bloat, and these hold regardless.
func builtin() []Rule {
	p := func(prefix, note string) Rule {
		return Rule{Prefix: prefix, Category: Protected, Note: note}
	}
	n := func(name, note string) Rule {
		return Rule{Name: name, Category: Protected, Note: note}
	}
	// A protection for one OEM's own package, scoped to that OEM. The
	// protections themselves live in code rather than the catalog so a table
	// edit cannot lift them; the scope keeps a Motorola rule from claiming to
	// know anything about a Samsung.
	mot := func(prefix, note string) Rule {
		return Rule{Prefix: prefix, Category: Protected, Vendor: "motorola", Note: note}
	}
	return []Rule{
		// Telephony, IMS and the radio stack. Losing any of it costs calls, SMS
		// or mobile data, and no amount of reinstalling from a store returns it.
		p("com.android.phone", "the telephony stack itself"),
		p("com.android.ims", "IMS: VoLTE, VoWiFi, RCS"),
		p("com.android.mms.service", "the SMS/MMS transport"),
		p("com.android.providers.telephony", "the telephony database: APNs, SMS, MMS"),
		p("com.android.server.telecom", "the call manager"),
		p("com.android.emergency", "emergency information and calling"),
		p("com.android.carrierconfig", "per-carrier radio configuration"),
		p("com.android.carrierdefaultapp", "carrier captive-portal and provisioning handling"),
		p("com.android.imsserviceentitlement", "IMS entitlement: what enables VoLTE/VoWiFi on a carrier"),
		p("com.android.simappdialog", "SIM application dialog"),
		p("com.qualcomm.qti.ims", "Qualcomm IMS service"),
		p("com.qti.phone", "Qualcomm telephony service"),
		p("com.qualcomm.qti.telephonyservice", "Qualcomm telephony service"),
		p("com.qualcomm.qti.uceShimService", "IMS presence (RCS capability exchange)"),
		p("com.qualcomm.qti.remoteSimlockAuth", "remote SIM-lock authentication: part of carrier unlocking"),
		mot("com.motorola.carrierconfig", "Motorola's carrier configuration"),
		mot("com.motorola.carriersettingsext", "Motorola's carrier settings extension"),
		mot("com.motorola.msimsettings", "multi-SIM settings"),

		// Provisioning, activation and carrier unlock. On a subsidy-locked unit
		// the RSU client is how the lock is ever lifted — removing it is how a
		// phone becomes permanently carrier-locked.
		mot("com.motorola.tracfone.rsu", "remote SIM unlock client: the route to carrier-unlocking this unit"),
		mot("com.motorola.android.provisioning", "device provisioning"),
		p("com.android.managedprovisioning", "managed/enterprise provisioning"),
		p("com.google.android.setupwizard", "first-boot setup: a device without it may not finish a factory reset"),
		mot("com.motorola.setup", "Motorola's setup wizard"),
		mot("com.motorola.setupwizard", "Motorola's setup wizard"),
		p("com.google.android.partnersetup", "partner setup, which carrier provisioning expects"),

		// The platform. Removing any of this for user 0 is how a phone stops
		// booting to a usable state. "android" is matched exactly: as a prefix it
		// would also claim things like android.autoinstalls.config.*, which is a
		// preload configuration and very much removable.
		n("android", "the framework itself"),
		p("com.android.systemui", "the system UI: status bar, navigation, lock screen"),
		p("com.android.settings", "Settings"),
		p("com.android.providers.settings", "the settings database"),
		p("com.android.permissioncontroller", "the permission manager"),
		p("com.android.shell", "the adb shell itself"),
		p("com.google.android.gms", "Play services: apps depend on it broadly"),
		p("com.android.vending", "the Play Store — how anything removed is reinstalled"),
		p("com.google.android.gsf", "Google services framework"),
		mot("com.motorola.aiservices", "on-device AI services other Motorola features call"),

		// Google's platform half: the packages that are part of Android rather
		// than apps on top of it. Many are mainline modules — the OS updates
		// them through Play — and removing one is removing a piece of the
		// operating system, not a preload. Protected here rather than in the
		// catalog for the same reason telephony is: a table edit must not be
		// able to take the WebView away from every app that renders HTML.
		p("com.google.android.webview", "the WebView every app renders HTML with — and what a URL kiosk *is*"),
		p("com.android.webview", "the WebView implementation"),
		p("com.google.android.trichromelibrary", "the shared library WebView and Chrome are built on"),
		p("com.google.android.packageinstaller", "the installer: without it nothing can be installed or removed"),
		p("com.google.android.permissioncontroller", "the permission manager"),
		p("com.google.android.providers.media.module", "the media provider (a mainline module): photos, video and audio access"),
		p("com.google.android.documentsui", "the file picker every app opens documents through"),
		p("com.google.android.networkstack", "the network stack (a mainline module)"),
		p("com.google.android.connectivity.resources", "connectivity configuration"),
		p("com.google.android.captiveportallogin", "captive-portal sign-in: without it, hotel and airport Wi-Fi cannot be joined"),
		p("com.google.android.cellbroadcast", "emergency alerts (AMBER, presidential, weather) — legally mandated on many networks"),
		p("com.google.android.carrier", "carrier configuration"),
		p("com.google.android.apps.carrier", "carrier services"),
		p("com.google.android.ims", "carrier services: RCS, and IMS provisioning on some builds"),
		p("com.google.android.wfcactivation", "Wi-Fi calling activation"),
		p("com.google.android.ext.services", "framework extension services (a mainline module)"),
		p("com.google.android.ext.shared", "framework shared extensions"),
		p("com.google.android.modulemetadata", "the mainline module manifest"),
		p("com.google.mainline", "mainline modules: pieces of the OS delivered through Play"),
		p("com.google.android.sdksandbox", "the SDK runtime sandbox (a mainline module)"),
		p("com.google.android.adservices", "the Privacy Sandbox service (a mainline module)"),
		p("com.google.android.ondevicepersonalization", "on-device personalization services (a mainline module)"),
		p("com.google.android.federatedcompute", "federated compute services (a mainline module)"),
		p("com.google.android.configupdater", "delivers configuration and certificate-revocation updates"),
		p("com.google.android.safetycenter.resources", "Safety Center resources"),
		p("com.google.android.overlay", "resource overlays for the modules above"),

		// Keys, attestation and secure storage.
		p("com.android.keychain", "the credential store"),
		p("com.qualcomm.qti.qmmi", "factory test framework the OEM's diagnostics use"),
	}
	// The OTA updater is deliberately *not* here. Removing it is a real choice
	// with a real cost (no more security updates), not a mistake to be
	// prevented, so it lives in the catalog under the "updates" category, which
	// nothing selects unless the operator asks for it by name.
}
