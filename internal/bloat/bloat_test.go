package bloat

import (
	"bytes"
	"sort"
	"strings"
	"testing"
)

// catalogRules stands in for catalog/bloat.yaml.
func catalogRules() []Rule {
	return []Rule{
		{Prefix: "com.aura.", Category: Ads, Risk: Safe, Note: "preload delivery"},
		{Name: "com.einnovation.temu", Category: Preload, Risk: Safe, Note: "Temu"},
		{Name: "com.motorola.android.fmradio", Category: OEMExtra, Risk: Caution, Note: "FM radio goes away"},
		{Name: "com.motorola.omadm.att", Category: CarrierForeign, Risk: Safe, Note: "AT&T DM client"},
		{Name: "com.motorola.android.fota", Category: Updates, Risk: Invasive, Note: "stops updates"},
	}
}

func TestClassifyExactBeatsPrefix(t *testing.T) {
	t.Run("prefix claims the family", func(t *testing.T) {
		r, known := New(catalogRules(), "motorola").Classify("com.aura.oobe.motorola")
		if !known || r.Category != Ads {
			t.Errorf("classified as %+v", r)
		}
	})
	t.Run("an exact rule wins over a prefix", func(t *testing.T) {
		// Both ordinary categories, so this is the specificity path rather than
		// the protection path (TestCatalogCannotUnprotect covers that one).
		rules := append(catalogRules(),
			Rule{Name: "com.aura.oobe.motorola", Category: OEMExtra, Risk: Caution, Note: "carries a setting worth keeping"})
		tbl := New(rules, "motorola")
		if r, _ := tbl.Classify("com.aura.oobe.motorola"); r.Category != OEMExtra {
			t.Errorf("exact rule lost to the prefix: %+v", r)
		}
		// …and the rest of the family is unaffected.
		if r, _ := tbl.Classify("com.aura.jet.att"); r.Category != Ads {
			t.Errorf("sibling reclassified as %v", r.Category)
		}
	})
}

// The protections live in code so that editing the catalog cannot remove them.
// A catalog entry at the same specificity must not win.
func TestCatalogCannotUnprotect(t *testing.T) {
	rules := []Rule{
		{Prefix: "com.android.phone", Category: Preload, Risk: Safe, Note: "definitely fine, promise"},
		{Name: "com.motorola.tracfone.rsu", Category: Preload, Risk: Safe, Note: "also fine"},
	}
	t2 := New(rules, "motorola")
	for _, pkg := range []string{"com.android.phone", "com.motorola.tracfone.rsu"} {
		if r, _ := t2.Classify(pkg); r.Category != Protected {
			t.Errorf("%s classified as %v — the catalog unprotected it", pkg, r.Category)
		}
	}
}

// A rule scoped to one OEM must not speak for another's device. On a Samsung a
// com.motorola.* rule is not merely useless — it claims knowledge of something
// the maintainer has never seen there — so it is dropped and the package falls
// to "unknown", which is the honest answer.
func TestVendorScope(t *testing.T) {
	rules := []Rule{
		{Name: "com.motorola.android.fmradio", Vendor: "motorola", Category: OEMExtra, Risk: Safe, Note: "FM radio"},
		{Name: "com.samsung.android.bixby.agent", Vendor: "samsung", Category: OEMExtra, Risk: Safe, Note: "Bixby"},
		{Prefix: "com.aura.", Category: Ads, Risk: Safe, Note: "preload delivery"},
	}

	moto := New(rules, "motorola")
	if r, known := moto.Classify("com.motorola.android.fmradio"); !known || r.Category != OEMExtra {
		t.Errorf("on motorola, the motorola rule did not apply: %+v", r)
	}
	if _, known := moto.Classify("com.samsung.android.bixby.agent"); known {
		t.Error("on motorola, a samsung rule applied")
	}
	// The unscoped rule applies on both.
	if _, known := moto.Classify("com.aura.oobe.motorola"); !known {
		t.Error("an unscoped rule did not apply on motorola")
	}

	sam := New(rules, "samsung")
	if _, known := sam.Classify("com.motorola.android.fmradio"); known {
		t.Error("on samsung, a motorola rule applied")
	}
	if r, known := sam.Classify("com.samsung.android.bixby.agent"); !known || r.Category != OEMExtra {
		t.Errorf("on samsung, the samsung rule did not apply: %+v", r)
	}
	if _, known := sam.Classify("com.aura.oobe.motorola"); !known {
		t.Error("an unscoped rule did not apply on samsung")
	}

	// An unknown device vendor keeps everything: narrowing on a guess would
	// hide knowledge the report should show, and the plan explains each entry
	// anyway.
	any := New(rules, "")
	for _, pkg := range []string{"com.motorola.android.fmradio", "com.samsung.android.bixby.agent"} {
		if _, known := any.Classify(pkg); !known {
			t.Errorf("with an unknown vendor, %s was dropped", pkg)
		}
	}
	if any.Vendor() != "" || moto.Vendor() != "motorola" {
		t.Errorf("Vendor() = %q / %q", any.Vendor(), moto.Vendor())
	}
}

// The protections are scoped too, and a vendor's own protected package is
// still protected on that vendor's device.
func TestVendorScopedProtections(t *testing.T) {
	moto := New(nil, "motorola")
	if r, _ := moto.Classify("com.motorola.tracfone.rsu"); r.Category != Protected {
		t.Errorf("the carrier-unlock client is not protected on motorola: %v", r.Category)
	}
	// The platform protections are unscoped, so they hold everywhere.
	for _, vendor := range []string{"motorola", "samsung", "google", ""} {
		if r, _ := New(nil, vendor).Classify("com.android.phone"); r.Category != Protected {
			t.Errorf("telephony is not protected on %q", vendor)
		}
	}
}

// Everything the table does not name is unknown, and unknown is never selected.
func TestUnknownIsNeverProposed(t *testing.T) {
	tbl := New(catalogRules(), "motorola")
	r, known := tbl.Classify("com.example.mystery")
	if known || r.Category != Unknown {
		t.Fatalf("classified as %+v (known=%v)", r, known)
	}
	plan := tbl.Build("dev", []Inventory{
		{Package: "com.example.mystery", FromImage: true},
	}, []Category{Ads, Preload, CarrierForeign, OEMExtra, Updates}, Invasive)

	if got := plan.Removals(); len(got) != 0 {
		t.Errorf("proposed %v for an unnamed package", got)
	}
	if u := plan.Unknowns(); len(u) != 1 || u[0] != "com.example.mystery" {
		t.Errorf("Unknowns() = %v", u)
	}
}

// The unclassified set is reported by disposition, because one total serving
// two purposes read as a contradiction: "150 unknown" kept beside "201 not in
// the catalog" was the same set counted twice, once excluding what had already
// been removed.
func TestUnknownsByState(t *testing.T) {
	plan := New(catalogRules(), "motorola").Build("dev", []Inventory{
		{Package: "com.example.still.here", FromImage: true},
		{Package: "com.example.already.gone", FromImage: true, Uninstalled: true},
		{Package: "com.example.disabled", FromImage: true, Disabled: true},
		{Package: "com.example.mine"},                        // the user's own app: out of scope entirely
		{Package: "com.aura.oobe.motorola", FromImage: true}, // classified, so not unknown
	}, DefaultCategories(), DefaultMaxRisk())

	installed, inactive := plan.UnknownsByState()
	if len(installed) != 1 || installed[0] != "com.example.still.here" {
		t.Errorf("installed unknowns = %v", installed)
	}
	if len(inactive) != 2 {
		t.Errorf("inactive unknowns = %v, want the removed and the disabled one", inactive)
	}
	// The two halves together are the whole, and the user's own app is in
	// neither: nothing about it is the catalog's business.
	if total := len(plan.Unknowns()); total != 3 {
		t.Errorf("Unknowns() = %d, want the 3 unclassified preloads", total)
	}
	for _, name := range plan.Unknowns() {
		if name == "com.example.mine" {
			t.Error("a user-installed app was counted as unclassified bloat")
		}
	}
}

func TestBuildStates(t *testing.T) {
	inv := []Inventory{
		{Package: "com.aura.oobe.motorola", FromImage: true},
		{Package: "com.einnovation.temu"},                                 // delivered into /data
		{Package: "com.motorola.android.fmradio", FromImage: true},        // category not selected
		{Package: "com.android.phone", FromImage: true},                   // protected
		{Package: "com.example.mine"},                                     // user's own, unnamed
		{Package: "com.aura.jet.att", FromImage: true, Uninstalled: true}, // already gone
	}
	plan := New(catalogRules(), "motorola").Build("ZL83", inv, []Category{Ads, Preload}, Invasive)

	want := map[string]State{
		"com.aura.oobe.motorola":       Remove,
		"com.einnovation.temu":         Remove,
		"com.motorola.android.fmradio": Keep,
		"com.android.phone":            Keep,
		"com.example.mine":             NotPreloaded,
		"com.aura.jet.att":             Gone,
	}
	for _, e := range plan.Entries {
		if want[e.Package] != e.State {
			t.Errorf("%s: state %q, want %q (reason: %s)", e.Package, e.State, want[e.Package], e.Reason)
		}
		if e.State == Keep && e.Reason == "" {
			t.Errorf("%s kept with no reason given", e.Package)
		}
	}

	// A sponsored app the delivery agent dropped in /data is still bloat — the
	// table names it — but its removal is not locally reversible.
	for _, e := range plan.Removals() {
		if e.Package == "com.einnovation.temu" && e.FromImage {
			t.Error("a /data install was recorded as restorable from the image")
		}
	}
}

// A package already disabled for this user does not run, which is the whole
// objective — so it is reported, not proposed. Found the hard way: a disabled
// privileged package answers "package is non-disable" to an uninstall.
func TestAlreadyDisabledIsNotProposed(t *testing.T) {
	plan := New(catalogRules(), "motorola").Build("dev", []Inventory{
		{Package: "com.aura.oobe.motorola", FromImage: true, Disabled: true},
		{Package: "com.aura.jet.att", FromImage: true},
	}, []Category{Ads}, Invasive)

	states := map[string]State{}
	for _, e := range plan.Entries {
		states[e.Package] = e.State
	}
	if states["com.aura.oobe.motorola"] != Off {
		t.Errorf("a disabled package is in state %q, want %q", states["com.aura.oobe.motorola"], Off)
	}
	if states["com.aura.jet.att"] != Remove {
		t.Errorf("an enabled package is in state %q, want %q", states["com.aura.jet.att"], Remove)
	}
	if got := plan.Removals(); len(got) != 1 {
		t.Errorf("proposed %d removals, want only the enabled one", len(got))
	}
}

// The record has to carry all three outcomes, because each has a different
// inverse: reinstall, re-enable, or a trip to the Play Store.
func TestRecordCarriesDisabled(t *testing.T) {
	rec := &Record{Device: "dev"}
	rec.Note(Entry{Package: "com.a", FromImage: true})
	rec.Note(Entry{Package: "com.b"})
	rec.NoteDisabled("com.motorola.paks")

	var buf bytes.Buffer
	if err := WriteRecord(&buf, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	back, err := ReadRecord(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if len(back.Removed) != 1 || len(back.RemovedFromData) != 1 || len(back.Disabled) != 1 {
		t.Errorf("round trip = %+v", back)
	}
	// A record whose only action was a disable is still an undo record.
	var only bytes.Buffer
	onlyDisabled := &Record{Device: "dev"}
	onlyDisabled.NoteDisabled("com.motorola.paks")
	if err := WriteRecord(&only, onlyDisabled); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if _, err := ReadRecord(bytes.NewReader(only.Bytes())); err != nil {
		t.Errorf("a disable-only record was rejected: %v", err)
	}
}

// Carrier-own software is offered but is not another carrier's leftovers and is
// not provisioning: it gets its own category, and is never in the default set.
func TestCarrierOwnIsSelectableButNotDefault(t *testing.T) {
	rules := append(catalogRules(), Rule{
		Name: "com.tracfone.preload.accountservices", Category: CarrierOwn,
		Risk: Invasive, Note: "Device Pulse",
	})
	inv := []Inventory{{Package: "com.tracfone.preload.accountservices", FromImage: true}}

	if got := New(rules, "motorola").Build("dev", inv, DefaultCategories(), DefaultMaxRisk()).Removals(); len(got) != 0 {
		t.Errorf("carrier software was proposed by default: %v", got)
	}
	if got := New(rules, "motorola").Build("dev", inv, []Category{CarrierOwn}, Invasive).Removals(); len(got) != 1 {
		t.Errorf("carrier software could not be selected: %v", got)
	}
	if _, err := ParseCategories([]string{"carrier"}); err != nil {
		t.Errorf("--category carrier was rejected: %v", err)
	}
}

// Riskier removals go last, so an interrupted run has done the harmless part.
func TestRemovalsOrderedByRisk(t *testing.T) {
	inv := []Inventory{
		{Package: "com.motorola.android.fota", FromImage: true},
		{Package: "com.motorola.android.fmradio", FromImage: true},
		{Package: "com.aura.oobe.motorola", FromImage: true},
	}
	plan := New(catalogRules(), "motorola").Build("dev", inv, []Category{Ads, OEMExtra, Updates}, Invasive)
	var order []Risk
	for _, e := range plan.Removals() {
		order = append(order, e.Risk())
	}
	if len(order) != 3 || order[0] != Safe || order[1] != Caution || order[2] != Invasive {
		t.Errorf("removal order = %v, want safe, caution, invasive", order)
	}
}

// Category and risk are independent axes: the category chooses the subject,
// the risk chooses the appetite. Gating a `safe` package on its category as
// well would make the risk field decorative.
func TestRiskCutoff(t *testing.T) {
	inv := []Inventory{
		{Package: "com.motorola.android.fmradio", FromImage: true}, // oem-extra, caution
		{Package: "com.motorola.android.fota", FromImage: true},    // updates, invasive
		{Package: "com.aura.oobe.motorola", FromImage: true},       // ads, safe
	}
	all := []Category{Ads, Preload, CarrierForeign, OEMExtra, Updates}
	tbl := New(catalogRules(), "motorola")

	names := func(p *Plan) string {
		var got []string
		for _, e := range p.Removals() {
			got = append(got, e.Package)
		}
		sort.Strings(got)
		return strings.Join(got, ",")
	}

	if got := names(tbl.Build("d", inv, all, Safe)); got != "com.aura.oobe.motorola" {
		t.Errorf("at safe: %s, want only the safe one", got)
	}
	if got := names(tbl.Build("d", inv, all, Caution)); got != "com.aura.oobe.motorola,com.motorola.android.fmradio" {
		t.Errorf("at caution: %s", got)
	}
	if got := len(tbl.Build("d", inv, all, Invasive).Removals()); got != 3 {
		t.Errorf("at invasive: %d removals, want all three", got)
	}
	// The held-back entry says *why*, and names the cutoff it exceeded.
	plan := tbl.Build("d", inv, all, Safe)
	for _, e := range plan.Entries {
		if e.Package != "com.motorola.android.fmradio" {
			continue
		}
		if e.State != Keep || !strings.Contains(e.Reason, "above the --max-risk safe") {
			t.Errorf("fmradio: %q / %q", e.State, e.Reason)
		}
	}
	if plan.MaxRisk != Safe {
		t.Errorf("the plan does not record its cutoff: %q", plan.MaxRisk)
	}
}

// The default answers "remove what nothing depends on": every safe entry in the
// categories that describe the device's own software, and nothing that costs a
// feature. The categories left out are the ones whose *category* carries a
// consequence no risk label captures.
func TestDefaultsRemoveEverySafeThing(t *testing.T) {
	inv := []Inventory{
		{Package: "com.aura.oobe.motorola", FromImage: true},       // ads, safe
		{Package: "com.einnovation.temu"},                          // preload, safe
		{Package: "com.motorola.android.fmradio", FromImage: true}, // oem-extra, caution
		{Package: "com.motorola.omadm.att", FromImage: true},       // carrier-foreign, safe
		{Package: "com.motorola.android.fota", FromImage: true},    // updates, invasive
		{Package: "com.motorola.demo", FromImage: true},            // oem-extra, safe
	}
	rules := append(catalogRules(), Rule{
		Name: "com.motorola.demo", Vendor: "motorola", Category: OEMExtra, Risk: Safe, Note: "retail demo",
	})
	plan := New(rules, "motorola").Build("d", inv, DefaultCategories(), DefaultMaxRisk())

	var got []string
	for _, e := range plan.Removals() {
		got = append(got, e.Package)
	}
	sort.Strings(got)
	want := "com.aura.oobe.motorola,com.einnovation.temu,com.motorola.demo"
	if strings.Join(got, ",") != want {
		t.Errorf("default removals = %v, want %s", got, want)
	}
	// A safe OEM extra is in; a caution one is not; and carrier-foreign is out
	// by category even though it is safe, because a SIM change makes it matter.
	reasons := map[string]string{}
	for _, e := range plan.Entries {
		reasons[e.Package] = e.Reason
	}
	if !strings.Contains(reasons["com.motorola.omadm.att"], "not selected") {
		t.Errorf("carrier-foreign was excluded for the wrong reason: %q", reasons["com.motorola.omadm.att"])
	}
	if !strings.Contains(reasons["com.motorola.android.fmradio"], "max-risk") {
		t.Errorf("a caution entry was excluded for the wrong reason: %q", reasons["com.motorola.android.fmradio"])
	}
}

func TestParseRisk(t *testing.T) {
	for in, want := range map[string]Risk{"": Safe, "safe": Safe, "CAUTION": Caution, " invasive ": Invasive} {
		got, err := ParseRisk(in)
		if err != nil || got != want {
			t.Errorf("ParseRisk(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseRisk("whatever"); err == nil {
		t.Error("ParseRisk accepted nonsense")
	}
	// The empty risk on a rule means safe, so an entry that forgot to say is
	// treated as the least consequential thing rather than the most.
	if !Risk("").AtMost(Safe) {
		t.Error("an unset risk is not within the safe cutoff")
	}
	if Caution.AtMost(Safe) || !Caution.AtMost(Invasive) {
		t.Error("risk ordering is wrong")
	}
}

func TestParseCategories(t *testing.T) {
	got, err := ParseCategories([]string{"ads", "OEM-EXTRA", " preload "})
	if err != nil {
		t.Fatalf("ParseCategories: %v", err)
	}
	if len(got) != 3 || got[0] != Ads || got[1] != OEMExtra || got[2] != Preload {
		t.Errorf("ParseCategories = %v", got)
	}
	// The two categories that exist to *not* be selected cannot be selected.
	for _, bad := range []string{"protected", "unknown", "nonsense"} {
		if _, err := ParseCategories([]string{bad}); err == nil {
			t.Errorf("ParseCategories(%q) was accepted", bad)
		}
	}
	// The default set is the categories that describe the device's own
	// software; what holds back a feature-costing entry inside them is the risk
	// cutoff, not the category. See TestDefaultsRemoveEverySafeThing.
	def := DefaultCategories()
	if len(def) != 3 || def[0] != Ads || def[1] != Preload || def[2] != OEMExtra {
		t.Errorf("DefaultCategories() = %v, want ads, preload and oem-extra", def)
	}
	for _, c := range def {
		if c == CarrierOwn || c == CarrierForeign || c == Updates {
			t.Errorf("%s is in the default set, but its category carries a consequence no risk label captures", c)
		}
	}
	if DefaultMaxRisk() != Safe {
		t.Errorf("DefaultMaxRisk() = %q, want safe", DefaultMaxRisk())
	}
}

// The record is the undo, so it has to survive a round trip and keep the two
// kinds of removal apart.
func TestRecordRoundTrip(t *testing.T) {
	rec := &Record{Device: "ZL83"}
	rec.Note(Entry{Package: "com.aura.oobe.motorola", FromImage: true})
	rec.Note(Entry{Package: "com.einnovation.temu"})

	if len(rec.Removed) != 1 || rec.Removed[0] != "com.aura.oobe.motorola" {
		t.Errorf("Removed = %v", rec.Removed)
	}
	if len(rec.RemovedFromData) != 1 || rec.RemovedFromData[0] != "com.einnovation.temu" {
		t.Errorf("RemovedFromData = %v", rec.RemovedFromData)
	}

	var buf bytes.Buffer
	if err := WriteRecord(&buf, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	back, err := ReadRecord(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if back.Device != "ZL83" || len(back.Removed) != 1 || len(back.RemovedFromData) != 1 {
		t.Errorf("round trip lost data: %+v", back)
	}
	if _, err := ReadRecord(strings.NewReader(`{"device":"x"}`)); err == nil {
		t.Error("a record with no removals was accepted")
	}
}

// The built-in floor alone proposes nothing: a tool shipped without its catalog
// should be useless, not dangerous.
func TestBuiltinAloneProposesNothing(t *testing.T) {
	inv := []Inventory{
		{Package: "com.einnovation.temu", FromImage: true},
		{Package: "com.aura.oobe.motorola", FromImage: true},
	}
	plan := Builtin().Build("dev", inv, []Category{Ads, Preload, CarrierForeign, OEMExtra, Updates}, Invasive)
	if got := plan.Removals(); len(got) != 0 {
		t.Errorf("the protective floor proposed %d removals", len(got))
	}
}
