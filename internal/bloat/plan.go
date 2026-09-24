package bloat

// Turning an inventory into a plan, and a plan into something reversible.
//
// The plan is the product here, not the removal: an operator should be able to
// read what is about to happen, why each package is on the list, and what stops
// working — and then decide. So a plan is built and printed by default, and
// applying it is a separate, explicit act.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Entry is one package, classified.
type Entry struct {
	Package string `json:"package"`
	Rule    Rule   `json:"-"`
	Known   bool   `json:"-"`
	State   State  `json:"state"`
	Reason  string `json:"reason,omitempty"`
	// FromImage says whether removing this one is locally reversible: an APK in
	// a read-only image partition comes back with `install-existing`, while one
	// a delivery agent dropped in /data is gone until the Play Store is asked.
	FromImage bool   `json:"from_image"`
	Result    string `json:"result,omitempty"` // filled in when applied
	Err       string `json:"error,omitempty"`
}

// Category and Risk of the governing rule, for the report.
func (e Entry) Category() Category { return e.Rule.Category }
func (e Entry) Risk() Risk         { return e.Rule.Risk }
func (e Entry) Note() string       { return e.Rule.Note }

// State is what the plan proposes for a package, or why it does not.
type State string

const (
	// Remove is the only action a plan ever takes.
	Remove State = "remove"
	// Keep is a package the table protects, or one no selected category names.
	Keep State = "keep"
	// Gone is already uninstalled for this user — nothing to do, and it is
	// listed so a second run reads as "already done" rather than silent.
	Gone State = "gone"
	// Blocked is bloat the device will not part with: a package in the build's
	// protected list, which refuses both uninstall and disable. Classified and
	// reported, never proposed — proposing it would be proposing a failure.
	Blocked State = "blocked-by-device"
	// Off is already disabled for this user. A disabled package does not run,
	// which is the whole objective, so proposing an uninstall on top of it buys
	// nothing — and on a privileged system package the device refuses anyway,
	// which is how this state was found: com.amazon.appmanager shipped disabled
	// and answered "package is non-disable".
	Off State = "already-disabled"
	// NotPreloaded is the user's own install. Out of scope: a debloat tool that
	// removes what someone chose to install is a different, worse tool.
	NotPreloaded State = "user-installed"
)

// Inventory is what a device reported about one package.
type Inventory struct {
	Package string
	// FromImage is true when the APK sits in a read-only image partition, which
	// is what makes a removal restorable: `install-existing` can only bring back
	// an APK that is still there.
	//
	// It is *not* the test for whether a package is bloat. The sponsored apps a
	// delivery agent installs during setup land in /data/app, indistinguishable
	// by path from something the owner chose — which is exactly why the table
	// names them: knowledge decides what is bloat, the path decides only whether
	// putting it back is a local operation or a trip to the Play Store.
	FromImage   bool
	Uninstalled bool
	Disabled    bool
}

// Plan is a classified inventory plus the selection that produced it.
type Plan struct {
	Device     string    `json:"device"`
	Categories []string  `json:"categories"`
	MaxRisk    Risk      `json:"max_risk"`
	Created    time.Time `json:"created"`
	Entries    []Entry   `json:"entries"`
}

// Build classifies an inventory and proposes removals that are both in a
// selected category and within the risk cutoff. Everything else is kept, with
// the reason recorded — a plan that silently omits what it did not choose
// cannot be audited.
//
// The two axes are deliberately independent. A category says what a package is
// *for* and who put it there; a risk says what removing it *costs*. Conflating
// them is how a taxonomy ends up decorative: if "safe" means "no function a
// stock phone depends on", then withholding a safe package because of its
// category is a second, unstated policy — so the category chooses the subject
// and the risk chooses the appetite.
func (t *Table) Build(device string, inv []Inventory, selected []Category, maxRisk Risk) *Plan {
	want := map[Category]bool{}
	var names []string
	for _, c := range selected {
		want[c] = true
		names = append(names, string(c))
	}
	sort.Strings(names)
	if maxRisk == "" {
		maxRisk = Safe
	}

	p := &Plan{Device: device, Categories: names, MaxRisk: maxRisk, Created: time.Now().UTC()}
	for _, item := range inv {
		rule, known := t.Classify(item.Package)
		e := Entry{Package: item.Package, Rule: rule, Known: known, FromImage: item.FromImage}
		switch {
		case item.Uninstalled:
			e.State, e.Reason = Gone, "already uninstalled for this user"
		case item.Disabled:
			// A disabled package does not run, which is the objective. Offering
			// an uninstall on top buys nothing, and a privileged system package
			// in this state refuses it anyway ("package is non-disable").
			e.State, e.Reason = Off, "already disabled for this user, so it does not run"
		case !known && !item.FromImage:
			// Not in the table and not in the image: the owner's own app. A
			// debloat tool that removes what someone chose to install is a
			// different, worse tool.
			e.State, e.Reason = NotPreloaded, "installed by the user, not by the image, and not named in the catalog"
		case rule.Blocked:
			e.State, e.Reason = Blocked, "this build protects it: "+rule.Note
		case rule.Category == Protected:
			e.State, e.Reason = Keep, "protected: "+rule.Note
		case rule.Category == Unknown:
			e.State, e.Reason = Keep, rule.Note
		case !want[rule.Category]:
			e.State, e.Reason = Keep, fmt.Sprintf("category %s not selected", rule.Category)
		case !rule.Risk.AtMost(maxRisk):
			e.State, e.Reason = Keep, fmt.Sprintf("risk %s is above the --max-risk %s cutoff", rule.Risk, maxRisk)
		default:
			e.State = Remove
		}
		p.Entries = append(p.Entries, e)
	}
	sort.SliceStable(p.Entries, func(i, j int) bool { return p.Entries[i].Package < p.Entries[j].Package })
	return p
}

// Removals are the packages the plan would remove, in the order it would act.
// Riskier removals go last, so an interrupted run has done the harmless part.
func (p *Plan) Removals() []Entry {
	var out []Entry
	for _, e := range p.Entries {
		if e.State == Remove {
			out = append(out, e)
		}
	}
	rank := map[Risk]int{Safe: 0, "": 0, Caution: 1, Invasive: 2}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Risk()] < rank[out[j].Risk()] })
	return out
}

// ByCategory groups entries for the report, in a fixed order so two runs read
// the same way.
func (p *Plan) ByCategory(state State) ([]Category, map[Category][]Entry) {
	groups := map[Category][]Entry{}
	for _, e := range p.Entries {
		if e.State != state {
			continue
		}
		groups[e.Category()] = append(groups[e.Category()], e)
	}
	order := []Category{Ads, Preload, CarrierOwn, CarrierForeign, OEMExtra, Updates, Protected, Unknown}
	var used []Category
	for _, c := range order {
		if len(groups[c]) > 0 {
			used = append(used, c)
		}
	}
	return used, groups
}

// Unknowns are the packages the table does not name, which is what a
// maintainer needs to extend it.
func (p *Plan) Unknowns() []string {
	installed, inactive := p.UnknownsByState()
	out := append(append([]string{}, installed...), inactive...)
	sort.Strings(out)
	return out
}

// UnknownsByState splits the unclassified packages by whether they are still
// running on the device.
//
// The split exists because one total served two purposes and appeared to
// contradict itself: a report that said "150 unknown" beside "201 packages are
// not in the catalog" was counting the same set twice, once excluding the ones
// already removed or shipped disabled. Both numbers were right, which is the
// worst kind of confusing.
//
// installed is what a maintainer should classify next; inactive is already
// harmless, and worth classifying only for completeness.
func (p *Plan) UnknownsByState() (installed, inactive []string) {
	for _, e := range p.Entries {
		if e.Known || e.State == NotPreloaded {
			continue
		}
		switch e.State {
		case Gone, Off:
			inactive = append(inactive, e.Package)
		default:
			installed = append(installed, e.Package)
		}
	}
	sort.Strings(installed)
	sort.Strings(inactive)
	return installed, inactive
}

// Record is what an applied plan writes: enough to undo it, and enough to say
// afterwards what actually happened to each package.
type Record struct {
	Device  string    `json:"device"`
	Applied time.Time `json:"applied"`
	// Removed are the image APKs, which --restore puts back with
	// `install-existing`.
	Removed []string `json:"removed"`
	// RemovedFromData were installed in /data by a delivery agent, so the APK
	// went with them. They are recorded separately because --restore cannot
	// bring them back — the Play Store can, and the record is what tells the
	// owner which ones those are.
	RemovedFromData []string `json:"removed_from_data,omitempty"`
	// Disabled are the ones the shell may not uninstall — privileged system
	// packages, which answer DELETE_FAILED_INTERNAL_ERROR or "package is
	// non-disable" — and which were disabled instead. A disabled package does
	// not run, so the objective is met; --restore re-enables them.
	Disabled []string `json:"disabled,omitempty"`
	Failed   []Entry  `json:"failed,omitempty"`
}

// NoteDisabled records a package that could only be disabled.
func (r *Record) NoteDisabled(pkg string) { r.Disabled = append(r.Disabled, pkg) }

// Note adds a removal to the record, on the side that says whether it can be
// undone locally.
func (r *Record) Note(e Entry) {
	if e.FromImage {
		r.Removed = append(r.Removed, e.Package)
		return
	}
	r.RemovedFromData = append(r.RemovedFromData, e.Package)
}

// WriteRecord saves the record as JSON.
func WriteRecord(w io.Writer, r *Record) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ReadRecord loads a record written by a previous apply.
func ReadRecord(r io.Reader) (*Record, error) {
	var rec Record
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, err
	}
	if len(rec.Removed) == 0 && len(rec.RemovedFromData) == 0 && len(rec.Disabled) == 0 {
		return nil, fmt.Errorf("the record lists nothing that was removed or disabled")
	}
	return &rec, nil
}

// ParseCategories turns the operator's --category list into categories,
// refusing one that is not a category and one that would select the protected
// set (which is not selectable by design).
func ParseCategories(vals []string) ([]Category, error) {
	allowed := map[Category]bool{Ads: true, Preload: true, CarrierOwn: true,
		CarrierForeign: true, OEMExtra: true, Updates: true}
	var out []Category
	for _, v := range vals {
		c := Category(strings.ToLower(strings.TrimSpace(v)))
		switch {
		case c == "":
			continue
		case c == Protected:
			return nil, fmt.Errorf("the protected category is not selectable: those packages cost calls, data, activation or the ability to carrier-unlock")
		case c == Unknown:
			return nil, fmt.Errorf("the unknown category is not selectable: nothing is known about those packages, which is the point — see --list and catalog/bloat.yaml")
		case !allowed[c]:
			return nil, fmt.Errorf("unknown category %q (have: ads, preload, carrier, carrier-foreign, oem-extra, updates)", v)
		}
		out = append(out, c)
	}
	return out, nil
}

// DefaultCategories is what a run considers when the operator names none: the
// sponsored-app machinery, the third-party apps it delivers, and the
// manufacturer's optional software.
//
// Paired with DefaultMaxRisk, that means "everything nothing depends on" —
// which is what the risk field already claims about a `safe` entry. The
// categories left out are the ones where the *category itself* carries a
// consequence no risk label captures: `carrier` (this device's own service),
// `carrier-foreign` (harmless now, relevant if the SIM changes) and `updates`
// (security patches). Those are asked for by name.
func DefaultCategories() []Category { return []Category{Ads, Preload, OEMExtra} }

// DefaultMaxRisk is the appetite a run has when the operator sets none: remove
// what costs nothing, list the rest. An entry that takes a feature with it
// (`caution`) or that may touch activation or updates (`invasive`) is named in
// the plan with what it costs, and waits to be asked for.
func DefaultMaxRisk() Risk { return Safe }
