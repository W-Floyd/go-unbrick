// Package distro is what a Linux distribution on a phone needs to say for a
// recon to read it.
//
// Most of that is a table. The differences between postmarketOS, Mobian,
// Droidian and the next one are not differences of mechanism: each ships a file
// somewhere that names the device, in one of a few formats, under one of a few
// key spellings, with the codename written one of a few ways. That belongs in
// catalog/distros.yaml, where adding support for a distribution is an entry
// rather than a release.
//
// The rest is not a table, and pretending otherwise is how a data-driven design
// goes wrong. Where a distribution keeps its device definition has changed
// between its own releases; what a recon can see at all depends on which
// packages happen to be installed; a distribution may need a precondition
// checked and explained before its answers mean anything. So Profile is an
// interface: Distro is its YAML-backed implementation, covering the ordinary
// cases completely, and a distribution that needs real logic is a Go type
// registered beside it.
package distro

import (
	"sort"
	"strconv"
	"strings"
)

// Profile is what a recon asks about a distribution.
type Profile interface {
	// ID is the os-release id this profile is for ("postmarketos").
	ID() string
	// Name is how a report spells it ("postmarketOS").
	Name() string
	// Matches reports whether a collected os-release is this distribution. An
	// exact id is checked before any ID_LIKE claim, so a derivative is itself
	// rather than its parent.
	Matches(id string, idLike []string) bool
	// DeviceFiles are the files that may carry the device definition, best
	// first, gated by the distribution's own version where that has moved. A
	// recon collects every candidate of every profile in one round trip, so
	// this is a list of paths and nothing else — never a command.
	DeviceFiles() []FileSpec
	// Device reads what the installed system claims the hardware is.
	Device(env Env) (Claim, map[string]string)
	// Preconditions are what is missing on this install for the recon to see
	// what it could: an uninstalled device package, a definition file that
	// moved, a tool that is not there. Each carries the fix, because "no
	// codename" with nothing else said sends the operator looking in the wrong
	// place.
	Preconditions(env Env) []Precondition
}

// Env is everything the collection brought back that a profile may need. It is
// passed whole rather than piecemeal so a profile can be as clever as it needs
// without the seam growing a method per question.
type Env struct {
	// The installed system's own identity, from os-release.
	ID, Name, Version, VersionID, BuildID string
	// Files are the collected device-definition candidates, keyed by the path
	// they were read from. A path that was not there is absent, which is what a
	// precondition looks at.
	Files map[string]string
	// Commands are the helper commands found on the device.
	Commands map[string]bool
	// Sections is the raw collection, for a profile that needs something the
	// fields above do not carry.
	Sections map[string]string
	// DTCodename and DTVendor are what the device tree calls this device, which
	// is the fallback when the distribution itself does not say.
	DTCodename, DTVendor string
}

// Claim is what a distribution's own device definition says the hardware is.
// It is a claim, not a measurement: the packager wrote it, so a recon treats it
// as Derived and lets the device's own answers outrank it.
type Claim struct {
	Codename     string // the OEM codename, vendor prefix removed
	VendorID     string // the OEM, lowercased, when the definition names one
	Name         string // marketing name, e.g. "Motorola Moto G Play (2024)"
	Manufacturer string
	Chassis      string
	Year         string
	Arch         string
	// From is the path the claim was read from, for the report's provenance.
	From string
}

// Precondition is something an install is missing, and what to do about it.
type Precondition struct {
	What string // "deviceinfo file"
	Why  string // what having it would tell the recon
	Fix  string // the command or package that provides it
}

func (p Precondition) String() string {
	s := p.What
	if p.Why != "" {
		s += " — " + p.Why
	}
	if p.Fix != "" {
		s += " (" + p.Fix + ")"
	}
	return s
}

// FileSpec is one device-definition candidate, optionally gated by the
// distribution's version: postmarketOS moved deviceinfo out of /etc, and a
// recon that knows both places does not need to care which release it met.
type FileSpec struct {
	Path string `yaml:"path"`
	// Since and Until bound the versions this path applies to, compared against
	// os-release VERSION_ID. Empty means unbounded. A rolling release whose
	// version does not parse (postmarketOS "edge") is treated as the newest
	// there is, which is what it is.
	Since string `yaml:"since,omitempty"`
	Until string `yaml:"until,omitempty"`
}

// applies reports whether a version is in this spec's range.
func (f FileSpec) applies(versionID string) bool {
	if f.Since == "" && f.Until == "" {
		return true
	}
	v, known := parseVersion(versionID)
	if !known {
		// An unparseable or absent version (edge, git builds) is newest: the
		// current path applies and a since-gate does not exclude it.
		return f.Until == ""
	}
	if f.Since != "" {
		if s, ok := parseVersion(f.Since); ok && compareVersion(v, s) < 0 {
			return false
		}
	}
	if f.Until != "" {
		if u, ok := parseVersion(f.Until); ok && compareVersion(v, u) >= 0 {
			return false
		}
	}
	return true
}

// Distro is one entry of distros.yaml: a distribution whose device definition
// is a table lookup.
type Distro struct {
	Ident   string   `yaml:"id"`
	Title   string   `yaml:"name,omitempty"`
	IDLike  []string `yaml:"id_like,omitempty"` // also claim distributions derived from these
	Aliases []string `yaml:"aliases,omitempty"` // other os-release ids that are this distribution

	Files []FileSpec `yaml:"device_files,omitempty"`

	// Format is how a candidate file is parsed:
	//   shell — KEY="value" assignments (postmarketOS deviceinfo, os-release)
	//   props — key=value Android-style properties
	//   plain — the whole file is the codename (a one-line marker file)
	Format string `yaml:"format,omitempty"`

	// Prefix is stripped from every key before the mappings below apply, so a
	// deviceinfo's "deviceinfo_codename" is asked for as "codename".
	Prefix string `yaml:"key_prefix,omitempty"`

	// Keys maps what this recon wants to what the file calls it. Each defaults
	// to the obvious spelling, so an entry only names what differs.
	Keys struct {
		Codename     string `yaml:"codename,omitempty"`
		Name         string `yaml:"name,omitempty"`
		Manufacturer string `yaml:"manufacturer,omitempty"`
		Chassis      string `yaml:"chassis,omitempty"`
		Year         string `yaml:"year,omitempty"`
		Arch         string `yaml:"arch,omitempty"`
	} `yaml:"keys,omitempty"`

	// CodenameStyle says how to read the codename value:
	//   vendor-dash — "<vendor>-<codename>", as postmarketOS names device packages
	//   plain       — the value is the codename
	CodenameStyle string `yaml:"codename_style,omitempty"`

	// Needs are the declarative preconditions: each fires when none of the
	// device-definition files were found, or when a named command is missing.
	Needs []Need `yaml:"needs,omitempty"`

	// Notes is for whoever maintains the table: what is known about this
	// distribution's device definition first-hand, and what is inference.
	Notes string `yaml:"notes,omitempty"`
}

// Need is a declarative precondition. It is deliberately narrow — "a file is
// missing" and "a command is missing" are what a table can state honestly;
// anything conditional on a version, a service or another package is what a Go
// profile is for.
type Need struct {
	What        string `yaml:"what"`
	Why         string `yaml:"why,omitempty"`
	Fix         string `yaml:"fix,omitempty"`
	WhenNoFiles bool   `yaml:"when_no_device_files,omitempty"`
	WhenNoCmd   string `yaml:"when_missing_command,omitempty"`
}

func (d *Distro) ID() string { return d.Ident }

func (d *Distro) Name() string {
	if d.Title != "" {
		return d.Title
	}
	return d.Ident
}

func (d *Distro) Matches(id string, idLike []string) bool {
	if id != "" {
		if strings.EqualFold(id, d.Ident) {
			return true
		}
		for _, a := range d.Aliases {
			if strings.EqualFold(id, a) {
				return true
			}
		}
	}
	for _, like := range idLike {
		for _, want := range d.IDLike {
			if strings.EqualFold(like, want) {
				return true
			}
		}
	}
	return false
}

func (d *Distro) DeviceFiles() []FileSpec { return d.Files }

// Device reads the first candidate file this install actually has, of those
// that apply to its version.
func (d *Distro) Device(env Env) (Claim, map[string]string) {
	for _, spec := range d.Files {
		if !spec.applies(env.VersionID) {
			continue
		}
		content, ok := env.Files[spec.Path]
		if !ok || strings.TrimSpace(content) == "" {
			continue
		}
		claim, kv := d.parse(content)
		claim.From = spec.Path
		return claim, kv
	}
	return Claim{}, nil
}

func (d *Distro) parse(content string) (Claim, map[string]string) {
	if d.Format == "plain" {
		v := firstLine(content)
		c := Claim{}
		c.Codename, c.VendorID = splitCodename(v, d.CodenameStyle)
		return c, map[string]string{"codename": v}
	}
	kv := parseAssignments(content, d.Prefix)
	key := func(want, dflt string) string {
		if want != "" {
			return kv[strings.ToLower(want)]
		}
		return kv[dflt]
	}
	c := Claim{
		Name:         key(d.Keys.Name, "name"),
		Manufacturer: key(d.Keys.Manufacturer, "manufacturer"),
		Chassis:      key(d.Keys.Chassis, "chassis"),
		Year:         key(d.Keys.Year, "year"),
		Arch:         key(d.Keys.Arch, "arch"),
	}
	c.Codename, c.VendorID = splitCodename(key(d.Keys.Codename, "codename"), d.CodenameStyle)
	return c, kv
}

// Preconditions fires the entry's declared needs.
func (d *Distro) Preconditions(env Env) []Precondition {
	haveFile := false
	for _, spec := range d.Files {
		if c, ok := env.Files[spec.Path]; ok && strings.TrimSpace(c) != "" {
			haveFile = true
			break
		}
	}
	var out []Precondition
	for _, n := range d.Needs {
		switch {
		case n.WhenNoFiles && !haveFile:
		case n.WhenNoCmd != "" && !env.Commands[n.WhenNoCmd]:
		default:
			continue
		}
		out = append(out, Precondition{What: n.What, Why: n.Why, Fix: n.Fix})
	}
	return out
}

// splitCodename reads a codename value the way the entry says it is written.
// postmarketOS names its device packages "<vendor>-<codename>" (motorola-fogona)
// and the part after the dash is the OEM's own codename — the same string a
// bootloader answers `getvar product` with, which is what makes it resolvable
// against the device catalog.
func splitCodename(v, style string) (codename, vendor string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", ""
	}
	if style == "plain" {
		return v, ""
	}
	if vend, rest, ok := strings.Cut(v, "-"); ok && rest != "" {
		return rest, strings.ToLower(vend)
	}
	return v, ""
}

// parseAssignments reads KEY=value lines, unquoting values and dropping a
// common key prefix. Both the shell and props formats are this: the difference
// between them is quoting, and unquoting is unconditional.
func parseAssignments(content, prefix string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if prefix != "" {
			k = strings.TrimPrefix(k, prefix)
		}
		if k == "" {
			continue
		}
		out[strings.ToLower(k)] = unquote(v)
	}
	return out
}

// Set is the loaded table: the built-ins, whatever Go profiles registered, and
// the catalog's entries, which win where they overlap.
type Set struct{ profiles []Profile }

// Profiles returns every entry.
func (s *Set) Profiles() []Profile {
	if s == nil {
		return nil
	}
	return s.profiles
}

// Match picks the profile for a collected os-release, or nil when no entry
// claims it — which is not a failure: a recon over an unknown distribution
// still has the device tree, the partition table and the kernel command line.
func (s *Set) Match(id string, idLike []string) Profile {
	if s == nil {
		return nil
	}
	for _, p := range s.profiles {
		if p.Matches(id, nil) {
			return p
		}
	}
	for _, p := range s.profiles {
		if p.Matches("", idLike) {
			return p
		}
	}
	return nil
}

// DeviceFiles is every device-definition candidate any profile declares,
// deduplicated. One round trip collects them all and the matched profile
// decides which it wanted — cheaper than knowing the distribution first.
func (s *Set) DeviceFiles() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range s.Profiles() {
		for _, f := range p.DeviceFiles() {
			if f.Path == "" || seen[f.Path] {
				continue
			}
			seen[f.Path] = true
			out = append(out, f.Path)
		}
	}
	sort.Strings(out)
	return out
}

// New is the table a recon reads an install with: the built-in profiles, any
// Go-backed ones that registered, and the catalog's entries — which win where
// they share an id, so the catalog is authoritative on what it states and the
// code covers what it omits.
//
// The entries come from the device catalog (catalog/distros.yaml, loaded by
// internal/catalog with the rest of the reference data) rather than being read
// here: one loader for the YAML, one interpreter for what it means.
func New(entries []*Distro) *Set {
	byID := map[string]Profile{}
	for _, p := range builtin() {
		byID[p.ID()] = p
	}
	for _, p := range registered() {
		byID[p.ID()] = p
	}
	for _, d := range entries {
		if d == nil || d.Ident == "" {
			continue
		}
		byID[d.Ident] = d
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	set := &Set{profiles: make([]Profile, 0, len(ids))}
	for _, id := range ids {
		set.profiles = append(set.profiles, byID[id])
	}
	return set
}

// Builtin is the table without any catalog: the distributions the code knows
// first-hand, plus whatever registered.
func Builtin() *Set { return New(nil) }

// Register adds a Go-backed profile — for a distribution whose device
// definition needs logic a table cannot state: a version-dependent layout, a
// precondition that depends on more than one thing being present, an identity
// that has to be computed. Called from an init function, like vendor.Register.
func Register(p Profile) {
	if p == nil || p.ID() == "" {
		return
	}
	custom[p.ID()] = p
}

var custom = map[string]Profile{}

func registered() []Profile {
	ids := make([]string, 0, len(custom))
	for id := range custom {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Profile, 0, len(ids))
	for _, id := range ids {
		out = append(out, custom[id])
	}
	return out
}

// builtin is the table a recon has without any catalog: the distribution whose
// device definition is known first-hand.
func builtin() []Profile {
	return []Profile{&Distro{
		Ident: "postmarketos", Title: "postmarketOS",
		Files: []FileSpec{
			// deviceinfo moved out of /etc as the device packages were
			// restructured; both paths are read, and the newer one is preferred
			// on an install whose version does not say (edge).
			{Path: "/usr/share/deviceinfo/deviceinfo"},
			{Path: "/etc/deviceinfo"},
			{Path: "/usr/share/misc/deviceinfo"},
		},
		Format: "shell", Prefix: "deviceinfo_", CodenameStyle: "vendor-dash",
		Needs: []Need{{
			What:        "no deviceinfo file",
			Why:         "it is what names the device by the OEM codename the catalog and the bootloader both use",
			Fix:         "install this device's postmarketOS device package (apk add device-<vendor>-<codename>)",
			WhenNoFiles: true,
		}},
		Notes: "device packages are named <vendor>-<codename>, which is the OEM codename the bootloader also reports",
	}}
}

// parseVersion reads a dotted numeric version ("24.06", "12.1") into its parts.
// A version that is not one — "edge", "unstable", a git description — is not a
// version, and the caller treats that as newest.
func parseVersion(s string) ([]int, bool) {
	s = strings.TrimSpace(strings.Trim(s, `"'`))
	if s == "" {
		return nil, false
	}
	var out []int
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

func compareVersion(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			return t
		}
	}
	return ""
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
