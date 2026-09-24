// Package provision turns a device-setup recipe into a plan of exact adb
// commands, and runs it only when told to.
//
// The shape follows the rest of this tool: the *recipe* is data
// (catalog/provision.yaml), the *verbs* are code. A recipe can say "install
// this APK, make it device owner, grant it these permissions, start it with
// these extras, then verify" because those are verbs this package implements;
// it cannot say "run this shell command", because a table that can run
// arbitrary commands on a phone is not a table, it is a script with fewer
// safeguards.
//
// What the operator sees first is every command that would run, in order, with
// the irreversible ones marked. Nothing executes without --apply.
package provision

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Profile is one recipe: everything needed to provision a device for a purpose.
type Profile struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name,omitempty"`
	// Vendor scopes a recipe to one OEM's devices, as a catalog vendor id
	// ("motorola"). Empty means any device, which is what a recipe for an app
	// like a kiosk shell should be: the app does not care who built the phone.
	// A recipe that leans on one OEM's packages or one OEM's quirks says so
	// here, and is then not offered on anything else.
	Vendor string `yaml:"vendor,omitempty"`
	// Doc is where the steps came from. A recipe that cannot be checked against
	// upstream documentation is a recipe nobody should run.
	Doc string `yaml:"doc,omitempty"`
	// Package is the app being provisioned, used by the preflight checks.
	Package string  `yaml:"package,omitempty"`
	APK     APKSpec `yaml:"apk,omitempty"`
	// APKs are the named ones, for a recipe that installs more than one app.
	// The operator supplies each with --apk <name>=<path>, and an install step
	// names which it wants. A recipe with a single unnamed apk: keeps using it.
	APKs  map[string]APKSpec `yaml:"apks,omitempty"`
	Needs Needs              `yaml:"requires,omitempty"`
	Vars  []Var              `yaml:"vars,omitempty"`
	Steps []Step             `yaml:"steps,omitempty"`
	Notes []string           `yaml:"notes,omitempty"`
}

// APKFor returns the spec for a named APK, or the unnamed one.
func (p *Profile) APKFor(name string) (APKSpec, bool) {
	if name == "" {
		return p.APK, p.APK.Source != "" || p.APK.SHA256 != ""
	}
	spec, ok := p.APKs[name]
	return spec, ok
}

// APKNames lists the APKs a recipe installs, "" for an unnamed single one.
func (p *Profile) APKNames() []string {
	var out []string
	for _, st := range p.Steps {
		if st.Install == nil {
			continue
		}
		out = append(out, st.Install.APK)
	}
	sort.Strings(out)
	return out
}

// APKSpec says where an APK comes from, precisely enough that the tool can
// fetch it: a GitHub repository ("github:owner/repo", or its URL) plus the
// asset to take from a release, or a direct URL to an .apk.
//
// Downloading and installing a binary on someone's phone is the most
// consequential thing here, so the fetch is built to be checkable: the plan
// names the resolved asset, tag and URL before anything is transferred, the
// download happens only under --apply, `sha256` is verified when a recipe pins
// it, and the digest of whatever was installed is printed and recorded either
// way. See fetch.go.
type APKSpec struct {
	Source string `yaml:"source,omitempty"`
	// Asset picks one file out of a release, as a '*' glob
	// ("app-full-release.apk", "freekiosk-*.apk"). Needed when a release ships
	// more than one APK: choosing between a full and a minimal build is not a
	// decision to make silently.
	Asset string `yaml:"asset,omitempty"`
	// Tag is a release tag; empty or "latest" takes the latest release.
	Tag string `yaml:"tag,omitempty"`
	// SHA256 pins the file. A recipe that pins installs the same bytes every
	// time; one that does not still reports what it installed.
	SHA256 string `yaml:"sha256,omitempty"`
}

// Needs are the preconditions a recipe declares, checked before anything runs.
type Needs struct {
	MinSDK int `yaml:"min_sdk,omitempty"`
	// NoAccounts is the device-owner precondition: `dpm set-device-owner`
	// refuses on a device with any account configured, and the refusal is late
	// and cryptic, so it is checked up front.
	NoAccounts bool `yaml:"no_accounts,omitempty"`
	// NoDeviceOwner refuses to run where an owner is already set, rather than
	// letting dpm fail halfway through a recipe.
	NoDeviceOwner bool `yaml:"no_device_owner,omitempty"`
}

// Var is a value the operator supplies with --var name=value.
type Var struct {
	Name     string `yaml:"name"`
	Required bool   `yaml:"required,omitempty"`
	Default  string `yaml:"default,omitempty"`
	// Secret marks a value that must not be printed: it ends up on a shell
	// command line on the device, where any process can read it out of
	// /proc — worth saying once, and worth never echoing into a terminal or a
	// record.
	Secret bool   `yaml:"secret,omitempty"`
	Note   string `yaml:"note,omitempty"`
}

// Step is one action. Exactly one verb field is set; the rest are nil.
type Step struct {
	Install     *InstallStep  `yaml:"install,omitempty"`
	DeviceOwner *OwnerStep    `yaml:"device_owner,omitempty"`
	Grant       *GrantStep    `yaml:"grant,omitempty"`
	AppOp       *AppOpStep    `yaml:"appop,omitempty"`
	Start       *StartStep    `yaml:"start,omitempty"`
	Settings    *SettingsStep `yaml:"settings,omitempty"`
	Disable     *PkgStep      `yaml:"disable,omitempty"`
	Enable      *PkgStep      `yaml:"enable,omitempty"`
	Uninstall   *PkgStep      `yaml:"uninstall,omitempty"`
	DeviceIdle  *PkgStep      `yaml:"battery_unrestricted,omitempty"`
	Open        *OpenStep     `yaml:"open,omitempty"`
	Manual      *ManualStep   `yaml:"manual,omitempty"`
	Verify      *VerifyStep   `yaml:"verify,omitempty"`
	// When names a var that must be non-empty for this step to apply, which is
	// how one recipe covers "lock to an app" and "show a URL" without two
	// almost-identical recipes.
	When string `yaml:"when,omitempty"`
	Note string `yaml:"note,omitempty"`
}

type InstallStep struct {
	// APK names which of the recipe's APKs this step installs, matching a key
	// of Profile.APKs. Empty means the single unnamed one.
	APK string `yaml:"apk,omitempty"`
	// Reinstall passes -r, keeping data across an upgrade.
	Reinstall bool `yaml:"reinstall,omitempty"`
	// Grants passes -g, granting the runtime permissions the manifest declares.
	Grants bool `yaml:"grant_runtime_permissions,omitempty"`
}

type OwnerStep struct {
	Component string `yaml:"component"`
	// Remove makes this the inverse verb (`dpm remove-active-admin`).
	Remove bool `yaml:"remove,omitempty"`
}

type GrantStep struct {
	Package    string `yaml:"package,omitempty"`
	Permission string `yaml:"permission"`
}

type AppOpStep struct {
	Package string `yaml:"package,omitempty"`
	Op      string `yaml:"op"`
	Mode    string `yaml:"mode"`
}

// StartStep is an activity launch with typed extras — the mechanism a
// configurable app usually exposes for headless setup.
type StartStep struct {
	Component string            `yaml:"component"`
	Strings   map[string]string `yaml:"strings,omitempty"` // --es
	Bools     map[string]string `yaml:"bools,omitempty"`   // --ez
	Ints      map[string]string `yaml:"ints,omitempty"`    // --ei
}

type SettingsStep struct {
	Namespace string `yaml:"namespace"` // global | system | secure
	Key       string `yaml:"key"`
	Value     string `yaml:"value"`
}

type PkgStep struct {
	Package string `yaml:"package"`
}

// OpenStep launches a settings screen or other intent action by name, so a
// manual step can put the operator on the right screen instead of describing
// where to find it. An action, never a shell command.
type OpenStep struct {
	Action string `yaml:"action"`
	// Extra is an optional single string extra, which is what the account and
	// app-detail settings screens take.
	ExtraKey   string `yaml:"extra_key,omitempty"`
	ExtraValue string `yaml:"extra_value,omitempty"`
}

// ManualStep is a step nobody can automate: signing into an app, confirming a
// prompt on the device's own screen. A provisioning flow that pretends these do
// not exist is a flow that silently half-works, so they are first-class — the
// plan lists them in order, and a run pauses on them.
type ManualStep struct {
	Do string `yaml:"do"`
	// Why explains what breaks if it is skipped.
	Why string `yaml:"why,omitempty"`
}

// VerifyStep reads something back and checks it, so a recipe can end by
// confirming what it did rather than assuming.
type VerifyStep struct {
	// What is the thing to read: "owners" (dpm list-owners), "packages"
	// (installed packages), "accounts" (configured accounts). A closed set on
	// purpose — see the package comment.
	What     string `yaml:"what"`
	Contains string `yaml:"contains,omitempty"`
	Absent   string `yaml:"absent,omitempty"`
}

// Action is one rendered step: the command that would run and what it means.
type Action struct {
	Describe string
	// Command is the shell command as it will be sent to the device. It is what
	// the plan prints, so an operator can copy it, read it, or refuse it.
	Command string
	// Install marks the one action that is not a shell command: an APK push and
	// install, which needs the local file. APKName says which of the recipe's
	// APKs it wants ("" for a single unnamed one).
	Install bool
	APKName string
	// Irreversible marks an action that cannot be undone on the device —
	// setting a device owner, which then needs a factory reset to clear.
	Irreversible bool
	// Manual marks a step only a person at the device can do: signing into an
	// app, answering a prompt on its screen. A run pauses on these rather than
	// skipping them silently, which is the difference between a flow that
	// finishes and one that looks finished.
	Manual bool
	// Secret marks a command whose text contains a value the operator asked not
	// to have printed; Masked is that command with those values replaced. The
	// plan prints Masked and the run sends Command — a note saying "masked"
	// over a command with the PIN still in it is worse than no note at all.
	Secret bool
	Masked string
	Note   string
	Verify *VerifyStep
}

// Print is the command as it should be shown to a person.
func (a Action) Print() string {
	if a.Secret && a.Masked != "" {
		return a.Masked
	}
	return a.Command
}

var varPattern = regexp.MustCompile(`\{\{([a-zA-Z0-9_]+)\}\}`)

// Render turns a profile into the actions it would perform, substituting vars.
// An unresolved required var is an error before anything runs, not a surprise
// halfway through.
func (p *Profile) Render(vars map[string]string) ([]Action, error) {
	resolved, secrets, err := p.resolve(vars)
	if err != nil {
		return nil, err
	}
	sub := func(s string) string {
		return varPattern.ReplaceAllStringFunc(s, func(m string) string {
			return resolved[varPattern.FindStringSubmatch(m)[1]]
		})
	}
	// mask replaces every secret value in a rendered command, and says whether
	// it found any.
	mask := func(s string) (string, bool) {
		found := false
		for name := range secrets {
			v := resolved[name]
			if v == "" || !strings.Contains(s, v) {
				continue
			}
			found = true
			s = strings.ReplaceAll(s, v, strings.Repeat("•", len([]rune(v))))
		}
		return s, found
	}
	pkg := sub(p.Package)

	var out []Action
	for i, st := range p.Steps {
		if st.When != "" && resolved[st.When] == "" {
			continue // this variant of the recipe was not asked for
		}
		a, err := p.renderStep(st, pkg, sub)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", i+1, err)
		}
		// The recipe's note adds to the verb's own, never replaces it: the verb
		// note is where "this needs a factory reset to undo" lives, and a
		// recipe should not be able to write that off the screen.
		a.Note = joinNotes(a.Note, sub(st.Note))
		a.Masked, a.Secret = mask(a.Command)
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("nothing to do: every step of %q is gated on a var that was not given", p.ID)
	}
	return out, nil
}

func (p *Profile) renderStep(st Step, pkg string, sub func(string) string) (Action, error) {
	switch {
	case st.Install != nil:
		flags := ""
		if st.Install.Reinstall {
			flags += " -r"
		}
		if st.Install.Grants {
			flags += " -g"
		}
		name := st.Install.APK
		what, flag := "the APK", "--apk <file>"
		if name != "" {
			what, flag = name, "--apk "+name+"=<file>"
		}
		return Action{
			Describe: "install " + what + flags,
			Command:  "pm install" + flags + " <" + flag + ">",
			Install:  true,
			APKName:  name,
		}, nil

	case st.DeviceOwner != nil:
		comp := sub(st.DeviceOwner.Component)
		if comp == "" {
			return Action{}, fmt.Errorf("device_owner needs a component")
		}
		if st.DeviceOwner.Remove {
			return Action{
				Describe: "remove the device owner",
				Command:  "dpm remove-active-admin " + shellQuote(comp),
			}, nil
		}
		return Action{
			Describe:     "make it device owner",
			Command:      "dpm set-device-owner " + shellQuote(comp),
			Irreversible: true,
			Note: "a device owner cannot be removed without a factory reset on most builds; " +
				"it also requires that no accounts are configured",
		}, nil

	case st.Grant != nil:
		target := firstNonEmpty(sub(st.Grant.Package), pkg)
		if target == "" || st.Grant.Permission == "" {
			return Action{}, fmt.Errorf("grant needs a package and a permission")
		}
		return Action{
			Describe: "grant " + st.Grant.Permission,
			Command:  fmt.Sprintf("pm grant %s %s", shellQuote(target), shellQuote(st.Grant.Permission)),
		}, nil

	case st.AppOp != nil:
		target := firstNonEmpty(sub(st.AppOp.Package), pkg)
		if target == "" || st.AppOp.Op == "" || st.AppOp.Mode == "" {
			return Action{}, fmt.Errorf("appop needs a package, an op and a mode")
		}
		return Action{
			Describe: "set app-op " + st.AppOp.Op + " to " + st.AppOp.Mode,
			Command: fmt.Sprintf("appops set %s %s %s",
				shellQuote(target), shellQuote(st.AppOp.Op), shellQuote(st.AppOp.Mode)),
		}, nil

	case st.Start != nil:
		comp := sub(st.Start.Component)
		if comp == "" {
			return Action{}, fmt.Errorf("start needs a component")
		}
		cmd := "am start -n " + shellQuote(comp)
		// Extras in a stable order, so two runs of one recipe produce the same
		// command and a plan can be diffed.
		for _, k := range sortedKeys(st.Start.Strings) {
			v := sub(st.Start.Strings[k])
			if v == "" {
				continue
			}
			cmd += fmt.Sprintf(" --es %s %s", shellQuote(k), shellQuote(v))
		}
		for _, k := range sortedKeys(st.Start.Bools) {
			v := sub(st.Start.Bools[k])
			if v == "" {
				continue
			}
			cmd += fmt.Sprintf(" --ez %s %s", shellQuote(k), shellQuote(v))
		}
		for _, k := range sortedKeys(st.Start.Ints) {
			v := sub(st.Start.Ints[k])
			if v == "" {
				continue
			}
			cmd += fmt.Sprintf(" --ei %s %s", shellQuote(k), shellQuote(v))
		}
		return Action{Describe: "configure it by launching " + comp, Command: cmd}, nil

	case st.Settings != nil:
		ns := st.Settings.Namespace
		switch ns {
		case "global", "system", "secure":
		default:
			return Action{}, fmt.Errorf("settings namespace %q is not one of global, system, secure", ns)
		}
		return Action{
			Describe: fmt.Sprintf("set %s setting %s", ns, st.Settings.Key),
			Command: fmt.Sprintf("settings put %s %s %s", ns,
				shellQuote(st.Settings.Key), shellQuote(sub(st.Settings.Value))),
		}, nil

	case st.Disable != nil:
		return Action{
			Describe: "disable " + sub(st.Disable.Package),
			Command:  "pm disable-user --user 0 " + shellQuote(sub(st.Disable.Package)),
		}, nil

	case st.Enable != nil:
		return Action{
			Describe: "enable " + sub(st.Enable.Package),
			Command:  "pm enable --user 0 " + shellQuote(sub(st.Enable.Package)),
		}, nil

	case st.Uninstall != nil:
		target := sub(st.Uninstall.Package)
		if target == "" {
			return Action{}, fmt.Errorf("uninstall needs a package")
		}
		return Action{
			Describe: "remove " + target + " for this user",
			Command:  "pm uninstall --user 0 " + shellQuote(target),
			Note: "a per-user removal: the APK stays in the image, so " +
				"`cmd package install-existing --user 0 " + target + "` puts it back",
		}, nil

	case st.DeviceIdle != nil:
		target := firstNonEmpty(sub(st.DeviceIdle.Package), pkg)
		if target == "" {
			return Action{}, fmt.Errorf("battery_unrestricted needs a package")
		}
		return Action{
			Describe: "exempt " + target + " from battery optimisation",
			Command:  "cmd deviceidle whitelist +" + shellQuote(target),
			Note:     "undone with `cmd deviceidle whitelist -" + target + "`",
		}, nil

	case st.Open != nil:
		if st.Open.Action == "" {
			return Action{}, fmt.Errorf("open needs an intent action")
		}
		cmd := "am start -a " + shellQuote(st.Open.Action)
		if st.Open.ExtraKey != "" {
			cmd += fmt.Sprintf(" --es %s %s", shellQuote(st.Open.ExtraKey), shellQuote(sub(st.Open.ExtraValue)))
		}
		return Action{Describe: "open " + st.Open.Action + " on the device", Command: cmd}, nil

	case st.Manual != nil:
		if st.Manual.Do == "" {
			return Action{}, fmt.Errorf("manual needs something to do")
		}
		return Action{
			Describe: "you: " + sub(st.Manual.Do),
			Command:  "(nothing — this one is done on the device)",
			Manual:   true,
			Note:     sub(st.Manual.Why),
		}, nil

	case st.Verify != nil:
		v := *st.Verify
		v.Contains = sub(v.Contains)
		v.Absent = sub(v.Absent)
		cmd, err := verifyCommand(v.What)
		if err != nil {
			return Action{}, err
		}
		return Action{Describe: "verify " + v.What, Command: cmd, Verify: &v}, nil
	}
	return Action{}, fmt.Errorf("no verb set (have: install, device_owner, grant, appop, start, settings, disable, enable, verify)")
}

// verifyCommand maps a closed set of readback names to commands. Closed because
// a recipe must not be able to name an arbitrary command to run.
func verifyCommand(what string) (string, error) {
	switch what {
	case "owners":
		return "dpm list-owners", nil
	case "packages":
		return "pm list packages", nil
	case "accounts":
		return "dumpsys account | grep -c 'Account {'", nil
	}
	return "", fmt.Errorf("verify what=%q is not one of owners, packages, accounts", what)
}

// resolve fills in the vars, applying defaults and rejecting what is missing.
func (p *Profile) resolve(given map[string]string) (map[string]string, map[string]bool, error) {
	out := map[string]string{}
	secrets := map[string]bool{}
	declared := map[string]bool{}

	for _, v := range p.Vars {
		declared[v.Name] = true
		if v.Secret {
			secrets[v.Name] = true
		}
		val := strings.TrimSpace(given[v.Name])
		if val == "" {
			val = v.Default
		}
		if val == "" && v.Required {
			note := v.Note
			if note != "" {
				note = " (" + note + ")"
			}
			return nil, nil, fmt.Errorf("--var %s= is required by %s%s", v.Name, p.ID, note)
		}
		out[v.Name] = val
	}
	// An undeclared var is a typo, and a typo that silently does nothing is how
	// a device ends up provisioned differently from what was asked.
	var unknown []string
	for name := range given {
		if !declared[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, nil, fmt.Errorf("%s declares no var %s (it has: %s)",
			p.ID, strings.Join(unknown, ", "), strings.Join(p.VarNames(), ", "))
	}
	return out, secrets, nil
}

// VarNames lists the vars a profile declares.
func (p *Profile) VarNames() []string {
	var out []string
	for _, v := range p.Vars {
		out = append(out, v.Name)
	}
	sort.Strings(out)
	return out
}

// Set is the loaded recipe table, already scoped to one device's vendor.
type Set struct {
	profiles []*Profile
	vendor   string
}

// New builds a set from catalog entries for a device of this vendor (a catalog
// vendor id, or "" to keep everything).
//
// Scoping happens here rather than at use: a recipe that leans on Motorola's
// packages should not be offered for a Samsung, and finding that out when a
// step fails is worse than not seeing the recipe.
func New(entries []*Profile, vendor string) *Set {
	byID := map[string]*Profile{}
	for _, p := range entries {
		if p == nil || p.ID == "" {
			continue
		}
		if !vendorMatches(p.Vendor, vendor) {
			continue
		}
		byID[p.ID] = p
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	s := &Set{vendor: vendor}
	for _, id := range ids {
		s.profiles = append(s.profiles, byID[id])
	}
	return s
}

// vendorMatches reports whether a rule scoped to `want` applies on a device of
// vendor `have`. An unscoped rule applies everywhere. An unknown device vendor
// keeps everything: a recon that could not name the OEM should not silently
// narrow what it offers — the plan says what each step does, and the operator
// can read it.
func vendorMatches(want, have string) bool {
	return want == "" || have == "" || strings.EqualFold(want, have)
}

// Vendor is the device vendor this set was scoped to.
func (s *Set) Vendor() string {
	if s == nil {
		return ""
	}
	return s.vendor
}

// Profiles returns every recipe, by id.
func (s *Set) Profiles() []*Profile {
	if s == nil {
		return nil
	}
	return s.profiles
}

// Get returns the recipe with an id.
func (s *Set) Get(id string) (*Profile, bool) {
	for _, p := range s.Profiles() {
		if strings.EqualFold(p.ID, id) {
			return p, true
		}
	}
	return nil, false
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// joinNotes keeps both notes, without repeating one inside the other.
func joinNotes(verb, recipe string) string {
	switch {
	case recipe == "":
		return verb
	case verb == "", strings.Contains(verb, recipe), strings.Contains(recipe, verb):
		return firstNonEmpty(recipe, verb)
	}
	return recipe + " — " + verb
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// shellQuote makes a value safe to interpolate into the remote command. Recipe
// values come from data and from the operator, and both end up in a shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
