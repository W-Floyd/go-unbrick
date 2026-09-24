package provision

// Running a plan: the preconditions first, then the actions, then what actually
// happened.
//
// The preconditions matter more here than anywhere else in this tool, because
// the one irreversible step (`dpm set-device-owner`) fails *late* and cryptically
// when they are unmet — an account on the device is enough — and a half-applied
// recipe on a kiosk device is worse than one that never started.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Device is what a plan needs from the transport: a shell, an installer, and
// enough about the device to check the preconditions. The adb route implements
// it; anything else that can do these things could too.
type Device interface {
	Serial() string
	// Shell runs one command and returns its combined output.
	Shell(cmd string) (string, error)
	// InstallAPK pushes a local APK and installs it.
	InstallAPK(path string, reinstall, grantRuntime bool) error
	// SDK is the device's API level, 0 when unknown.
	SDK() int
}

// Check is one precondition and what the device said about it.
type Check struct {
	What string
	OK   bool
	Says string
	// Fix is what to do about it, in the operator's terms — the exact flag to
	// re-run with where there is one. A precondition that blocks a run without
	// saying how to get past it makes the operator go and find out what the
	// tool already knows.
	Fix string
	// Fatal marks a failed check that must stop the run rather than warn.
	Fatal bool
}

// Preflight tests a profile's declared preconditions against the device.
//
// actions is the plan as it will actually run, because relevance depends on it:
// "no accounts configured" and "no device owner set" are preconditions of
// `dpm set-device-owner` and of nothing else, so on a run where that step was
// skipped — upstream documents URL kiosk mode as not needing it — they are not
// failures to stop for.
func Preflight(d Device, p *Profile, actions []Action) []Check {
	setsOwner := false
	for _, a := range actions {
		if strings.HasPrefix(a.Command, "dpm set-device-owner") {
			setsOwner = true
			break
		}
	}

	var out []Check
	if p.Needs.MinSDK > 0 {
		sdk := d.SDK()
		out = append(out, Check{
			What:  fmt.Sprintf("Android API level ≥ %d", p.Needs.MinSDK),
			OK:    sdk == 0 || sdk >= p.Needs.MinSDK,
			Says:  fmt.Sprintf("device reports %s", orUnknown(sdk)),
			Fatal: sdk != 0 && sdk < p.Needs.MinSDK,
		})
	}
	if p.Needs.NoAccounts {
		n, says := accountCount(d)
		fatal := n != 0 && setsOwner
		fix := ""
		switch {
		case !setsOwner:
			says += " — not needed, since this run does not set a device owner"
		case fatal && planClearsAccounts(d, actions):
			// The recipe fixes its own precondition: it removes the package
			// that serves the account's type, before the owner step. Calling
			// that fatal would refuse to run the very plan that resolves it.
			says += " — this run removes the package that owns it first"
			fatal = false
		case fatal:
			fix = accountFix(d, p)
		}
		out = append(out, Check{
			What: "no accounts configured",
			OK:   n == 0,
			Says: says,
			Fix:  fix,
			// Fatal only where it matters: `dpm set-device-owner` refuses
			// outright with an account present, and the refusal comes after the
			// APK is already installed.
			Fatal: fatal,
		})
	}
	if p.Needs.NoDeviceOwner {
		owners, _ := d.Shell("dpm list-owners")
		has := strings.Contains(owners, "Device owner")
		out = append(out, Check{
			What:  "no device owner set yet",
			OK:    !has,
			Says:  firstLine(owners),
			Fatal: has && setsOwner,
		})
	}
	if p.APK.SHA256 != "" {
		out = append(out, Check{
			What: "APK digest pinned by the recipe",
			OK:   true,
			Says: "will be checked against the file passed with --apk",
		})
	}
	return out
}

// accountCount asks what accounts are configured, and — the useful part — which
// package owns each one.
//
// The device-owner precondition is "no accounts", and the obvious advice is
// "remove them in Settings". But an account's type is served by an
// authenticator that belongs to a package, and dumpsys says which: on the
// observed TracFone unit the single account was `type=com.motorola.contacts.
// preloaded`, owned by com.motorola.contacts.preloadcontacts — a *preload*. So
// the account was removable over adb by removing that package, with no Settings
// visit and no factory reset. Naming the owner is what turns a manual step into
// an automatable one, and it is read off the device rather than hardcoded per
// vendor.
func accountCount(d Device) (int, string) {
	out, err := d.Shell("dumpsys account")
	if err != nil {
		return -1, "could not read the account list: " + err.Error()
	}
	accounts := parseAccountTypes(out)
	if len(accounts) == 0 {
		return 0, "no accounts"
	}
	owners := parseAuthenticators(out)
	var parts []string
	for _, a := range accounts {
		if owner := owners[a.Type]; owner != "" {
			parts = append(parts, fmt.Sprintf("%s (%s, owned by %s)", a.Name, a.Type, owner))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", a.Name, a.Type))
	}
	return len(accounts), fmt.Sprintf("%d configured: %s", len(accounts), strings.Join(parts, "; "))
}

// accountFix says how to get past a configured account, using what the device
// already told us: which package serves each account's type.
//
// The flag it suggests is found from the recipe rather than hardcoded — a
// recipe with an uninstall step parameterised by a var is a recipe that can
// clear an account, and the var's name is what the operator has to pass. So the
// catalog names the knob and the code reads it off, instead of the code knowing
// what the catalog called it.
func accountFix(d Device, p *Profile) string {
	owners := AccountOwners(d)
	if len(owners) == 0 {
		return "remove the accounts in Settings → Accounts on the device"
	}

	var removable, stuck []string
	for name, owner := range owners {
		if unremovablePackage(owner) {
			stuck = append(stuck, fmt.Sprintf("%s (%s)", name, owner))
			continue
		}
		removable = append(removable, owner)
	}
	sort.Strings(removable)
	sort.Strings(stuck)

	var out []string
	if len(stuck) > 0 {
		out = append(out, fmt.Sprintf("%s belongs to a package that cannot be removed, so remove that account in Settings → Accounts",
			strings.Join(stuck, ", ")))
	}
	if len(removable) == 1 {
		if v := uninstallVar(p); v != "" {
			out = append(out, fmt.Sprintf("re-run with --var %s=%s to remove the package that owns it (a per-user uninstall, undone with `cmd package install-existing`)",
				v, removable[0]))
		} else {
			out = append(out, fmt.Sprintf("remove the package that owns it: adb shell pm uninstall --user 0 %s", removable[0]))
		}
	} else if len(removable) > 1 {
		out = append(out, fmt.Sprintf("the accounts are owned by %s — remove them in Settings → Accounts, or uninstall those packages",
			strings.Join(removable, ", ")))
	}
	out = append(out, "or --skip device_owner, which upstream documents as fine for URL kiosk mode")
	return strings.Join(out, "; ")
}

// unremovablePackage reports whether an account's owner is part of the platform
// rather than a preload — a Google account belongs to Play services, which no
// amount of adb will uninstall.
func unremovablePackage(pkg string) bool {
	switch pkg {
	case "com.google.android.gms", "com.google.android.gsf", "com.android.vending", "android":
		return true
	}
	return false
}

// uninstallVar finds the var a recipe's uninstall step is parameterised by.
func uninstallVar(p *Profile) string {
	for _, st := range p.Steps {
		if st.Uninstall == nil {
			continue
		}
		if m := varPattern.FindStringSubmatch(st.Uninstall.Package); m != nil {
			return m[1]
		}
	}
	return ""
}

// planClearsAccounts reports whether the plan removes the package behind every
// configured account before it needs them gone. An account exists because some
// package serves its type; remove that package and the account goes with it,
// which is how a device-owner precondition is met over adb rather than in
// Settings.
//
// Every account must be covered: one left behind is enough for
// `dpm set-device-owner` to refuse.
func planClearsAccounts(d Device, actions []Action) bool {
	owners := AccountOwners(d)
	if len(owners) == 0 {
		return false
	}
	removed := map[string]bool{}
	for _, a := range actions {
		if rest, ok := strings.CutPrefix(a.Command, "pm uninstall --user 0 "); ok {
			removed[strings.Trim(strings.TrimSpace(rest), "'")] = true
		}
	}
	for _, owner := range owners {
		if !removed[owner] {
			return false
		}
	}
	return true
}

// AccountOwners returns the package that owns each configured account's type —
// what an operator needs to know to clear an account without touching the
// device's screen. A Google account's owner is Play services, which is not
// removable; a preload's owner usually is.
func AccountOwners(d Device) map[string]string {
	out, err := d.Shell("dumpsys account")
	if err != nil {
		return nil
	}
	owners := parseAuthenticators(out)
	got := map[string]string{}
	for _, a := range parseAccountTypes(out) {
		if owner := owners[a.Type]; owner != "" {
			got[a.Name] = owner
		}
	}
	return got
}

type account struct{ Name, Type string }

var (
	// "Account {name=TracFone, type=com.motorola.contacts.preloaded}"
	accountLine = regexp.MustCompile(`Account \{name=([^,]*), type=([^}]*)\}`)
	// "AuthenticatorDescription {type=X}, ComponentInfo{pkg/cls}"
	authLine = regexp.MustCompile(`AuthenticatorDescription \{type=([^}]*)\}, ComponentInfo\{([^/}]*)/`)
)

func parseAccountTypes(out string) []account {
	var got []account
	seen := map[string]bool{}
	for _, m := range accountLine.FindAllStringSubmatch(out, -1) {
		key := m[1] + "\x00" + m[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		got = append(got, account{Name: strings.TrimSpace(m[1]), Type: strings.TrimSpace(m[2])})
	}
	return got
}

func parseAuthenticators(out string) map[string]string {
	got := map[string]string{}
	for _, m := range authLine.FindAllStringSubmatch(out, -1) {
		got[strings.TrimSpace(m[1])] = strings.TrimSpace(m[2])
	}
	return got
}

// Fatal reports whether any check must stop the run.
func Fatal(checks []Check) bool {
	for _, c := range checks {
		if c.Fatal {
			return true
		}
	}
	return false
}

// Result is what one action did.
type Result struct {
	Describe string `json:"describe"`
	// Command is omitted for an action whose text carries a secret: a record is
	// a file, and a PIN in a file is a PIN in a backup.
	Command string `json:"command,omitempty"`
	Output  string `json:"output,omitempty"`
	Err     string `json:"error,omitempty"`
}

// Record is the audit trail of an applied plan.
type Record struct {
	Profile   string    `json:"profile"`
	Device    string    `json:"device"`
	Applied   time.Time `json:"applied"`
	Actions   []Result  `json:"actions"`
	Completed bool      `json:"completed"`
	// Irreversible names what was done that cannot be undone on the device, so
	// the record says it rather than the operator having to remember.
	Irreversible []string `json:"irreversible,omitempty"`
	// Manual names the steps a person had to do, which is what someone reading
	// this later needs in order to know whether the flow really finished.
	Manual []string `json:"manual,omitempty"`
	// Installed is which build of each app went on the device, by digest. It is
	// what makes a run reproducible after the fact: paste a digest into the
	// recipe's `sha256` and every later run installs that exact file.
	Installed []InstalledAPK `json:"installed,omitempty"`
}

// InstalledAPK is one installed file, identified by content rather than by
// version string — a release can be re-cut under the same tag, a digest cannot.
type InstalledAPK struct {
	APK    string `json:"apk,omitempty"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Hooks let the caller own the terminal: Progress announces each action, and
// Pause is how a manual step waits for the person at the device. A nil Pause
// means manual steps are noted and not waited on, which is what an unattended
// run has to do.
type Hooks struct {
	Progress func(i, n int, a Action)
	Pause    func(a Action) bool
	// Fetch supplies a local file for an install step that was not given one,
	// returning the path and the file's digest. Nil means no fetching: the step
	// then asks for --apk rather than reaching the network by itself.
	Fetch func(apkName string) (path, digest string, err error)
}

// Apply runs the actions in order, stopping at the first failure: a recipe is a
// sequence, and step four rarely means anything if step three did not happen.
//
// apks maps a recipe's APK names to local files ("" for a single unnamed one).
// An install step with no local file is fetched through hooks.Fetch, which is
// how the recipe's own source is used; without a fetcher, the step asks for
// --apk instead of reaching the network on its own initiative.
func Apply(d Device, p *Profile, actions []Action, apks map[string]string, hooks Hooks) (*Record, error) {
	rec := &Record{Profile: p.ID, Device: d.Serial(), Applied: time.Now().UTC()}

	for i, a := range actions {
		if hooks.Progress != nil {
			hooks.Progress(i, len(actions), a)
		}
		res := Result{Describe: a.Describe}
		if !a.Secret {
			res.Command = a.Command
		}

		var err error
		switch {
		case a.Manual:
			// Only a person can do this one. A run that is being watched waits;
			// an unattended one records that it was not done, because claiming
			// otherwise would make the record a lie.
			if hooks.Pause == nil {
				res.Output = "not done: nobody was there to do it"
				rec.Manual = append(rec.Manual, a.Describe)
				break
			}
			if !hooks.Pause(a) {
				err = fmt.Errorf("stopped at a manual step")
				break
			}
			rec.Manual = append(rec.Manual, a.Describe)

		case a.Install:
			spec, _ := p.APKFor(a.APKName)
			path, digest := apks[a.APKName], ""
			switch {
			case path != "":
				// A file the operator passed: verify a pin against it, and
				// report its digest like any other install.
				if spec.SHA256 != "" {
					if derr := checkDigest(path, spec.SHA256); derr != nil {
						err = derr
						break
					}
				}
				digest, _ = fileDigest(path)
			case hooks.Fetch != nil:
				path, digest, err = hooks.Fetch(a.APKName)
			default:
				err = fmt.Errorf("this step installs %s: pass it with --apk %s=<file> (it comes from %s)",
					orThisApp(a.APKName), orThisApp(a.APKName), orNone(spec.Source))
			}
			if err != nil {
				break
			}
			// What was installed, by digest, whether or not the recipe pinned
			// it: a record that cannot say which build went on the device is
			// not much of a record.
			if digest != "" {
				rec.Installed = append(rec.Installed, InstalledAPK{
					APK: a.APKName, File: filepath.Base(path), SHA256: digest,
				})
				res.Output = "sha256 " + digest
			}
			err = d.InstallAPK(path, true, true)
		case a.Verify != nil:
			var out string
			out, err = d.Shell(a.Command)
			res.Output = strings.TrimSpace(out)
			if err == nil {
				err = checkVerify(*a.Verify, out)
			}
		default:
			var out string
			out, err = d.Shell(a.Command)
			res.Output = strings.TrimSpace(out)
			if err == nil {
				err = commandRefused(out)
			}
		}

		if err != nil {
			res.Err = err.Error()
			rec.Actions = append(rec.Actions, res)
			return rec, fmt.Errorf("%s: %w", a.Describe, err)
		}
		if a.Irreversible {
			rec.Irreversible = append(rec.Irreversible, a.Describe)
		}
		rec.Actions = append(rec.Actions, res)
	}
	rec.Completed = true
	return rec, nil
}

// commandRefused reads a shell answer that looks like a refusal. The shell
// exits 0 for most of these, so the text is the only signal.
//
// The *cause* is what the operator needs, and it is rarely the first line:
// `pm`/`dpm` answer "Exception occurred while executing 'set':" and put
// "java.lang.SecurityException: Permission Denial …" underneath, with a stack
// trace after that. So the lines are ranked rather than taken in order.
func commandRefused(out string) error {
	var preamble string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "at ") { // a stack frame
			continue
		}
		// The cause: an exception class with its message.
		if i := strings.Index(t, "Exception: "); i >= 0 {
			return fmt.Errorf("%s", strings.TrimSpace(t[i+len("Exception: "):]))
		}
		switch {
		case strings.HasPrefix(t, "Failure"), strings.HasPrefix(t, "Error"),
			strings.Contains(t, "Permission denial"),
			strings.Contains(t, "Unknown command"),
			strings.Contains(t, "not found"):
			return fmt.Errorf("%s", t)
		case strings.Contains(t, "Exception") && preamble == "":
			// "Exception occurred while executing …": keep it in case the cause
			// line never arrives, but keep looking for the cause first.
			preamble = t
		}
	}
	if preamble != "" {
		return fmt.Errorf("%s", preamble)
	}
	return nil
}

// checkVerify applies a readback expectation.
func checkVerify(v VerifyStep, out string) error {
	if v.Contains != "" && !strings.Contains(out, v.Contains) {
		return fmt.Errorf("expected %q in the output, got: %s", v.Contains, firstLine(out))
	}
	if v.Absent != "" && strings.Contains(out, v.Absent) {
		return fmt.Errorf("did not expect %q in the output", v.Absent)
	}
	return nil
}

// checkDigest verifies a pinned APK before it is installed. A recipe that pins
// a digest is a recipe that can be trusted to install the same thing twice.
func checkDigest(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("APK digest does not match the recipe: have %s, recipe pins %s", got, want)
	}
	return nil
}

// WriteRecord saves a record as JSON.
func WriteRecord(w io.Writer, r *Record) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}

func orUnknown(n int) string {
	if n == 0 {
		return "an unknown level"
	}
	return strconv.Itoa(n)
}

func orNone(s string) string {
	if s == "" {
		return "the project's releases page"
	}
	return s
}

func orThisApp(name string) string {
	if name == "" {
		return "an APK"
	}
	return name
}
