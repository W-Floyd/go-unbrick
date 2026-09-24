package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDevice answers shell commands from a table and records what it was asked
// to do, so a plan can be run without a phone.
type fakeDevice struct {
	sdk        int
	answers    map[string]string
	ran        []string
	installed  []string
	installErr error
}

func (f *fakeDevice) Serial() string { return "FAKE123" }
func (f *fakeDevice) SDK() int       { return f.sdk }

func (f *fakeDevice) Shell(cmd string) (string, error) {
	f.ran = append(f.ran, cmd)
	for prefix, answer := range f.answers {
		if strings.HasPrefix(cmd, prefix) {
			return answer, nil
		}
	}
	return "", nil
}

func (f *fakeDevice) InstallAPK(path string, reinstall, grantRuntime bool) error {
	f.installed = append(f.installed, path)
	return f.installErr
}

func newFake() *fakeDevice {
	return &fakeDevice{sdk: 34, answers: map[string]string{
		// No accounts: dumpsys prints the section with nothing in it.
		"dumpsys account": "Accounts: 0",
		"dpm list-owners": "Device owner: com.freekiosk",
	}}
}

// dumpsysAccounts is the shape of the real thing, from the observed device: an
// account line plus the authenticator table that says which package serves each
// type. The second is what turns "remove it in Settings" into an adb command.
const dumpsysAccounts = `Accounts: 1
    Account {name=TracFone, type=com.motorola.contacts.preloaded}
  AuthenticatorDescription {type=com.google}, ComponentInfo{com.google.android.gms/com.google.android.gms.auth.account.authenticator.GoogleAccountAuthenticatorService}, uid 10220
  AuthenticatorDescription {type=com.motorola.contacts.preloaded}, ComponentInfo{com.motorola.contacts.preloadcontacts/com.motorola.contacts.preloadcontacts.authenticator.AuthenticationService}, uid 10231
`

func TestApplyRunsEveryStepInOrder(t *testing.T) {
	d := newFake()
	p := kiosk()
	actions, err := p.Render(map[string]string{"pin": "1234", "url": "https://x.invalid"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	apk := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(apk, []byte("not really an apk"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec, err := Apply(d, p, actions, map[string]string{"": apk}, Hooks{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !rec.Completed {
		t.Error("record does not say the run completed")
	}
	if len(d.installed) != 1 || d.installed[0] != apk {
		t.Errorf("installed %v", d.installed)
	}
	// Order is the recipe's, and the shell saw everything but the install.
	if len(d.ran) != len(actions)-1 {
		t.Errorf("ran %d commands for %d actions: %v", len(d.ran), len(actions), d.ran)
	}
	if !strings.HasPrefix(d.ran[0], "dpm set-device-owner") {
		t.Errorf("first shell command = %q", d.ran[0])
	}
	// The irreversible step is named in the record, so the operator has it
	// written down rather than remembered.
	if len(rec.Irreversible) != 1 {
		t.Errorf("record irreversible = %v", rec.Irreversible)
	}
	// A secret command's text is left out of the record: a record is a file.
	for _, r := range rec.Actions {
		if strings.Contains(r.Command, "1234") {
			t.Errorf("the record kept the PIN: %s", r.Command)
		}
	}
}

// A recipe is a sequence: step four rarely means anything if step three did not
// happen, so a failure stops the run and says where.
func TestApplyStopsAtFirstFailure(t *testing.T) {
	d := newFake()
	d.answers["appops set"] = "Exception occurred while executing 'set':\njava.lang.SecurityException: Permission Denial\n\tat com.android.server"
	p := kiosk()
	actions, _ := p.Render(map[string]string{"pin": "1", "url": "https://x.invalid"})
	apk := filepath.Join(t.TempDir(), "a.apk")
	_ = os.WriteFile(apk, []byte("x"), 0o644)

	rec, err := Apply(d, p, actions, map[string]string{"": apk}, Hooks{})
	if err == nil {
		t.Fatal("a refused command was treated as success")
	}
	if !strings.Contains(err.Error(), "Permission Denial") {
		t.Errorf("error lost the device's reason: %v", err)
	}
	if rec.Completed {
		t.Error("record claims completion after a failure")
	}
	// Nothing after the failing step ran.
	for _, c := range d.ran {
		if strings.HasPrefix(c, "pm grant") {
			t.Error("a later step ran after the failure")
		}
	}
}

// The install step needs a file, and saying so up front beats a cryptic failure.
func TestApplyNeedsAnAPK(t *testing.T) {
	d := newFake()
	p := kiosk()
	actions, _ := p.Render(map[string]string{"pin": "1", "url": "https://x.invalid"})
	_, err := Apply(d, p, actions, nil, Hooks{})
	if err == nil {
		t.Fatal("the install step ran with no APK")
	}
	if !strings.Contains(err.Error(), "--apk") {
		t.Errorf("error does not say how to fix it: %v", err)
	}
}

// A pinned digest is what makes a recipe install the same build twice.
func TestApplyChecksPinnedDigest(t *testing.T) {
	apk := filepath.Join(t.TempDir(), "a.apk")
	content := []byte("the real apk")
	if err := os.WriteFile(apk, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)

	p := kiosk()
	p.APK.SHA256 = hex.EncodeToString(sum[:])
	actions, _ := p.Render(map[string]string{"pin": "1", "url": "https://x.invalid"})
	if _, err := Apply(newFake(), p, actions, map[string]string{"": apk}, Hooks{}); err != nil {
		t.Errorf("a matching digest was rejected: %v", err)
	}

	p.APK.SHA256 = strings.Repeat("ab", 32)
	if _, err := Apply(newFake(), p, actions, map[string]string{"": apk}, Hooks{}); err == nil {
		t.Error("a mismatched digest was installed anyway")
	} else if !strings.Contains(err.Error(), "digest") {
		t.Errorf("error does not mention the digest: %v", err)
	}
}

// Verify is what lets a recipe end by checking rather than assuming.
func TestVerifyFailsWhenTheReadbackDisagrees(t *testing.T) {
	d := newFake()
	d.answers["dpm list-owners"] = "No device owner"
	p := &Profile{ID: "x", Steps: []Step{
		{Verify: &VerifyStep{What: "owners", Contains: "com.freekiosk"}},
	}}
	actions, _ := p.Render(nil)
	if _, err := Apply(d, p, actions, nil, Hooks{}); err == nil {
		t.Fatal("verify passed on a readback that does not contain what it wanted")
	}

	// And the absent form is the inverse.
	p2 := &Profile{ID: "x", Steps: []Step{
		{Verify: &VerifyStep{What: "owners", Absent: "com.freekiosk"}},
	}}
	a2, _ := p2.Render(nil)
	if _, err := Apply(d, p2, a2, nil, Hooks{}); err != nil {
		t.Errorf("absent-check failed though the string is absent: %v", err)
	}
}

// Preconditions of the device-owner step are not preconditions of a run that
// skips it — upstream documents URL kiosk mode as not needing an owner.
func TestPreflightRelevance(t *testing.T) {
	d := newFake()
	d.answers["dumpsys account"] = dumpsysAccounts
	d.answers["dpm list-owners"] = "No device owner"
	p := kiosk()

	withOwner, _ := p.Render(map[string]string{"pin": "1", "url": "https://x.invalid"})
	if !Fatal(Preflight(d, p, withOwner)) {
		t.Error("accounts present with a device-owner step should be fatal")
	}

	// The same plan minus that one action.
	var without []Action
	for _, a := range withOwner {
		if !strings.HasPrefix(a.Command, "dpm set-device-owner") {
			without = append(without, a)
		}
	}
	checks := Preflight(d, p, without)
	if Fatal(checks) {
		t.Error("accounts present without a device-owner step should not be fatal")
	}
	var says string
	for _, c := range checks {
		if strings.Contains(c.What, "accounts") {
			says = c.Says
		}
	}
	if !strings.Contains(says, "not needed") {
		t.Errorf("the check does not explain why it no longer matters: %q", says)
	}
}

// The useful half of the accounts check: which package owns the account, since
// that is what turns "remove it in Settings" into something adb can do. Read
// off the device, so it works for any vendor rather than being a table of
// per-OEM package names.
func TestAccountOwnerDiscovery(t *testing.T) {
	d := newFake()
	d.answers["dumpsys account"] = dumpsysAccounts

	owners := AccountOwners(d)
	if got := owners["TracFone"]; got != "com.motorola.contacts.preloadcontacts" {
		t.Errorf("account owner = %q, want the preload that serves its type", got)
	}

	// And the preflight says it, so the operator does not have to go digging.
	var says string
	for _, c := range Preflight(d, kiosk(), nil) {
		if strings.Contains(c.What, "accounts") {
			says = c.Says
		}
	}
	if !strings.Contains(says, "com.motorola.contacts.preloadcontacts") {
		t.Errorf("the accounts check does not name the owning package: %q", says)
	}
	if !strings.Contains(says, "TracFone") {
		t.Errorf("the accounts check does not name the account: %q", says)
	}
}

// A blocking precondition must carry its remedy: the tool knows which package
// owns the account, so making the operator go and find that out is a gap, not
// caution.
func TestPreflightFailureCarriesItsFix(t *testing.T) {
	d := newFake()
	d.answers["dumpsys account"] = dumpsysAccounts
	d.answers["dpm list-owners"] = "No device owner"
	p := kiosk()
	// The recipe gains the uninstall step the real one has, parameterised by a
	// var — which is how the fix knows what flag to suggest, without the code
	// hardcoding the catalog's name for it.
	p.Vars = append(p.Vars, Var{Name: "account_holder"})
	p.Steps = append(p.Steps, Step{When: "account_holder", Uninstall: &PkgStep{Package: "{{account_holder}}"}})

	actions, _ := p.Render(map[string]string{"pin": "1", "url": "https://x.invalid"})
	var fix string
	for _, c := range Preflight(d, p, actions) {
		if c.Fatal {
			fix = c.Fix
		}
	}
	if fix == "" {
		t.Fatal("the blocking check offers no fix")
	}
	if !strings.Contains(fix, "--var account_holder=com.motorola.contacts.preloadcontacts") {
		t.Errorf("the fix does not name the flag and the package: %q", fix)
	}
	if !strings.Contains(fix, "--skip device_owner") {
		t.Errorf("the fix does not mention the other way out: %q", fix)
	}
}

// A Google account is the case that cannot be fixed over adb, and saying
// "uninstall Play services" would be worse than useless.
func TestGoogleAccountFixPointsAtSettings(t *testing.T) {
	d := newFake()
	d.answers["dumpsys account"] = `Accounts: 1
    Account {name=someone@gmail.com, type=com.google}
  AuthenticatorDescription {type=com.google}, ComponentInfo{com.google.android.gms/…}, uid 10220
`
	d.answers["dpm list-owners"] = "No device owner"
	p := kiosk()
	actions, _ := p.Render(map[string]string{"pin": "1", "url": "https://x.invalid"})

	var fix string
	for _, c := range Preflight(d, p, actions) {
		if c.Fatal {
			fix = c.Fix
		}
	}
	if !strings.Contains(fix, "Settings") {
		t.Errorf("fix = %q, want it to point at Settings", fix)
	}
	if strings.Contains(fix, "pm uninstall") || strings.Contains(fix, "--var") {
		t.Errorf("fix suggests removing Play services: %q", fix)
	}
}

func TestPreflightMinSDK(t *testing.T) {
	d := newFake()
	d.sdk = 23 // Android 6, below the recipe's floor
	checks := Preflight(d, kiosk(), nil)
	if !Fatal(checks) {
		t.Error("an SDK below the recipe's minimum should be fatal")
	}
	// An unknown level is not a failure: the device would not say, and the
	// recipe may still work.
	d.sdk = 0
	if Fatal(Preflight(d, kiosk(), nil)) {
		t.Error("an unknown SDK level was treated as too old")
	}
}

func TestRecordRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	rec := &Record{Profile: "freekiosk", Device: "FAKE123", Completed: true,
		Actions: []Result{{Describe: "install the APK", Command: "pm install -r -g x"}}}
	if err := WriteRecord(&buf, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if !strings.Contains(buf.String(), "freekiosk") || !strings.Contains(buf.String(), "install the APK") {
		t.Errorf("record = %s", buf.String())
	}
}
