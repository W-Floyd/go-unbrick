package provision

import (
	"strings"
	"testing"
)

// kiosk is a recipe of the shape catalog/provision.yaml holds: an install, an
// irreversible privilege grant, two permission steps, two mutually exclusive
// configuration launches gated on a var, and a readback.
func kiosk() *Profile {
	return &Profile{
		ID: "freekiosk", Name: "FreeKiosk", Package: "com.freekiosk",
		APK:   APKSpec{Source: "https://example.invalid/releases"},
		Needs: Needs{MinSDK: 26, NoAccounts: true, NoDeviceOwner: true},
		Vars: []Var{
			{Name: "pin", Required: true, Secret: true, Note: "kiosk PIN"},
			{Name: "url"},
			{Name: "lock_package"},
			{Name: "auto_start", Default: "true"},
			{Name: "owner_component", Default: "com.freekiosk/.DeviceAdminReceiver"},
		},
		Steps: []Step{
			{Install: &InstallStep{Reinstall: true, Grants: true}},
			{DeviceOwner: &OwnerStep{Component: "{{owner_component}}"}},
			{AppOp: &AppOpStep{Op: "android:get_usage_stats", Mode: "allow"}},
			{Grant: &GrantStep{Permission: "android.permission.WRITE_SECURE_SETTINGS"}},
			{When: "lock_package", Start: &StartStep{
				Component: "com.freekiosk/.MainActivity",
				Strings:   map[string]string{"lock_package": "{{lock_package}}", "pin": "{{pin}}"},
				Bools:     map[string]string{"auto_start": "{{auto_start}}"},
			}},
			{When: "url", Start: &StartStep{
				Component: "com.freekiosk/.MainActivity",
				Strings:   map[string]string{"url": "{{url}}", "pin": "{{pin}}"},
			}},
			{Verify: &VerifyStep{What: "owners", Contains: "com.freekiosk"}},
		},
	}
}

func TestRenderCommands(t *testing.T) {
	actions, err := kiosk().Render(map[string]string{"pin": "1234", "url": "https://dash.local"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// The url variant runs; the lock_package one is gated out by `when`.
	var cmds []string
	for _, a := range actions {
		cmds = append(cmds, a.Command)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"dpm set-device-owner 'com.freekiosk/.DeviceAdminReceiver'",
		"appops set 'com.freekiosk' 'android:get_usage_stats' 'allow'",
		"pm grant 'com.freekiosk' 'android.permission.WRITE_SECURE_SETTINGS'",
		"am start -n 'com.freekiosk/.MainActivity' --es 'pin' '1234' --es 'url' 'https://dash.local'",
		"dpm list-owners",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan is missing:\n  %s\ngot:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "lock_package") {
		t.Error("the lock_package variant rendered even though that var was not given")
	}
	// Extras are emitted in a stable order, so one recipe produces one command
	// and two runs can be diffed.
	again, _ := kiosk().Render(map[string]string{"pin": "1234", "url": "https://dash.local"})
	if again[len(again)-2].Command != actions[len(actions)-2].Command {
		t.Error("two renders of one recipe produced different commands")
	}
}

// A secret value must not reach the terminal, and the note must not claim
// masking that did not happen.
func TestSecretsAreMasked(t *testing.T) {
	actions, err := kiosk().Render(map[string]string{"pin": "9876", "url": "https://x.invalid"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var found bool
	for _, a := range actions {
		if !strings.Contains(a.Command, "9876") {
			continue
		}
		found = true
		if !a.Secret {
			t.Error("a command carrying the PIN was not marked secret")
		}
		if strings.Contains(a.Print(), "9876") {
			t.Errorf("Print() leaks the PIN: %s", a.Print())
		}
		if !strings.Contains(a.Print(), "••••") {
			t.Errorf("Print() does not show the masking: %s", a.Print())
		}
		// The command that actually runs still carries the real value.
		if !strings.Contains(a.Command, "9876") {
			t.Error("the executable command lost the PIN")
		}
	}
	if !found {
		t.Fatal("no command carried the PIN at all")
	}
}

func TestRequiredAndUnknownVars(t *testing.T) {
	if _, err := kiosk().Render(map[string]string{"url": "https://x.invalid"}); err == nil {
		t.Error("a missing required var was accepted")
	} else if !strings.Contains(err.Error(), "pin") {
		t.Errorf("error does not name the missing var: %v", err)
	}
	// A typo that silently did nothing would provision the device differently
	// from what was asked.
	_, err := kiosk().Render(map[string]string{"pin": "1", "ur1": "https://x.invalid"})
	if err == nil {
		t.Fatal("an undeclared var was accepted")
	}
	if !strings.Contains(err.Error(), "ur1") {
		t.Errorf("error does not name the unknown var: %v", err)
	}
}

// A recipe where every step is gated on vars that were not given is an error,
// not an empty success.
func TestNothingToDo(t *testing.T) {
	p := &Profile{ID: "x", Steps: []Step{
		{When: "url", Start: &StartStep{Component: "a/.B"}},
	}, Vars: []Var{{Name: "url"}}}
	if _, err := p.Render(nil); err == nil {
		t.Error("a recipe with no applicable steps rendered as a plan")
	}
}

// The verb set is closed, and a recipe naming something outside it fails at
// render time rather than sending anything to a device.
func TestClosedVerbSet(t *testing.T) {
	bad := &Profile{ID: "x", Steps: []Step{{Note: "no verb at all"}}}
	if _, err := bad.Render(nil); err == nil {
		t.Error("a step with no verb was accepted")
	}
	badVerify := &Profile{ID: "x", Steps: []Step{{Verify: &VerifyStep{What: "anything"}}}}
	if _, err := badVerify.Render(nil); err == nil {
		t.Error("verify accepted an arbitrary readback")
	}
	badSettings := &Profile{ID: "x", Steps: []Step{
		{Settings: &SettingsStep{Namespace: "wherever", Key: "k", Value: "v"}},
	}}
	if _, err := badSettings.Render(nil); err == nil {
		t.Error("settings accepted an unknown namespace")
	}
}

// Values from data and from the operator both end up in a shell on the device.
func TestValuesAreQuoted(t *testing.T) {
	p := &Profile{ID: "x", Package: "com.x",
		Vars: []Var{{Name: "u"}},
		Steps: []Step{{When: "u", Start: &StartStep{
			Component: "com.x/.A", Strings: map[string]string{"url": "{{u}}"},
		}}},
	}
	actions, err := p.Render(map[string]string{"u": "https://x/; rm -rf /"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(actions[0].Command, `'https://x/; rm -rf /'`) {
		t.Errorf("a value was interpolated unquoted: %s", actions[0].Command)
	}
}

// The irreversible step must be marked, because the confirmation the command
// layer asks for depends on it.
func TestIrreversibleIsMarked(t *testing.T) {
	actions, _ := kiosk().Render(map[string]string{"pin": "1", "url": "https://x.invalid"})
	var owner *Action
	for i := range actions {
		if strings.HasPrefix(actions[i].Command, "dpm set-device-owner") {
			owner = &actions[i]
		}
	}
	if owner == nil {
		t.Fatal("no device-owner action rendered")
	}
	if !owner.Irreversible {
		t.Error("set-device-owner is not marked irreversible")
	}
	if !strings.Contains(owner.Note, "factory reset") {
		t.Errorf("the note does not say what undoing it takes: %q", owner.Note)
	}
	// Its inverse is not irreversible.
	undo := &Profile{ID: "u", Steps: []Step{
		{DeviceOwner: &OwnerStep{Component: "com.x/.A", Remove: true}},
	}}
	ua, err := undo.Render(nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if ua[0].Irreversible || !strings.HasPrefix(ua[0].Command, "dpm remove-active-admin") {
		t.Errorf("remove rendered as %+v", ua[0])
	}
}

// A recipe that leans on one OEM's packages is not offered on another's
// device: finding that out when a step fails is worse than not seeing it.
func TestVendorScopedRecipes(t *testing.T) {
	entries := []*Profile{
		{ID: "generic", Steps: []Step{{Verify: &VerifyStep{What: "owners"}}}},
		{ID: "moto-only", Vendor: "motorola", Steps: []Step{{Verify: &VerifyStep{What: "owners"}}}},
	}
	moto := New(entries, "motorola")
	if _, ok := moto.Get("moto-only"); !ok {
		t.Error("a motorola recipe is not offered on a motorola device")
	}
	if _, ok := moto.Get("generic"); !ok {
		t.Error("an unscoped recipe is not offered on a motorola device")
	}

	sam := New(entries, "samsung")
	if _, ok := sam.Get("moto-only"); ok {
		t.Error("a motorola recipe is offered on a samsung device")
	}
	if _, ok := sam.Get("generic"); !ok {
		t.Error("an unscoped recipe is not offered on a samsung device")
	}

	// An unknown vendor keeps everything, and listing with no device shows all.
	if len(New(entries, "").Profiles()) != 2 {
		t.Error("an unknown vendor narrowed the list")
	}
	if New(entries, "motorola").Vendor() != "motorola" {
		t.Error("the set does not report its scope")
	}
}

// A recipe installing several apps names each, and the operator supplies each
// by name.
func TestNamedAPKs(t *testing.T) {
	p := &Profile{ID: "combo",
		APKs: map[string]APKSpec{
			"ha":        {Source: "https://example.invalid/ha"},
			"freekiosk": {Source: "https://example.invalid/fk"},
		},
		Steps: []Step{
			{Install: &InstallStep{APK: "ha", Reinstall: true}},
			{Install: &InstallStep{APK: "freekiosk", Reinstall: true}},
		},
	}
	actions, err := p.Render(nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if actions[0].APKName != "ha" || actions[1].APKName != "freekiosk" {
		t.Errorf("APK names = %q, %q", actions[0].APKName, actions[1].APKName)
	}
	// The plan says which file each step wants, since that is what the operator
	// has to pass.
	if !strings.Contains(actions[0].Command, "--apk ha=") {
		t.Errorf("the plan does not name the file to pass: %s", actions[0].Command)
	}
	if spec, ok := p.APKFor("ha"); !ok || spec.Source == "" {
		t.Errorf("APKFor(ha) = %+v, %v", spec, ok)
	}
	if _, ok := p.APKFor("nope"); ok {
		t.Error("APKFor invented an APK")
	}
}

// A step nobody can automate is a first-class step, not an omission.
func TestManualStep(t *testing.T) {
	p := &Profile{ID: "x", Steps: []Step{
		{Manual: &ManualStep{Do: "sign into Home Assistant", Why: "otherwise the kiosk locks onto a login screen"}},
	}}
	actions, err := p.Render(nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !actions[0].Manual {
		t.Error("the manual step is not marked manual")
	}
	if !strings.Contains(actions[0].Describe, "sign into Home Assistant") {
		t.Errorf("describe = %q", actions[0].Describe)
	}
	if !strings.Contains(actions[0].Note, "login screen") {
		t.Errorf("note lost the why: %q", actions[0].Note)
	}
}

func TestUninstallAndBatteryVerbs(t *testing.T) {
	p := &Profile{ID: "x", Package: "com.app", Steps: []Step{
		{Uninstall: &PkgStep{Package: "com.motorola.contacts.preloadcontacts"}},
		{DeviceIdle: &PkgStep{}},
		{Open: &OpenStep{Action: "android.settings.SYNC_SETTINGS"}},
	}}
	actions, err := p.Render(nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := []string{
		"pm uninstall --user 0 'com.motorola.contacts.preloadcontacts'",
		"cmd deviceidle whitelist +'com.app'",
		"am start -a 'android.settings.SYNC_SETTINGS'",
	}
	for i, w := range want {
		if actions[i].Command != w {
			t.Errorf("action %d = %q, want %q", i, actions[i].Command, w)
		}
	}
	// The removal says how to put it back, since that is what makes it safe to
	// offer at all.
	if !strings.Contains(actions[0].Note, "install-existing") {
		t.Errorf("uninstall note does not say how to undo it: %q", actions[0].Note)
	}
}

func TestSetLookup(t *testing.T) {
	set := New([]*Profile{kiosk(), {ID: "other"}}, "")
	if _, ok := set.Get("FREEKIOSK"); !ok {
		t.Error("Get is case-sensitive")
	}
	if _, ok := set.Get("nope"); ok {
		t.Error("Get invented a recipe")
	}
	if len(set.Profiles()) != 2 {
		t.Errorf("Profiles() = %d", len(set.Profiles()))
	}
	if got := kiosk().VarNames(); len(got) != 5 {
		t.Errorf("VarNames() = %v", got)
	}
}
