package distro

import "testing"

func TestBuiltinPostmarketOS(t *testing.T) {
	set := Builtin()
	p := set.Match("postmarketos", nil)
	if p == nil {
		t.Fatal("postmarketOS is not matched by the built-in table")
	}
	if p.Name() != "postmarketOS" {
		t.Errorf("Name() = %q", p.Name())
	}

	env := Env{ID: "postmarketos", VersionID: "24.06", Files: map[string]string{
		"/usr/share/deviceinfo/deviceinfo": `deviceinfo_name="Motorola Moto G Play (2024)"
deviceinfo_manufacturer="Motorola"
deviceinfo_codename="motorola-fogona"
deviceinfo_chassis="handset"`,
	}}
	claim, kv := p.Device(env)
	// The device package is named <vendor>-<codename>; the catalog is keyed by
	// the codename alone and the vendor half is the OEM.
	if claim.Codename != "fogona" || claim.VendorID != "motorola" {
		t.Errorf("claim codename/vendor = %q/%q", claim.Codename, claim.VendorID)
	}
	if claim.Name != "Motorola Moto G Play (2024)" || claim.Chassis != "handset" {
		t.Errorf("claim = %+v", claim)
	}
	if claim.From != "/usr/share/deviceinfo/deviceinfo" {
		t.Errorf("claim.From = %q, want the file it was read from", claim.From)
	}
	// The full key set is kept for the report, with the prefix stripped.
	if kv["manufacturer"] != "Motorola" {
		t.Errorf("key set = %v", kv)
	}
	if len(p.Preconditions(env)) != 0 {
		t.Errorf("preconditions on a complete install: %v", p.Preconditions(env))
	}
}

// An install with no device package: the precondition has to name what is
// missing, why it matters and how to fix it, because "no codename" on its own
// sends the operator looking in the wrong place.
func TestPreconditionWhenNoDeviceFile(t *testing.T) {
	p := Builtin().Match("postmarketos", nil)
	got := p.Preconditions(Env{ID: "postmarketos"})
	if len(got) != 1 {
		t.Fatalf("preconditions = %v, want one", got)
	}
	if got[0].What == "" || got[0].Why == "" || got[0].Fix == "" {
		t.Errorf("precondition is incomplete: %+v", got[0])
	}
	if s := got[0].String(); s == "" {
		t.Error("String() is empty")
	}
}

// A distribution's own releases move things. A version-gated candidate is how
// the table states that without the recon having to know which release it met.
func TestVersionGatedDeviceFiles(t *testing.T) {
	d := &Distro{
		Ident:  "exampleos",
		Format: "shell",
		Files: []FileSpec{
			{Path: "/usr/share/example/device", Since: "3.0"},
			{Path: "/etc/example-device", Until: "3.0"},
		},
		CodenameStyle: "plain",
	}
	files := map[string]string{
		"/usr/share/example/device": "codename=new",
		"/etc/example-device":       "codename=old",
	}

	// Before the move, the old path is the one that applies…
	if claim, _ := d.Device(Env{VersionID: "2.4", Files: files}); claim.Codename != "old" {
		t.Errorf("on 2.4 read %q, want the pre-3.0 path", claim.Codename)
	}
	// …after it, the new one…
	if claim, _ := d.Device(Env{VersionID: "3.1", Files: files}); claim.Codename != "new" {
		t.Errorf("on 3.1 read %q, want the 3.0+ path", claim.Codename)
	}
	// …and a rolling release whose version does not parse is newest, which is
	// what "edge" is.
	if claim, _ := d.Device(Env{VersionID: "edge", Files: files}); claim.Codename != "new" {
		t.Errorf("on edge read %q, want the current path", claim.Codename)
	}
	// The boundary is inclusive-since / exclusive-until, so 3.0 itself is new.
	if claim, _ := d.Device(Env{VersionID: "3.0", Files: files}); claim.Codename != "new" {
		t.Errorf("on 3.0 read %q, want the 3.0+ path", claim.Codename)
	}
}

func TestMatchPrefersExactIDOverDerivative(t *testing.T) {
	set := New([]*Distro{
		{Ident: "debian"},
		{Ident: "mobian", IDLike: []string{"debian"}},
	})
	// Mobian declares itself Debian-like; it is still Mobian.
	if p := set.Match("mobian", []string{"debian"}); p == nil || p.ID() != "mobian" {
		t.Errorf("Match(mobian) = %v", p)
	}
	// A Debian derivative nothing claims by id falls back to the ID_LIKE entry.
	if p := set.Match("someos", []string{"debian"}); p == nil || p.ID() != "mobian" {
		t.Errorf("Match(someos, like debian) = %v, want the entry claiming debian", p)
	}
	// And an unrelated distribution matches nothing, which is not a failure.
	if p := set.Match("nixos", nil); p != nil {
		t.Errorf("Match(nixos) = %v, want nil", p.ID())
	}
}

func TestAliasesAndPlainFormat(t *testing.T) {
	set := New([]*Distro{{
		Ident: "ubuntu-touch", Aliases: []string{"ubports"},
		Files: []FileSpec{{Path: "/etc/device"}}, Format: "plain", CodenameStyle: "plain",
	}})
	p := set.Match("ubports", nil)
	if p == nil {
		t.Fatal("an alias did not match")
	}
	claim, _ := p.Device(Env{Files: map[string]string{"/etc/device": "# a comment\nyggdrasil\n"}})
	if claim.Codename != "yggdrasil" {
		t.Errorf("plain format read %q", claim.Codename)
	}
}

// A catalog entry replaces the built-in of the same id, so the table is
// authoritative where it speaks and the code covers what it omits.
func TestCatalogEntryOverridesBuiltin(t *testing.T) {
	set := New([]*Distro{{
		Ident: "postmarketos", Title: "postmarketOS (local)",
		Files: []FileSpec{{Path: "/etc/my-deviceinfo"}}, Format: "shell",
	}})
	p := set.Match("postmarketos", nil)
	if p == nil || p.Name() != "postmarketOS (local)" {
		t.Fatalf("catalog entry did not override the built-in: %v", p)
	}
	files := p.DeviceFiles()
	if len(files) != 1 || files[0].Path != "/etc/my-deviceinfo" {
		t.Errorf("device files = %v", files)
	}
}

// The union of every profile's candidates is what one collection asks for.
func TestSetDeviceFiles(t *testing.T) {
	set := New([]*Distro{
		{Ident: "a", Files: []FileSpec{{Path: "/etc/a"}, {Path: "/etc/shared"}}},
		{Ident: "b", Files: []FileSpec{{Path: "/etc/shared"}, {Path: "/etc/b"}}},
	})
	got := set.DeviceFiles()
	seen := map[string]int{}
	for _, f := range got {
		seen[f]++
	}
	if seen["/etc/shared"] != 1 {
		t.Errorf("a shared path appears %d times in %v", seen["/etc/shared"], got)
	}
	for _, want := range []string{"/etc/a", "/etc/b", "/usr/share/deviceinfo/deviceinfo"} {
		if seen[want] != 1 {
			t.Errorf("%s missing from %v", want, got)
		}
	}
}

// A Go-backed profile is for what a table cannot state. Registering one must
// put it in the table beside the data-driven entries.
type codeProfile struct{ calls int }

func (c *codeProfile) ID() string   { return "codeos" }
func (c *codeProfile) Name() string { return "CodeOS" }
func (c *codeProfile) Matches(id string, idLike []string) bool {
	return id == "codeos"
}
func (c *codeProfile) DeviceFiles() []FileSpec { return []FileSpec{{Path: "/etc/codeos"}} }
func (c *codeProfile) Device(env Env) (Claim, map[string]string) {
	c.calls++
	// The thing a table cannot do: decide from more than one input.
	if env.VersionID == "1.0" && env.Commands["getprop"] {
		return Claim{Codename: env.DTCodename, VendorID: "computed"}, nil
	}
	return Claim{}, nil
}
func (c *codeProfile) Preconditions(env Env) []Precondition {
	if !env.Commands["getprop"] {
		return []Precondition{{What: "getprop missing", Fix: "install the halium container"}}
	}
	return nil
}

func TestRegisterGoProfile(t *testing.T) {
	p := &codeProfile{}
	Register(p)
	t.Cleanup(func() { delete(custom, p.ID()) })

	set := Builtin()
	got := set.Match("codeos", nil)
	if got == nil || got.ID() != "codeos" {
		t.Fatalf("registered profile not in the table: %v", got)
	}
	env := Env{ID: "codeos", VersionID: "1.0", DTCodename: "fogona",
		Commands: map[string]bool{"getprop": true}}
	if claim, _ := got.Device(env); claim.Codename != "fogona" || claim.VendorID != "computed" {
		t.Errorf("claim = %+v", claim)
	}
	if pre := got.Preconditions(Env{}); len(pre) != 1 {
		t.Errorf("preconditions = %v", pre)
	}
}
