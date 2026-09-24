package transport

import (
	"testing"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/facts"
)

// testSourceKey stands in for a transport's own source key, which is how the
// shared providers are registered: the derivations are common, the key and the
// provenance are the route's.
var testSourceKey = facts.Key[*ShellRecon]("source:device.test",
	facts.Fmt(func(*ShellRecon) string { return "(test device)" }))

func resolveShell(t *testing.T, r *ShellRecon, withCatalog bool) *facts.Bag {
	t.Helper()
	bag := facts.NewBag()
	facts.Set(bag, testSourceKey, r, facts.Provenance{Source: "test", Authority: facts.Attested})
	if withCatalog {
		cat, err := catalog.Load(t.TempDir())
		if err != nil {
			t.Fatalf("catalog: %v", err)
		}
		cat.AddVariant("socdivar", "Qualcomm SM6225 Snapdragon 680")
		facts.Set(bag, facts.SourceCatalog, cat, facts.Provenance{Source: "catalog", Authority: facts.Reference})
	}
	ps := ShellProviders("test", testSourceKey.Name(),
		func(b *facts.Bag) (*ShellRecon, bool) { return facts.Get(b, testSourceKey) },
		facts.Derived)
	facts.New(ps, nil).ResolveAll(bag, facts.Options{})
	return bag
}

func TestShellProviders(t *testing.T) {
	bag := resolveShell(t, ParseShell(collected), true)

	if got, ok := facts.Get(bag, facts.Slot); !ok || got != "a" {
		t.Errorf("slot = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.LockState); !ok || got != "unlocked" {
		t.Errorf("lock_state = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.ABEnabled); !ok || !got {
		t.Errorf("ab_enabled = %v (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.Codename); !ok || got != "fogona" {
		t.Errorf("codename = %q (%v), want the device tree's own answer", got, ok)
	}
	// The part number the kernel reports is set in the catalog's spelling, so
	// the same fact derived from a fused JTAG id compares equal to it rather
	// than reading as a disagreement between two correct answers.
	if got, ok := facts.Get(bag, facts.SoC); !ok || got != "Qualcomm SM6225 Snapdragon 680" {
		t.Errorf("soc = %q (%v), want the catalog spelling", got, ok)
	}
	// Everything a running system says is Derived: a bootloader's or a
	// package's version of the same fact must win the display on a conflict.
	for _, name := range []string{facts.Slot.Name(), facts.SoC.Name(), facts.Codename.Name()} {
		best, _ := bag.Best(name)
		if best.Authority != facts.Derived {
			t.Errorf("%s authority = %v, want derived", name, best.Authority)
		}
	}
}

// An uncatalogued SoC still yields its part number, and only once: emitting
// both a resolved and a raw spelling would manufacture a same-fact conflict.
func TestUncataloguedSoC(t *testing.T) {
	bag := facts.NewBag()
	facts.Set(bag, testSourceKey, ParseShell(collected), facts.Provenance{Source: "test", Authority: facts.Attested})
	cat, err := catalog.Load(t.TempDir())
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	facts.Set(bag, facts.SourceCatalog, cat, facts.Provenance{Source: "catalog", Authority: facts.Reference})
	ps := ShellProviders("test", testSourceKey.Name(),
		func(b *facts.Bag) (*ShellRecon, bool) { return facts.Get(b, testSourceKey) },
		facts.Derived)
	res := facts.New(ps, nil).ResolveAll(bag, facts.Options{})

	if got, ok := facts.Get(bag, facts.SoC); !ok || got != "SM6225" {
		t.Errorf("soc = %q (%v), want the raw part number", got, ok)
	}
	if n := len(bag.Values(facts.SoC.Name())); n != 1 {
		t.Errorf("soc has %d values, want 1 (a raw and a resolved spelling would conflict)", n)
	}
	for _, f := range res.Findings {
		t.Errorf("unexpected finding: %s", f.Message)
	}
}

// Nothing resolves off a device that answered nothing, and no provider errors
// on the way to finding that out.
func TestShellProvidersDeclineOnEmpty(t *testing.T) {
	bag := resolveShell(t, ParseShell(""), true)
	for _, name := range []string{facts.Slot.Name(), facts.LockState.Name(),
		facts.ABEnabled.Name(), facts.SoC.Name(), facts.Codename.Name()} {
		if bag.Has(name) {
			best, _ := bag.Best(name)
			t.Errorf("%s resolved to %v off an empty collection", name, best.Data)
		}
	}
}

// Without a catalog the SoC rule cannot run at all — it names the catalog as an
// input — and the rest still resolve.
func TestShellProvidersWithoutCatalog(t *testing.T) {
	bag := resolveShell(t, ParseShell(collected), false)
	if bag.Has(facts.SoC.Name()) {
		t.Error("soc resolved with no catalog in the Bag")
	}
	if got, ok := facts.Get(bag, facts.Slot); !ok || got != "a" {
		t.Errorf("slot = %q (%v), want it resolved regardless", got, ok)
	}
}

func TestSoCName(t *testing.T) {
	cat, err := catalog.Load(t.TempDir())
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	cat.AddVariant("socdivar", "Qualcomm SM6225 Snapdragon 680")

	// A part number named in a variant value resolves to that value…
	if got, _ := SoCName(cat, "SM6225"); got != "Qualcomm SM6225 Snapdragon 680" {
		t.Errorf("SoCName(SM6225) = %q", got)
	}
	// …case-insensitively, since sysfs and the device tree disagree on case.
	if got, _ := SoCName(cat, "sm6225"); got != "Qualcomm SM6225 Snapdragon 680" {
		t.Errorf("SoCName(sm6225) = %q", got)
	}
	// A platform codename is a variant key, which is the table's own lookup.
	if got, _ := SoCName(cat, "socdivar"); got != "Qualcomm SM6225 Snapdragon 680" {
		t.Errorf("SoCName(socdivar) = %q", got)
	}
	// A prefix of a known part is not that part.
	if got, _ := SoCName(cat, "SM622"); got != "" {
		t.Errorf("SoCName(SM622) = %q, want no match", got)
	}
	if got, _ := SoCName(nil, "SM6225"); got != "" {
		t.Errorf("SoCName with no catalog = %q", got)
	}
}
