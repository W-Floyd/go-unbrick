package linuxdev

import (
	"testing"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/distro"
	"go-unbrick/internal/facts"
)

// resolve runs this route's providers over one collected recon, with a catalog
// that knows the SoC by its Qualcomm platform codename — the shape the real
// catalog has, where the variant table is keyed by platform and the part number
// is only in the value.
func resolve(t *testing.T, r *Recon) *facts.Bag {
	t.Helper()
	cat, err := catalog.Load(t.TempDir())
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	cat.AddVariant("socdivar", "Qualcomm SM6225 Snapdragon 680")
	bag := facts.NewBag()
	facts.Set(bag, SourceLinux, r, facts.Provenance{Source: "ssh test", Authority: facts.Attested})
	facts.Set(bag, facts.SourceCatalog, cat, facts.Provenance{Source: "catalog", Authority: facts.Reference})
	facts.New(FactProviders(), nil).ResolveAll(bag, facts.Options{})
	return bag
}

func TestProvidersOverBootedLinux(t *testing.T) {
	bag := resolve(t, Parse(collected, distro.Builtin()))

	if got, ok := facts.Get(bag, DeviceOS); !ok || got != "postmarketOS edge (build 20240612-0132)" {
		t.Errorf("device_os = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, KernelRelease); !ok || got != "6.6.32-postmarketos-qcom-sm6225" {
		t.Errorf("kernel_release = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.Codename); !ok || got != "fogona" {
		t.Errorf("codename = %q (%v)", got, ok)
	}
	// The shared shell providers are registered over this route's key too, so a
	// fact that any booted device answers resolves here without this package
	// declaring it.
	if got, ok := facts.Get(bag, facts.Slot); !ok || got != "a" {
		t.Errorf("slot = %q (%v)", got, ok)
	}
	if got, ok := facts.Get(bag, facts.SoC); !ok || got != "Qualcomm SM6225 Snapdragon 680" {
		t.Errorf("soc = %q (%v)", got, ok)
	}
}

// The distribution's device definition and the device tree both name the
// device. When they agree that is corroboration on one value, which is the
// whole point of running both rather than picking one.
func TestCodenameCorroborated(t *testing.T) {
	bag := resolve(t, Parse(collected, distro.Builtin()))
	agreeing := bag.Agreeing(facts.Codename.Name())
	if len(agreeing) != 2 {
		t.Errorf("codename agreeing sources = %v, want the deviceinfo and the device tree", agreeing)
	}
}

// The installed system's own identity is the one thing a running install is the
// authority on — nothing else can say what is installed.
func TestInstalledOSIsAttested(t *testing.T) {
	bag := resolve(t, Parse(collected, distro.Builtin()))
	best, ok := bag.Best(DeviceOS.Name())
	if !ok || best.Authority != facts.Attested {
		t.Errorf("device_os authority = %v (%v), want attested", best.Authority, ok)
	}
	// Everything about the *hardware*, though, passed through a mutable
	// userspace, so a bootloader or a package outranks it.
	best, _ = bag.Best(facts.Codename.Name())
	if best.Authority != facts.Derived {
		t.Errorf("codename authority = %v, want derived", best.Authority)
	}
}

func TestProvidersDeclineOnEmpty(t *testing.T) {
	bag := resolve(t, Parse("", distro.Builtin()))
	for _, name := range []string{facts.Codename.Name(), facts.Slot.Name(), facts.SoC.Name(),
		facts.LockState.Name(), facts.ABEnabled.Name(), DeviceOS.Name(), KernelRelease.Name()} {
		if bag.Has(name) {
			best, _ := bag.Best(name)
			t.Errorf("%s resolved to %v off an empty collection", name, best.Data)
		}
	}
}
