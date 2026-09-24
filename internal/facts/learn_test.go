package facts

import "testing"

func TestLearnableExcludesIdentifying(t *testing.T) {
	b := NewBag()
	Set(b, Codename, "fogona", Provenance{Source: "test", Authority: Attested})
	Set(b, SoC, "SM6225", Provenance{Source: "test", Authority: Attested})
	Set(b, UnlockChallenge, "deadbeef", Provenance{Source: "test", Authority: Attested})
	Set(b, Slot, "a", Provenance{Source: "test", Authority: Attested})
	Set(b, LockState, "unlocked", Provenance{Source: "test", Authority: Attested})
	// device_os/kernel_release live in another package; register keys of the
	// same name here to exercise the installed-OS exclusion.
	Set(b, Key[string]("device_os"), "postmarketOS edge", Provenance{Source: "test", Authority: Attested})
	Set(b, Key[string]("kernel_release"), "7.3.0-rc4", Provenance{Source: "test", Authority: Attested})

	got := Learnable(b)
	if got["codename"] != "fogona" || got["soc"] != "SM6225" {
		t.Fatalf("model facts missing: %v", got)
	}
	for _, id := range []string{"unlock_challenge", "slot", "lock_state", "device_os", "kernel_release"} {
		if _, ok := got[id]; ok {
			t.Errorf("non-model fact %q must not be learnable", id)
		}
	}
}
