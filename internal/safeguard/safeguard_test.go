package safeguard

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name        string
		category    string
		criticality string
		protected   bool
	}{
		{"modemst1", CategoryRadio, CriticalityIrreplaceable, true},
		{"modemst1_a", CategoryRadio, CriticalityIrreplaceable, true},
		{"modemst2_b", CategoryRadio, CriticalityIrreplaceable, true},
		{"fsg", CategoryRadio, CriticalityIrreplaceable, true},
		{"fsc", CategoryRadio, CriticalityIrreplaceable, true},
		{"persist", CategoryCalibration, CriticalityIrreplaceable, true},
		{"prodpersist", CategoryCalibration, CriticalityIrreplaceable, true},
		{"cid", CategoryIdentity, CriticalityIrreplaceable, true},
		{"frp", CategoryIdentity, CriticalityImportant, true},
		{"devinfo", CategoryIdentity, CriticalityImportant, true},
		{"utags", CategoryIdentity, CriticalityImportant, true},
		{"hw", CategoryIdentity, CriticalityImportant, true},
		{"nvram", CategoryRadio, CriticalityIrreplaceable, true},
		{"efs", CategoryRadio, CriticalityIrreplaceable, true},
		{"xbl_a", CategoryBoot, CriticalityReplaceable, false},
		{"abl_b", CategoryBoot, CriticalityReplaceable, false},
		{"tz", CategoryBoot, CriticalityReplaceable, false},
		{"unknown_part", CategoryUnknown, CriticalityReplaceable, false},
		// Android payload and peripheral firmware: described, but nothing a
		// blankflash must preserve, so none of it may become protected.
		{"boot_a", CategoryOS, CriticalityReplaceable, false},
		{"vendor_boot_b", CategoryOS, CriticalityReplaceable, false},
		{"super", CategoryOS, CriticalityReplaceable, false},
		{"system_dlkm_a", CategoryOS, CriticalityReplaceable, false},
		{"vbmeta_system_b", CategoryOS, CriticalityReplaceable, false},
		{"modem_a", CategoryRadio, CriticalityReplaceable, false},
		{"userdata", CategoryData, CriticalityImportant, false},
		{"metadata", CategoryData, CriticalityImportant, false},
		{"apdp", CategoryPlatform, CriticalityReplaceable, false},
		{"last_parti4", CategoryPlatform, CriticalityReplaceable, false},
		{"pad3", CategoryPlatform, CriticalityReplaceable, false},
	}

	for _, tc := range cases {
		meta := Classify(tc.name)
		if meta.Category != tc.category {
			t.Errorf("%s: category got %s, want %s", tc.name, meta.Category, tc.category)
		}
		if meta.Criticality != tc.criticality {
			t.Errorf("%s: criticality got %s, want %s", tc.name, meta.Criticality, tc.criticality)
		}
		if meta.Protected != tc.protected {
			t.Errorf("%s: protected got %v, want %v", tc.name, meta.Protected, tc.protected)
		}
	}
}

func TestSynthesizeDirectives(t *testing.T) {
	targetParts := []string{"persist", "modemst1", "modemst2", "fsg", "cid", "frp", "utags", "devinfo"}
	flashOrder := []string{"abl", "xbl", "tz"}

	backups, restores := SynthesizeDirectives(targetParts, flashOrder)

	if len(backups) == 0 {
		t.Fatal("expected non-empty backups")
	}
	if len(restores) == 0 {
		t.Fatal("expected non-empty restores")
	}

	backupText := strings.Join(backups, "\n")
	restoreText := strings.Join(restores, "\n")

	// Ensure core protected partitions are present
	for _, p := range []string{"persist", "modemst1", "modemst2", "fsg", "cid", "frp", "utags", "devinfo", "sp", "hw", "misc"} {
		want := `<backup name="` + p + `"/>`
		if !strings.Contains(backupText, want) {
			t.Errorf("missing %s in backup directives", want)
		}
	}

	// Ensure commit tag is present
	if !strings.Contains(backupText, `<backup commit="1"/>`) {
		t.Error("missing <backup commit=\"1\"/>")
	}

	// Ensure skip tags for boot components in both slots
	for _, b := range []string{"abl_a", "abl_b", "xbl_a", "xbl_b", "tz_a", "tz_b"} {
		if !strings.Contains(backupText, `skip="true"`) || !strings.Contains(backupText, b) {
			t.Errorf("expected skip directive for %s", b)
		}
	}

	// Ensure restore directive is present
	if !strings.Contains(restoreText, `<restore dummy="foo"/>`) {
		t.Error("missing <restore dummy=\"foo\"/>")
	}
}

func TestAudit(t *testing.T) {
	parts := []string{"modemst1", "modemst2", "fsg", "persist", "abl_a", "xbl_a", "tz_a", "custom_scratch"}
	rep := Audit(parts)

	if rep.ProtectedCount != 4 {
		t.Errorf("protected count: got %d, want 4", rep.ProtectedCount)
	}
	if rep.ReplaceableCount != 3 {
		t.Errorf("replaceable count: got %d, want 3", rep.ReplaceableCount)
	}
	if rep.UnknownCount != 1 {
		t.Errorf("unknown count: got %d, want 1", rep.UnknownCount)
	}
}

