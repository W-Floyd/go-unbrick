package vendor

import "testing"

func TestParseBuildInfo(t *testing.T) {
	sheet := `BUILD REQUEST INFO:
SW Version: fogona_g-user 14 U1TFS34.100-35-14-1-21 e7791-698bc2 release-keys
Modem Version: HA12_26.35.01.61R
FSG Version: FSG-6225-05.67
MBM Version: MBM-3.0-fogona-c4cd6cf87739-260723-U1TFS34.100-35-14-1-21-e7791
Build Fingerprint: motorola/fogona_g/fogona:14/U1TFS34.100-35-14-1-21/e7791-698bc2:user/release-keys

Model Number: moto g play - 2024
Build Date: Thu Jul 23 13:23:45 CDT 2026`
	bi := ParseBuildInfo([]byte(sheet))
	if bi == nil {
		t.Fatal("nil")
	}
	if bi.Fingerprint != "motorola/fogona_g/fogona:14/U1TFS34.100-35-14-1-21/e7791-698bc2:user/release-keys" {
		t.Errorf("fingerprint: %q", bi.Fingerprint)
	}
	if bi.MarketingName != "moto g play - 2024" {
		t.Errorf("marketing: %q", bi.MarketingName)
	}
	if bi.Modem != "HA12_26.35.01.61R" {
		t.Errorf("modem: %q", bi.Modem)
	}
	if bi.MBMDate() != "260723" {
		t.Errorf("mbm date: %q", bi.MBMDate())
	}
	// A member that is not a build sheet must not parse (so it isn't recognized).
	if ParseBuildInfo([]byte("just some text\nwith lines")) != nil {
		t.Error("non-sheet parsed")
	}
}
