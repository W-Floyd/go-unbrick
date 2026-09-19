package vendor

import "testing"

func TestParseSigningInfo(t *testing.T) {
	txt := `HAB_PRODUCT fogona
HAB_SECURITY_VERSION 18
HAB_CID 50
HAB_CUSTOMER_REGION Retail
OTA_KEY motorola/security/certs/.../ota.x509.pem
This build is customer signed.
Retail                => 50
RetailLocked          => 51
enforce_anti_rollback_check_in_ota=true
[anti_rollback_version_begin]
xbl.elf=0x00
tz.mbn=0x02
[anti_rollback_version_end]`
	si := ParseSigningInfo([]byte(txt))
	if si == nil {
		t.Fatal("nil")
	}
	if si.HABCID != 50 || si.SecurityVersion != 18 || si.Region != "Retail" || !si.CustomerSigned {
		t.Errorf("fields: %+v", si)
	}
	if si.RegionCIDs["RetailLocked"] != 51 {
		t.Errorf("region map: %v", si.RegionCIDs)
	}
	if !si.EnforceOTARoll || len(si.Rollback) != 2 {
		t.Errorf("rollback: enf=%v n=%d", si.EnforceOTARoll, len(si.Rollback))
	}
	if len(si.RollbackBumped) != 1 || si.RollbackBumped[0] != "tz.mbn" {
		t.Errorf("bumped: %v", si.RollbackBumped)
	}
	if ParseSigningInfo([]byte("nothing here")) != nil {
		t.Error("non-signing-info should be nil")
	}
}
