package vendor

import "testing"

func TestParseSLCF(t *testing.T) {
	// Empty file = retail default, no lock.
	if c, _ := ParseSLCF(nil); c.Locked {
		t.Error("empty .nvm should be unlocked")
	}
	// Minimal record set: state item, plus a config record with a control-key
	// placeholder and two PLMN entries (MCC 0x03 MNC + small status byte).
	// 802160ea + "0001"; 802162ea + <CK-16> + "310"03"240"02 "311"03"480"05
	nvm := "802160ea0001\n" +
		"802162ea<CK-16>" +
		"333130" + "03" + "323430" + "02" + // 310 x03 240 x02
		"333131" + "03" + "343830" + "05" + // 311 x03 480 x05
		"\n"
	c, err := ParseSLCF([]byte(nvm))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Locked || c.ControlKeyDigits != 16 {
		t.Errorf("locked=%v keydigits=%d", c.Locked, c.ControlKeyDigits)
	}
	if len(c.PLMNs) != 2 || c.PLMNs[0].String() != "310-240 (T-Mobile)" || c.PLMNs[1].MCC != "311" {
		t.Errorf("PLMNs=%v", c.PLMNs)
	}
	if len(c.NVItems) != 2 {
		t.Errorf("NVItems=%v", c.NVItems)
	}
}

func TestParseFlashfile(t *testing.T) {
	xml := `<flashing>
	  <software_version version="fogona_g-user 14 U1TFS34.100-35-14-1-21 release-keys"/>
	  <subsidy_lock_config MD5="abc" name="slcf_rev_d_trac_visible_rsu_v1.3.nvm"/>
	  <cid_value value="0x0033"/>
	</flashing>`
	ff := ParseFlashfile([]byte(xml))
	if ff.CIDValue != "0x0033" {
		t.Errorf("CIDValue=%q", ff.CIDValue)
	}
	if ff.SubsidyLock != "slcf_rev_d_trac_visible_rsu_v1.3.nvm" {
		t.Errorf("SubsidyLock=%q", ff.SubsidyLock)
	}
	if ff.SoftwareVersion == "" {
		t.Error("SoftwareVersion empty")
	}
}
