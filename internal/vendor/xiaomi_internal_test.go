package vendor

import "testing"

func TestXiaomiCompanions(t *testing.T) {
	const dir = "https://bn.d.miui.com/OS2.0.209.0.VMTMIXM/"
	const tgz = dir + "tapas_global_images_OS2.0.209.0.VMTMIXM_20260909.0000.00_15.0_global_2936b5ae03.tgz"
	const ota = dir + "tapas_global-ota_full-OS2.0.209.0.VMTMIXM-user-15.0-e4778deae7.zip"
	for _, c := range []struct {
		in    string
		known []string
		what  string
		url   string
		hint  string
	}{
		{tgz, nil, "full OTA", "", dir + "tapas_global-ota_full-OS2.0.209.0.VMTMIXM-user-15.0-<hash>.zip"},
		// The other release's OTA, and an OTA of another device, are not it.
		{tgz, []string{dir + "tapas_global-ota_full-OS2.0.100.0.VMTMIXM-user-15.0-0123456789.zip",
			dir + "sky_global-ota_full-OS2.0.209.0.VMTMIXM-user-15.0-0123456789.zip", ota},
			"full OTA", ota, dir + "tapas_global-ota_full-OS2.0.209.0.VMTMIXM-user-15.0-<hash>.zip"},
		{ota + "?sig=x", []string{tgz}, "fastboot package", tgz,
			dir + "tapas_global_images_OS2.0.209.0.VMTMIXM_<date>_15.0_global_<hash>.tgz"},
	} {
		got := xiaomi{}.Companions(c.in, c.known)
		if len(got) != 1 || got[0].What != c.what || got[0].URL != c.url || got[0].Hint != c.hint {
			t.Errorf("Companions(%s) = %+v", c.in, got)
		}
	}
	if got := (xiaomi{}).Companions("/tmp/fogona.zip", []string{ota}); got != nil {
		t.Errorf("unrelated name: %+v", got)
	}
}

func TestXiaomiBuildFacts(t *testing.T) {
	if v, ok := xiaomiIncremental("Redmi/tapas_global/tapas:15/AQ3A.240829.003/OS2.0.209.0.VMTMIXM:user/release-keys"); !ok || v != "OS2.0.209.0.VMTMIXM" {
		t.Errorf("incremental = %q, %v", v, ok)
	}
	if _, ok := xiaomiIncremental("motorola/fogona_g/fogona:14/U1TF.1/abc:user/release-keys"); ok {
		t.Error("incremental from a non-Xiaomi fingerprint")
	}
	m := parseMiscTxt([]byte("device=tapas\nbuild_number=OS2.0.209.0.VMTMIXM\n"))
	if m["device"] != "tapas" || m["build_number"] != "OS2.0.209.0.VMTMIXM" {
		t.Errorf("misc.txt = %v", m)
	}
}
