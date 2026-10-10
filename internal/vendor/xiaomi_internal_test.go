package vendor

import (
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
)

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
		if len(got) != 1 || got[0].What != c.what || got[0].URL != c.url || got[0].Found != (c.url != "") || got[0].Hint != c.hint {
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

func TestXiaomiSKUProps(t *testing.T) {
	b := facts.NewBag()
	recognizeXiaomiSKUProps(b, facts.File{Name: "odm/etc/m7g_ss_build.prop", Data: []byte("ro.product.odm.model=23021RAAEG\n")})
	recognizeXiaomiSKUProps(b, facts.File{Name: "vendor/etc/m7g_build.prop", Data: []byte("x=1\n")}) // not odm's
	got := facts.GetAll(b, imgfacts.SourcePartProps)
	if len(got) != 1 || got[0].SKU != "m7g_ss" || got[0].Props["ro.product.odm.model"] != "23021RAAEG" {
		t.Errorf("sku props = %+v", got)
	}
}

func TestXiaomiMirrors(t *testing.T) {
	got := xiaomi{}.Mirrors("https://bn.d.miui.com/OS4.0.24.0.XEOCNXM/madrid-ota.zip?x=1")
	if len(got) != len(xiaomiCDN)-1 || got[0] != "https://cdnorg.d.miui.com/OS4.0.24.0.XEOCNXM/madrid-ota.zip?x=1" {
		t.Errorf("mirrors = %v", got)
	}
	if got := (xiaomi{}).Mirrors("https://example.com/OS4/x.zip"); got != nil {
		t.Errorf("non-Xiaomi host: %v", got)
	}
}

func TestXiaomiIncrementalShape(t *testing.T) {
	for fp, want := range map[string]string{
		"Redmi/tapas_global/tapas:15/AQ3A.240829.003/OS2.0.209.0.VMTMIXM:user/release-keys":           "OS2.0.209.0.VMTMIXM",
		"Xiaomi/madrid/madrid:17/CP2A.260605.016/17OS4.0.261004.103610129.QCPECN.S:user/release-keys": "",
	} {
		if got, ok := xiaomiIncremental(fp); got != want && (ok || want != "") {
			t.Errorf("xiaomiIncremental(%s) = %q, %v", fp, got, ok)
		}
	}
}

func TestXiaomiBuildFromMiExt(t *testing.T) {
	b := facts.NewBag()
	rs := append(imgfacts.Recognizers(), xiaomi{}.FactRecognizers()...)
	facts.Recognize(b, rs, facts.File{Name: "mi_ext/etc/build.prop", Data: []byte("ro.build.version.incremental=OS4.0.24.0.XEOCNXM\n")})
	facts.New(xiaomi{}.FactProviders(), nil).ResolveAll(b, facts.Options{})
	if v, _ := facts.Get(b, facts.SoftwareVersion); v != "OS4.0.24.0.XEOCNXM" {
		t.Errorf("build = %q", v)
	}
}
