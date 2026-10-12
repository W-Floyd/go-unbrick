package nura

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
)

func parts() []PartFiles {
	return []PartFiles{
		{Name: "modem", Files: []string{"image/adsp.mdt", "image/adsp.b00", "image/adsp.b01", "image/adspr.jsn", "image/venus.mdt", "image/venus.b00", "image/Data.msc", "other/hidden.bin"}},
		{Name: "vendor", Files: []string{"firmware/touch.bin", "firmware/adsp.mdt", "etc/audio.bin", "lib/x.so"}},
		{Name: "bluetooth", Files: []string{"image/crbtfw.tlv"}},
		{Name: "fsg", Files: []string{"a1.mbn", "b1.mbn"}},
		{Name: "dsp", Files: []string{"adsp/m.so"}},
	}
}

func TestPlanLoaderLinksBlobsAndSiblings(t *testing.T) {
	pl := PlanLoader("_a", parts())
	for _, want := range []string{"adsp.mdt", "adsp.b00", "adsp.b01", "adspr.jsn", "touch.bin", "Data.msc"} {
		if _, ok := pl.Target[want]; !ok {
			t.Errorf("%s not exposed: %v", want, pl.Target)
		}
	}
	if _, ok := pl.Target["hidden.bin"]; ok {
		t.Error("only image/ and firmware/ are walked")
	}
	if _, ok := pl.Target["audio.bin"]; ok {
		t.Error("vendor/etc is not walked")
	}
	// .mdt gets an .mbn alias.
	if got := pl.Target["adsp.mbn"]; !strings.Contains(got, "as .mbn") {
		t.Errorf("adsp.mbn = %q", got)
	}
	// modem sorts before vendor, so its adsp.mdt wins over vendor's copy.
	if got := pl.Target["adsp.mdt"]; got != "modem:image/adsp.mdt" {
		t.Errorf("adsp.mdt from %q, want modem's", got)
	}
}

func TestPlanLoaderSpecialCases(t *testing.T) {
	pl := PlanLoader("_a", parts())
	for k, want := range map[string]string{
		"qca/crbtfw.tlv":         "bluetooth_a:image/crbtfw.tlv",
		"fsg/a1.mbn":             "fsg_a:a1.mbn",
		"qcom/venus-x/venus.mdt": "modem:image/venus.mdt",
	} {
		if got := pl.Target[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if strings.Join(pl.Mounted, " ") != "bluetooth_a dsp_a fsg_a modem_a vendor_a" {
		t.Errorf("mounted %v", pl.Mounted)
	}
	if strings.Join(pl.Missing, " ") != "apnhlos persist" {
		t.Errorf("missing %v (persist and apnhlos are not slotted)", pl.Missing)
	}
}

func TestCheckClassifiesNeeds(t *testing.T) {
	pl := PlanLoader("_a", parts())
	index := map[string][]string{"audio.bin": {"vendor_a:etc/audio.bin"}}
	cov := Check(pl, []Need{
		{Name: "dsp", Files: []string{"adsp.mbn|adsp.mdt"}},
		{Name: "amp", Files: []string{"audio.bin"}},
		{Name: "ghost", Files: []string{"nowhere.bin"}},
	}, index)
	want := []Status{ByLoader, OutsideLoader, Absent}
	for i, c := range cov {
		if c.Status != want[i] {
			t.Errorf("%s: %s, want %s", c.Need, c.Status, want[i])
		}
	}
	lc := &LoaderCheck{Plan: pl, Coverage: cov, Verdict: Verdict(pl, cov)}
	if got := lc.ToShip(); len(got) != 1 || got[0] != "vendor_a:etc/audio.bin" {
		t.Errorf("ToShip = %v", got)
	}
	if !strings.Contains(lc.Verdict, "covers 1 of 3") && !strings.Contains(lc.Verdict, "cover 1 of 3") {
		t.Errorf("verdict %q", lc.Verdict)
	}
}

func TestVerdictWithNothingToMount(t *testing.T) {
	pl := PlanLoader("", []PartFiles{{Name: "boot", Files: nil}})
	if got := Verdict(pl, nil); !strings.Contains(got, "nothing to mount") {
		t.Errorf("got %q", got)
	}
}

func TestNeedsDeriveGPUAndParts(t *testing.T) {
	cat, err := catalog.Load("../../catalog")
	if err != nil {
		t.Fatal(err)
	}
	p := Package{DT: DT{GPU: "Adreno610v2", Parts: []Part{{Compatible: "chipone-tddi"}, {Compatible: "qcom,rx-macro"}}}}
	var names []string
	for _, n := range Needs(p, cat) {
		names = append(names, n.Name+"="+strings.Join(n.Files, ","))
	}
	got := strings.Join(names, " ")
	for _, want := range []string{"adsp=adsp.mbn|adsp.mdt", "gpu=a610_zap.mbn|a610_zap.mdt", "chipone_firmware.bin"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Contains(got, "rx-macro") {
		t.Errorf("a part with no firmware must add no need: %s", got)
	}
}
