package nura

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/port"
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

func TestOutsideFileInAWalkedDirIsExplainedWhenShadowed(t *testing.T) {
	// The loader skips firmware/adsp.elf: modem's image/adsp.mdt already has the name adsp.
	pl := PlanLoader("_a", []PartFiles{
		{Name: "modem", Files: []string{"image/adsp.mdt"}},
		{Name: "vendor", Files: []string{"firmware/adsp.elf", "etc/cfg.ini"}},
	})
	cov := Check(pl, []Need{{Name: "n", Files: []string{"adsp.elf"}}, {Name: "m", Files: []string{"cfg.ini"}}},
		map[string][]string{"adsp.elf": {"vendor_a:firmware/adsp.elf"}, "cfg.ini": {"vendor_a:etc/cfg.ini"}})
	if cov[0].Status != OutsideLoader || !strings.Contains(cov[0].Where, "skipped: modem:image/adsp.mdt already has this name") {
		t.Errorf("shadowed file: %+v", cov[0])
	}
	if cov[1].Status != OutsideLoader || strings.Contains(cov[1].Where, "skipped") {
		t.Errorf("a file somewhere the loader never looks needs no shadow note: %+v", cov[1])
	}
}

func TestStockDriverOnlyNamesAreNotThingsToShip(t *testing.T) {
	p := port.Package{
		PartFiles: []PartFiles{{Name: "vendor", Files: []string{"etc/wifi/cfg.ini", "firmware/touch.bin"}}},
		FileIndex: map[string][]string{"cfg.ini": {"vendor_a:etc/wifi/cfg.ini"}, "touch.bin": {"vendor_a:firmware/touch.bin"}},
		Modules:   []port.Module{{Name: "qca_wlan", Firmware: []string{"cfg.ini"}}},
		DT:        port.DT{FirmwareNames: []port.FirmwareName{{Prop: "firmware-name", Value: "touch.bin"}}},
	}
	lc := CheckLoader(p)
	if got := lc.ToShip(); len(got) != 0 {
		t.Errorf("a name only the stock Wi-Fi driver asks for must not be shipped: %v", got)
	}
	var proxy, authoritative int
	for _, c := range lc.Coverage {
		if c.Proxy {
			proxy++
		} else {
			authoritative++
		}
	}
	if proxy != 1 || authoritative != 1 {
		t.Errorf("proxy %d authoritative %d, want 1 and 1: %+v", proxy, authoritative, lc.Coverage)
	}
	for _, want := range []string{"cover 1 of 1", "Stock Android drivers name 1 more, 1 of them not exposed"} {
		if !strings.Contains(lc.Verdict, want) {
			t.Errorf("verdict %q lacks %q", lc.Verdict, want)
		}
	}
	// A name the device tree also asks for is authoritative, whoever else does.
	p.DT.FirmwareNames = append(p.DT.FirmwareNames, port.FirmwareName{Prop: "firmware-name", Value: "cfg.ini"})
	if got := CheckLoader(p).ToShip(); len(got) != 1 {
		t.Errorf("once the device tree names it, it is a need: %v", got)
	}
}

func TestVerdictWithNothingToMount(t *testing.T) {
	pl := PlanLoader("", []PartFiles{{Name: "boot", Files: nil}})
	if got := Verdict(pl, nil); !strings.Contains(got, "nothing to mount") {
		t.Errorf("got %q", got)
	}
}

func TestNeedsComeFromTheBoardsOwnReferences(t *testing.T) {
	p := port.Package{
		PartFiles: parts(),
		FileIndex: map[string][]string{"adsp.mdt": {"modem_a:image/adsp.mdt"}, "touch.bin": {"vendor_a:firmware/touch.bin"}},
		Modules:   []port.Module{{Name: "touch_drv", Firmware: []string{"touch.bin", "not-in-the-package.bin"}}},
	}
	var got []string
	for _, n := range Needs(p) {
		got = append(got, n.Name+"="+strings.Join(n.Files, ","))
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"driver touch_drv=touch.bin", "shipped in the modem partition=adsp.mdt"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if strings.Contains(joined, "not-in-the-package") {
		t.Errorf("a name a driver mentions but the package lacks is not a need: %s", joined)
	}
}
