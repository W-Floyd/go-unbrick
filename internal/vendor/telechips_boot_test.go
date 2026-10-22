package vendor

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// bootStage is a Telechips BL3 whose default environment is env, a string per
// variable.
func bootStage(env ...string) []byte {
	img := make([]byte, 0x4000)
	copy(img, "CERT")
	copy(img[0x100:], "HDR\x00")
	img[0x105] = 0x10 // payload 0x1000
	img[0x109] = 0x10 // at 0x1000
	copy(img[0x110:], "803xA53-BL3")
	copy(img[0x120:], "0.0.0")
	p := img[0x1000+0x90:]
	copy(p, "U-Boot 2020.01 (Jan 07 2026 - 17:20:41 +0900)\x00"+strings.Join(env, "\x00")+"\x00")
	return img
}

const testBootcmd = "bootcmd=if test ${rst_type} = cold; then " +
	"fdt load - ${bootdevnum}#a7s_dtb ${slot} ${subcore_fdt_addr}; " +
	"tcc_load part - ${bootdevnum}#a7s_boot ${slot} ${subcore_kerneladdr}; avm_start 0; fi; " +
	"run loadfdtpart; dtimg load - 0#dtbo ${slot} ${overlay_addr}; " +
	"if run avb_verify; then echo OK;else exit;fi; boot_android - ${bootdevnum}#${miscpart} ${slot} ${kerneladdr}"

func recognizedStage(t *testing.T, env ...string) *facts.Bag {
	t.Helper()
	bag := facts.NewBag()
	got := facts.Recognize(bag, tcc{}.FactRecognizers(), facts.File{Name: "bl3_ca53", Data: bootStage(env...), From: "pkg payload bl3_ca53"})
	if len(got) != 1 {
		t.Fatalf("not recognised: %v", got)
	}
	return bag
}

func derive(t *testing.T, bag *facts.Bag) {
	t.Helper()
	for _, p := range (tcc{}).FactProviders() {
		if _, err := p.Derive(bag); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTelechipsBootLoadsAndWhatVBMetaDoesNotCover(t *testing.T) {
	bag := recognizedStage(t, testBootcmd, "miscpart=misc", "bootpart=boot", "fdtpart=dtb",
		"avb_verify=avb init ${bootdev} ${bootdevnum}; avb verify ${slot};",
		"loadfdtpart=fdt load - ${bootdevnum}#${fdtpart} ${slot} ${fdt_addr}")
	facts.Set(bag, facts.AVBProtected, "boot, dtbo, system, vendor", facts.Provenance{Source: "vbmeta", Authority: facts.Attested})
	derive(t, bag)

	loads, ok := facts.Get(bag, TelechipsBootLoads)
	if !ok || loads != "before the AVB check: a7s_dtb, a7s_boot, dtb, dtbo; after it: boot" {
		t.Errorf("loads: %q", loads)
	}
	un, ok := facts.Get(bag, TelechipsUnprotectedLoads)
	if !ok || un != "a7s_dtb (fdt load), a7s_boot (tcc_load part), dtb (fdt load)" {
		t.Errorf("unprotected: %q", un)
	}
}

// With no vbmeta to compare against, the loads are known but nothing is said of
// coverage: absence of the other half is not "none covered".
func TestTelechipsUnprotectedNeedsTheVBMeta(t *testing.T) {
	bag := recognizedStage(t, testBootcmd, "miscpart=misc")
	derive(t, bag)
	if _, ok := facts.Get(bag, TelechipsBootLoads); !ok {
		t.Error("loads are known without a vbmeta")
	}
	if v, ok := facts.Get(bag, TelechipsUnprotectedLoads); ok {
		t.Errorf("coverage claimed with no vbmeta: %q", v)
	}
}

func TestTelechipsStageWithoutABootScriptIsNotASource(t *testing.T) {
	bag := facts.NewBag()
	if got := facts.Recognize(bag, tcc{}.FactRecognizers(), facts.File{Name: "x", Data: bootStage("bootdelay=0")}); len(got) != 0 {
		t.Errorf("recognised a stage with no bootcmd: %v", got)
	}
	if got := facts.Recognize(bag, tcc{}.FactRecognizers(), facts.File{Name: "x", Data: []byte("not an image")}); len(got) != 0 {
		t.Errorf("recognised a non-image: %v", got)
	}
}
