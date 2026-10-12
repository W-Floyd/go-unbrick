package port

import (
	"strings"
	"testing"
)

func pkgWithFiles() Package {
	return Package{
		FileIndex: map[string][]string{
			"venus.mbn":        {"modem_a:image/venus.mbn"},
			"venus.b00":        {"modem_a:image/venus.b00"},
			"touch.bin":        {"vendor_a:firmware/touch.bin"},
			"a610_zap.mdt":     {"modem_a:image/a610_zap.mdt"},
			"a662_zap.mdt":     {"vendor_a:firmware/a662_zap.mdt"},
			"a610_sqe.fw":      {"vendor_a:firmware/a610_sqe.fw"},
			"adsp.mdt":         {"modem_a:image/adsp.mdt"},
			"adsp.b00":         {"modem_a:image/adsp.b00"},
			"unrelated_fw.bin": {"vendor_a:firmware/unrelated_fw.bin"},
		},
		PartFiles: []PartFiles{{Name: "modem", Files: []string{"image/adsp.mdt", "image/adsp.b00", "image/venus.mbn", "image/Data.msc"}}},
	}
}

func refBy(refs []FirmwareRef, name string) *FirmwareRef {
	for i, r := range refs {
		for _, n := range r.Names {
			if n == name {
				return &refs[i]
			}
		}
	}
	return nil
}

func TestFirmwareRefsFromDeviceTreeStem(t *testing.T) {
	p := pkgWithFiles()
	p.DT.FirmwareNames = []FirmwareName{{Prop: "vidc,firmware-name", Value: "venus"}}
	r := refBy(FirmwareRefs(p), "venus.mbn")
	if r == nil {
		t.Fatal("venus not found")
	}
	// A split image's .b00 segment is part of it, not an alternative name.
	if strings.Contains(strings.Join(r.Names, " "), "venus.b00") {
		t.Errorf("segment taken as a name: %v", r.Names)
	}
	if !strings.Contains(strings.Join(r.By, " "), "device tree vidc,firmware-name") || len(r.Where) == 0 {
		t.Errorf("by %v where %v", r.By, r.Where)
	}
}

func TestFirmwareRefsFromDriversKeepOnlyFilesThePackageHas(t *testing.T) {
	p := pkgWithFiles()
	p.Modules = []Module{{Name: "touch_drv", Firmware: []string{"touch.bin", "never_shipped.bin"}}}
	refs := FirmwareRefs(p)
	if r := refBy(refs, "touch.bin"); r == nil || r.By[0] != "driver touch_drv" {
		t.Errorf("touch.bin: %+v", r)
	}
	if refBy(refs, "never_shipped.bin") != nil {
		t.Error("a name the package lacks must not be a reference")
	}
	if refBy(refs, "unrelated_fw.bin") != nil {
		t.Error("a file no driver or tree names is not a reference")
	}
}

func TestGPUModelNarrowsAGenerationsList(t *testing.T) {
	p := pkgWithFiles()
	p.DT.GPU = "Adreno610v2"
	p.Modules = []Module{{Name: "kgsl", Firmware: []string{"a610_zap.mdt", "a662_zap.mdt", "a610_sqe.fw"}}}
	refs := FirmwareRefs(p)
	if refBy(refs, "a610_zap.mdt") == nil || refBy(refs, "a610_sqe.fw") == nil {
		t.Error("the board's own generation was dropped")
	}
	if refBy(refs, "a662_zap.mdt") != nil {
		t.Error("another generation's firmware should be narrowed out")
	}

	// Without a model, nothing is narrowed.
	p.DT.GPU = ""
	if refBy(FirmwareRefs(p), "a662_zap.mdt") == nil {
		t.Error("with no GPU model every generation stays")
	}
}

func TestFirmwareRefsIncludeWhatTheModemPartitionShips(t *testing.T) {
	refs := FirmwareRefs(pkgWithFiles())
	r := refBy(refs, "adsp.mdt")
	if r == nil || !strings.Contains(strings.Join(r.By, " "), "shipped in the modem partition") {
		t.Errorf("adsp: %+v", r)
	}
	if refBy(refs, "Data.msc") != nil {
		t.Error("only remoteproc images (.mdt, .mbn) count as shipped subsystem firmware")
	}
}

func TestNamedButAbsentFirmwareIsStillAReference(t *testing.T) {
	p := Package{FileIndex: map[string][]string{}}
	p.DT.FirmwareNames = []FirmwareName{{Prop: "firmware-name", Value: "missing_fw"}}
	refs := FirmwareRefs(p)
	if len(refs) != 1 || refs[0].Names[0] != "missing_fw" || len(refs[0].Where) != 0 {
		t.Errorf("refs %+v", refs)
	}
}
