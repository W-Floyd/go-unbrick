package nura

import (
	"errors"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/port"
)

func loadCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load("../../../catalog")
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func fogona() port.Package {
	return port.Package{
		Props: map[string]string{
			"ro.product.vendor.manufacturer": "motorola", "ro.product.vendor.device": "fogona",
			"ro.product.vendor.model": "moto g play - 2024", "ro.vendor.product.cpu.abilist64": "arm64-v8a",
		},
		DT: port.DT{Model: "fogona"},
	}
}

func TestConfigComesFromTheCatalogEntry(t *testing.T) {
	c := configFrom(loadCatalog(t))
	if !c.fromCatalog || c.KernelPackage != "linux-{vendor}-{codename}" || c.LoaderPackage != "msm-firmware-loader" ||
		c.BuildFunc != "devicepkg_build" || len(c.Depends) != 1 || len(c.MakeDepends) != 1 {
		t.Errorf("config %+v", c)
	}
	if got := c.kernelName(fogona()); got != "linux-motorola-fogona" {
		t.Errorf("kernel package %q", got)
	}
	if got := c.deviceName(fogona()); got != "device-motorola-fogona" {
		t.Errorf("device package %q", got)
	}
	// No catalog: structural defaults only, everything else blank.
	none := configFrom(nil)
	if none.fromCatalog || none.KernelPackage != "" || none.deviceName(fogona()) != "device-motorola-fogona" {
		t.Errorf("without a catalog: %+v", none)
	}
}

func TestAPKBUILDCarriesTheDeviceinfoChecksumAndDependencies(t *testing.T) {
	c := configFrom(loadCatalog(t))
	p := fogona()
	deviceinfo := []byte(Render(Deviceinfo(p, true)))
	loader := &LoaderCheck{Coverage: []Coverage{{Status: ByLoader}, {Status: ByLoader, Proxy: true}, {Status: OutsideLoader}}}
	out := apkbuild(p, c, deviceinfo, Deviceinfo(p, true), loader, "")
	for _, want := range []string{
		"pkgname=device-motorola-fogona",
		`pkgdesc="Motorola Moto G Play 2024"`,
		`arch="aarch64"`,
		"\tlinux-motorola-fogona\n",
		"\tmkbootimg\n",
		"\tpostmarketos-base\n",
		"\tmsm-firmware-loader # covers 1 of the files",
		`makedepends="devicepkg-dev"`,
		"devicepkg_build $startdir $pkgname",
		sha512hex(deviceinfo) + "  deviceinfo",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "firmware-motorola-fogona") {
		t.Error("no firmware package, so no dependency on one")
	}
	// A loader that covers nothing is not a dependency.
	if strings.Contains(apkbuild(p, c, deviceinfo, nil, &LoaderCheck{}, ""), "msm-firmware-loader") {
		t.Error("the loader is a dependency only when it covers something")
	}
	if !strings.Contains(apkbuild(p, c, deviceinfo, nil, nil, "firmware-motorola-fogona"), "\tfirmware-motorola-fogona\n") {
		t.Error("a firmware package is a dependency")
	}
}

func TestAPKBUILDWithoutACatalogLeavesTODOsNotGuesses(t *testing.T) {
	p := fogona()
	out := apkbuild(p, configFrom(nil), []byte("x"), nil, nil, "")
	for _, want := range []string{"TODO: no packaging conventions", "# TODO: the kernel package", "# TODO: the distribution's base package", `makedepends="" # TODO: `, "TODO_function"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "mkbootimg") || strings.Contains(out, "postmarketos-base") {
		t.Error("a name the catalog does not give must not be invented")
	}
}

func TestFirmwarePackageCopiesFilesTheLoaderCannotSupply(t *testing.T) {
	c := configFrom(loadCatalog(t))
	p := fogona()
	p.SoC = []port.SoCMatch{{File: "arch/arm64/boot/dts/qcom/sm6225.dtsi"}}
	blob := func(loc string) ([]byte, error) {
		if loc == "vendor_a:etc/wifi/cfg.ini" {
			return []byte("cfg"), nil
		}
		return nil, errors.New("not here")
	}
	files, notes := firmwarePackage(p, port.Options{Blob: blob}, c, []string{"vendor_a:etc/wifi/cfg.ini", "vendor_a:etc/missing.bin"})
	if string(files["firmware-motorola-fogona/cfg.ini"]) != "cfg" {
		t.Errorf("files %v", files)
	}
	apk := string(files["firmware-motorola-fogona/APKBUILD"])
	for _, want := range []string{
		"pkgname=firmware-motorola-fogona",
		`license="proprietary"`,
		`install -Dm644 "$srcdir"/cfg.ini -t "$pkgdir"/usr/lib/firmware/qcom/sm6225/motorola/fogona/`,
		sha512hex([]byte("cfg")) + "  cfg.ini",
	} {
		if !strings.Contains(apk, want) {
			t.Errorf("missing %q in:\n%s", want, apk)
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "etc/missing.bin") {
		t.Errorf("a file that cannot be read is a note, not a silent drop: %v", notes)
	}

	// Without the package at hand, the files are listed and the gap is said.
	_, notes = firmwarePackage(p, port.Options{}, c, []string{"vendor_a:etc/wifi/cfg.ini"})
	if len(notes) != 1 || !strings.Contains(notes[0], "was not at hand") {
		t.Errorf("no reader: %v", notes)
	}
}

func TestEmitWritesTheDevicePackageAndOnlyShipsWhatIsNeeded(t *testing.T) {
	cat := loadCatalog(t)
	p := fogona()
	p.PartFiles = []PartFiles{{Name: "modem", Files: []string{"image/adsp.mdt"}}, {Name: "vendor", Files: []string{"etc/cfg.ini"}}}
	p.FileIndex = map[string][]string{"adsp.mdt": {"modem_a:image/adsp.mdt"}, "cfg.ini": {"vendor_a:etc/cfg.ini"}}
	p.DT.FirmwareNames = []port.FirmwareName{{Prop: "firmware-name", Value: "cfg.ini"}}
	p.Slot = "_a"
	b, err := (emitter{}).Emit(p, port.Options{Catalog: cat, Blob: func(string) ([]byte, error) { return []byte("data"), nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"device-motorola-fogona/APKBUILD", "device-motorola-fogona/deviceinfo", "firmware-motorola-fogona/APKBUILD", "firmware-motorola-fogona/cfg.ini"} {
		if _, ok := b.Files[f]; !ok {
			t.Errorf("missing %s: %v", f, keys(b.Files))
		}
	}
	if !strings.Contains(string(b.Files["device-motorola-fogona/APKBUILD"]), "\tfirmware-motorola-fogona\n") {
		t.Error("the device package must depend on the firmware package it needs")
	}

	// The same board with nothing outside the loader writes no firmware package.
	p.DT.FirmwareNames = nil
	b, _ = (emitter{}).Emit(p, port.Options{Catalog: cat})
	for f := range b.Files {
		if strings.HasPrefix(f, "firmware-") {
			t.Errorf("unexpected firmware file %s", f)
		}
	}

	if _, err := (emitter{}).Emit(port.Package{}, port.Options{}); err == nil {
		t.Error("a package that names no maker has no package name")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
