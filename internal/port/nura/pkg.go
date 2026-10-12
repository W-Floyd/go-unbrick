package nura

import (
	"crypto/sha512"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/port"
)

// config is the packaging convention, read from the bundle section of the
// distribution's catalog entry (catalog/distros.yaml). An empty value is a
// name the catalog does not give, which the generated file marks TODO rather
// than guesses.
type config struct {
	Category, DevicePrefix, FirmwarePrefix, License string
	KernelPackage, BasePackage, LoaderPackage       string
	BuildFunc, PackageFunc                          string
	Depends, MakeDepends                            []string
	fromCatalog                                     bool
}

// catalogIDs are the entries the emitter reads its conventions from, first
// match wins: the Nura name, then the one the entry still has.
var catalogIDs = []string{"nura", "postmarketos"}

func configFrom(cat *catalog.Catalog) config {
	c := config{DevicePrefix: "device", FirmwarePrefix: "firmware"}
	for _, id := range catalogIDs {
		for _, d := range cat.Distros() {
			if d.Ident != id || d.Bundle == nil {
				continue
			}
			c.fromCatalog = true
			str := func(k string, dst *string) {
				if v, ok := d.Bundle[k].(string); ok && v != "" {
					*dst = v
				}
			}
			list := func(k string) []string {
				var out []string
				if vs, ok := d.Bundle[k].([]any); ok {
					for _, v := range vs {
						if s, ok := v.(string); ok {
							out = append(out, s)
						}
					}
				}
				return out
			}
			str("category", &c.Category)
			str("device_prefix", &c.DevicePrefix)
			str("firmware_prefix", &c.FirmwarePrefix)
			str("license", &c.License)
			str("kernel_package", &c.KernelPackage)
			str("base_package", &c.BasePackage)
			str("loader_package", &c.LoaderPackage)
			str("build_func", &c.BuildFunc)
			str("package_func", &c.PackageFunc)
			c.Depends, c.MakeDepends = list("depends"), list("makedepends")
			return c
		}
	}
	return c
}

func (c config) deviceName(p port.Package) string {
	return c.DevicePrefix + "-" + port.BoardName(p)
}

func (c config) firmwareName(p port.Package) string {
	return c.FirmwarePrefix + "-" + port.BoardName(p)
}

// kernelName fills the kernel package template ("linux-{vendor}-{codename}").
func (c config) kernelName(p port.Package) string {
	if c.KernelPackage == "" {
		return ""
	}
	brand, code, _ := p.Identity()
	return strings.NewReplacer("{vendor}", strings.ToLower(brand), "{codename}", code).Replace(c.KernelPackage)
}

func sha512hex(b []byte) string { return fmt.Sprintf("%x", sha512.Sum512(b)) }

// apkbuild writes the device package's APKBUILD. deviceinfo is the file's text,
// whose checksum it carries; lines supplies the architecture.
func apkbuild(p port.Package, c config, deviceinfo []byte, lines []Line, loader *LoaderCheck, firmwarePkg string) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	_, _, name := p.Identity()
	pkg := c.deviceName(p)

	w("# Draft from a stock package by unbrick port. Lines marked TODO need a decision.")
	if c.fromCatalog {
		w("# Package names come from the bundle section of catalog/distros.yaml, as they")
		w("# were before the rename to Nura: check them against the tree this goes into.")
	} else {
		w("# TODO: no packaging conventions in the catalog; package names below are blank.")
	}
	w(`maintainer=""`)
	w("pkgname=%s", pkg)
	w("pkgdesc=%q", name)
	w("pkgver=0")
	w("pkgrel=0")
	w(`url="" # TODO`)
	if c.License != "" {
		w("license=%q", c.License)
	} else {
		w(`license="" # TODO`)
	}
	arch := ""
	for _, l := range lines {
		if l.Key == "arch" {
			arch = l.Val
		}
	}
	if arch != "" {
		w("arch=%q", arch)
	} else {
		w(`arch="" # TODO: a package named no 64-bit ABI`)
	}
	w(`options="!check !archcheck"`)

	w("depends=\"")
	if k := c.kernelName(p); k != "" {
		w("\t%s", k)
	} else {
		w("\t# TODO: the kernel package")
	}
	for _, d := range c.Depends {
		w("\t%s", d)
	}
	if c.BasePackage != "" {
		w("\t%s", c.BasePackage)
	} else {
		w("\t# TODO: the distribution's base package")
	}
	if loader != nil && c.LoaderPackage != "" && loaderCovers(loader) > 0 {
		w("\t%s # covers %d of the files the board names; see HARDWARE.md", c.LoaderPackage, loaderCovers(loader))
	}
	if firmwarePkg != "" {
		w("\t%s", firmwarePkg)
	}
	w("\"")
	if len(c.MakeDepends) > 0 {
		w("makedepends=\"%s\"", strings.Join(c.MakeDepends, " "))
	} else {
		w(`makedepends="" # TODO`)
	}
	w(`source="deviceinfo"`)
	w("")
	build, pack := orTodo(c.BuildFunc), orTodo(c.PackageFunc)
	w("build() {")
	w("\t%s $startdir $pkgname", build)
	w("}")
	w("")
	w("package() {")
	w("\t%s $startdir $pkgname", pack)
	w("}")
	w("")
	w("sha512sums=\"")
	w("%s  deviceinfo", sha512hex(deviceinfo))
	w("\"")
	return b.String()
}

func orTodo(s string) string {
	if s == "" {
		return "TODO_function"
	}
	return s
}

// loaderCovers counts the files the board names that the loader would expose
// (the stock-driver-only names are hints and do not count).
func loaderCovers(l *LoaderCheck) int {
	n := 0
	for _, c := range l.Coverage {
		if c.Status == ByLoader && !c.Proxy {
			n++
		}
	}
	return n
}

// firmwarePackage writes the firmware package for the files the loader cannot
// supply: an APKBUILD and the files, copied out of the stock package. ship are
// "partition:path" locations. Without a Blob reader the files are listed but
// not copied.
func firmwarePackage(p port.Package, o port.Options, c config, ship []string) (files map[string][]byte, notes []string) {
	pkg := c.firmwareName(p)
	brand, code, name := p.Identity()
	dir := path.Join(strings.ToLower(brand), code)
	soc := ""
	if len(p.SoC) > 0 {
		soc = strings.TrimSuffix(filepath.Base(p.SoC[0].File), ".dtsi")
		dir = path.Join("qcom", soc, dir)
	}
	sort.Strings(ship)

	files = map[string][]byte{}
	var installs, sums []string
	for _, loc := range ship {
		base := path.Base(loc)
		if o.Blob == nil {
			notes = append(notes, "firmware package lists "+loc+" but the stock package was not at hand to copy it from")
			continue
		}
		data, err := o.Blob(loc)
		if err != nil {
			notes = append(notes, fmt.Sprintf("firmware package: could not read %s: %v", loc, err))
			continue
		}
		files[pkg+"/"+base] = data
		installs = append(installs, fmt.Sprintf("\tinstall -Dm644 \"$srcdir\"/%s -t \"$pkgdir\"/usr/lib/firmware/%s/", base, dir))
		sums = append(sums, fmt.Sprintf("%s  %s", sha512hex(data), base))
	}

	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("# Draft from a stock package by unbrick port: firmware the loader cannot supply.")
	w("# TODO: the install directory is a guess at the convention; check where the drivers look.")
	w(`maintainer=""`)
	w("pkgname=%s", pkg)
	w("pkgver=0")
	w("pkgrel=0")
	w("pkgdesc=%q", "Firmware for "+name)
	w(`url="" # TODO`)
	w(`arch="aarch64"`)
	w(`license="proprietary"`)
	w(`options="!check !strip !archcheck !tracedeps"`)
	var srcs []string
	for _, loc := range ship {
		srcs = append(srcs, path.Base(loc))
	}
	w("source=\"%s\"", strings.Join(srcs, " "))
	w("")
	w("package() {")
	if len(installs) == 0 {
		w("\t# TODO: nothing was copied")
		w("\tmkdir -p \"$pkgdir\"")
	}
	for _, i := range installs {
		w("%s", i)
	}
	w("}")
	w("")
	w("sha512sums=\"")
	for _, s := range sums {
		w("%s", s)
	}
	w("\"")
	files[pkg+"/APKBUILD"] = []byte(b.String())
	return files, notes
}
