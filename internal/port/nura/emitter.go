// Package nura is the port emitter for Nura (formerly postmarketOS): a device
// package's deviceinfo, and a check of whether msm-firmware-loader can supply
// the device's firmware from its own partitions.
package nura

import (
	"fmt"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/port"
)

func init() { port.Register(emitter{}) }

type emitter struct{}

func (emitter) ID() string    { return "nura" }
func (emitter) Title() string { return "Nura" }

// Emit writes the device package's deviceinfo and the loader findings.
func (emitter) Emit(p port.Package, o port.Options) (*port.Bundle, error) {
	brand, code, _ := p.Identity()
	if brand == "" || code == "" {
		return nil, fmt.Errorf("nura: the package names no maker or codename, so there is no device package name")
	}
	pkg := "device-" + strings.ToLower(brand) + "-" + code

	loader := CheckLoader(p)
	uses := loader != nil && len(loader.Plan.Mounted) > 0
	b := &port.Bundle{Files: map[string][]byte{
		pkg + "/deviceinfo": []byte(Render(Deviceinfo(p, uses))),
	}}
	if loader != nil {
		b.Report = append(b.Report, loaderSection(loader))
	}
	return b, nil
}

// loaderSection is the hardware report's account of msm-firmware-loader.
func loaderSection(l *LoaderCheck) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("## Firmware: msm-firmware-loader\n")
	w("%s.\n", l.Verdict)
	if len(l.Plan.Missing) > 0 {
		w("Not in the package: %s (`persist` is a device partition, read on the device).\n", strings.Join(l.Plan.Missing, ", "))
	}
	w("| needed by | file | status | where |")
	w("|---|---|---|---|")
	for _, c := range l.Coverage {
		status := string(c.Status)
		if c.Proxy {
			status += " (stock driver only)"
		}
		w("| %s | %s | %s | %s |", c.Need, strings.ReplaceAll(c.File, "|", " or "), status, c.Where)
	}
	w("\n`loader`: exposed by the loader's flat link tree. `outside`: in the package, but not in an `image/` or `firmware/` directory of a partition the loader walks, so a firmware package must ship it. `absent`: not in the package at all.")
	w("\nThis is about file *names*. The loader links them flat (plus `venus`, `qca/` and `fsg/`, and a prefix directory for each `firmware-name` in the running device tree), so a driver that asks for `qcom/<name>` or a path the port's DTS chooses still needs that path to resolve; the table cannot see the port's requests.")
	return b.String()
}
