// Package catalog models the devices that drive blankflash extrapolation, as one
// flat master list (loaded from version-controlled YAML). Each device carries its
// vendor and cpu_name; the binary blankflashes and firmware it references live in
// the gitignored library, never here.
//
// The loader-signing family is (vendor, cpu_name): the Firehose loader is signed
// per SoC + OEM key, so every device sharing a vendor and a cpu_name token can
// authenticate the same loader. That pair is the unit of extrapolation.
package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v4"
)

type Device struct {
	Codename string   `yaml:"codename"`
	Name     string   `yaml:"name"`
	Vendor   string   `yaml:"vendor"`   // OEM id, e.g. "motorola" — with cpu_name, the family key
	CPUName  string   `yaml:"cpu_name"` // qboot loader-signing token, e.g. "SM_DIVAR"
	SoC      string   `yaml:"soc"`      // marketing SoC name (cosmetic, may be empty)
	Models   []string `yaml:"models"`   // model numbers (carrier/region variants)
	Storage  []string `yaml:"storage"`  // advisory; real storage is inferred from firmware
}

// Family keys the loader store on the silicon a signed loader authenticates
// against: (vendor OEM_ID, JTAG_ID). JTAG_ID is the MSM hardware id fused in the
// SoC and carried in the loader cert's HW_ID — the fact secboot actually checks —
// so it, not the qboot cpu_name label, decides which loaders run on a target.
// cpu_name is a many-to-many packaging label (one JTAG → several cpu_names and
// vice-versa), demoted to loader metadata; the device↔loader bridge is resolved
// via loaders that carry both (see library.LoadersForCPU).
type Family struct {
	Vendor string
	JTAGID string // uppercase 8-hex MSM id, e.g. "0016F0E1"
}

func (f Family) String() string { return f.Vendor + "/" + f.JTAGID }

// CPUFamily is the human-facing (vendor, cpu_name) grouping used for display and
// sibling detection — not a loader key (see Family).
func (d *Device) CPUFamily() string { return d.Vendor + "/" + d.CPUName }

type catalogFile struct {
	Devices []*Device `yaml:"devices"`
}

type Catalog struct {
	devices []*Device
	byCode  map[string]*Device
}

// Load reads every *.yaml under dir as a device list and merges them.
func Load(dir string) (*Catalog, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	c := &Catalog{byCode: map[string]*Device{}}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var cf catalogFile
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&cf); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		for _, d := range cf.Devices {
			if d.Codename == "" {
				return nil, fmt.Errorf("%s: device missing codename", filepath.Base(f))
			}
			if d.Vendor == "" || d.CPUName == "" {
				return nil, fmt.Errorf("%s: %q missing vendor or cpu_name", filepath.Base(f), d.Codename)
			}
			if prev, dup := c.byCode[d.Codename]; dup {
				return nil, fmt.Errorf("%s: duplicate codename %q (also vendor %s)", filepath.Base(f), d.Codename, prev.Vendor)
			}
			c.byCode[d.Codename] = d
			c.devices = append(c.devices, d)
		}
	}
	return c, nil
}

// Device returns the device for a codename.
func (c *Catalog) Device(codename string) (*Device, bool) {
	d, ok := c.byCode[codename]
	return d, ok
}

// Siblings returns every device in the same family as the codename, excluding it
// — the candidate donors for extrapolating its blankflash.
func (c *Catalog) Siblings(codename string) ([]*Device, bool) {
	d, ok := c.byCode[codename]
	if !ok {
		return nil, false
	}
	var out []*Device
	for _, o := range c.devices {
		if o != d && o.Vendor == d.Vendor && o.CPUName == d.CPUName {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Codename < out[j].Codename })
	return out, true
}

// SoCByCPUName reports whether a (vendor, cpu_name) family is in the catalog, and
// its marketing SoC name if any device carries one.
func (c *Catalog) SoCByCPUName(vendor, cpu string) (string, bool) {
	soc, found := "", false
	for _, d := range c.devices {
		if d.Vendor == vendor && d.CPUName == cpu {
			found = true
			if d.SoC != "" && soc == "" {
				soc = d.SoC
			}
		}
	}
	return soc, found
}

// AllDevices returns every device in canonical order (see deviceLess).
func (c *Catalog) AllDevices() []*Device {
	out := append([]*Device{}, c.devices...)
	sort.Slice(out, func(i, j int) bool { return deviceLess(out[i], out[j]) })
	return out
}

// deviceLess is the canonical device ordering: vendor, then cpu_name (the always-
// present signing-family key; soc is derived from it and often blank), then
// codename. Used for both listing and saving so the file diff stays stable.
func deviceLess(a, b *Device) bool {
	if a.Vendor != b.Vendor {
		return a.Vendor < b.Vendor
	}
	if a.CPUName != b.CPUName {
		return a.CPUName < b.CPUName
	}
	return a.Codename < b.Codename
}

// Render marshals devices to canonical block-style YAML, sorted by vendor,
// cpu_name, then codename for a stable diff.
func Render(devs []*Device) ([]byte, error) {
	sorted := append([]*Device{}, devs...)
	sort.Slice(sorted, func(i, j int) bool { return deviceLess(sorted[i], sorted[j]) })
	return yaml.Marshal(catalogFile{Devices: sorted})
}
