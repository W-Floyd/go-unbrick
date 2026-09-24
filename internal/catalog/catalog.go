// Package catalog models the devices that drive blankflash extrapolation, as one
// flat master list (loaded from version-controlled YAML). Each device carries its
// vendor and cpu_name; the binary blankflashes and firmware it references live in
// the gitignored library, never here.
//
// The loader-signing family is (vendor OEM_ID, JTAG_ID): the Firehose loader is
// signed against the fused HW_ID the PBL enforces, so JTAG_ID — not the qboot
// cpu_name label — decides which devices can authenticate it (see Family). A
// device records its jtag_id(s) to key loaders exactly; cpu_name remains the
// fallback bridge and a human-facing grouping.
package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	yaml "go.yaml.in/yaml/v4"

	"go-unbrick/internal/bloat"
	"go-unbrick/internal/distro"
	"go-unbrick/internal/harvest"
	"go-unbrick/internal/provision"
)

type Device struct {
	Codename string   `yaml:"codename"`
	Name     string   `yaml:"name"`
	Vendor   string   `yaml:"vendor"`            // OEM id, e.g. "motorola" — with cpu_name, the family key
	CPUName  string   `yaml:"cpu_name"`          // qboot loader-signing token, e.g. "SM_DIVAR"
	JTAGIDs  []string `yaml:"jtag_id,omitempty"` // known fused MSM ids; the authoritative loader key when present, since the PBL checks JTAG_ID, not cpu_name. Optional — derive falls back to the cpu_name bridge.
	SoC      string   `yaml:"soc,omitempty"`     // marketing SoC name (cosmetic, resolved from variants if omitted)
	Models   []string `yaml:"models"`            // model numbers (carrier/region variants)
	Storage  []string `yaml:"storage"`           // advisory; real storage is inferred from firmware
}

// Family keys the loader store on the silicon a signed loader authenticates
// against: (vendor OEM_ID, JTAG_ID). JTAG_ID is the MSM hardware id fused in the
// SoC and carried in the loader cert's HW_ID — the fact secboot actually checks —
// so it, not the qboot cpu_name label, decides which loaders run on a target.
// cpu_name is a many-to-many packaging label (one JTAG → several cpu_names and
// vice-versa), demoted to loader metadata. A device that records its jtag_id(s)
// resolves loaders directly and exactly (library.LoadersForJTAGs); one that does
// not falls back to the lossy cpu_name bridge (library.LoadersForCPU).
type Family struct {
	Vendor string
	JTAGID string // uppercase 8-hex MSM id, e.g. "0016F0E1"
}

func (f Family) String() string { return f.Vendor + "/" + f.JTAGID }

// CPUFamily is the human-facing (vendor, cpu_name) grouping used for display and
// sibling detection — not a loader key (see Family).
func (d *Device) CPUFamily() string { return d.Vendor + "/" + d.CPUName }

type VendorConfig struct {
	Name        string   `yaml:"name,omitempty"`
	UpstreamDir string   `yaml:"upstream_dir,omitempty"`
	Platform    string   `yaml:"platform,omitempty"`
	OEMIDs      []string `yaml:"oem_ids,omitempty"`
}

type PartitionRule struct {
	Category    string `yaml:"category"`
	Criticality string `yaml:"criticality"`
	Action      string `yaml:"action"`
	Vendor      string `yaml:"vendor"`
	Description string `yaml:"description"`
}

type catalogFile struct {
	Devices    []*Device                `yaml:"devices,omitempty"`
	Variants   map[string]string        `yaml:"variants,omitempty"`
	Aliases    map[string]string        `yaml:"aliases,omitempty"`
	Vendors    map[string]*VendorConfig `yaml:"vendors,omitempty"`
	SWIDs      map[uint64]string        `yaml:"sw_ids,omitempty"`
	EFIGUIDs   map[string]string        `yaml:"efi_guids,omitempty"`
	Partitions map[string]PartitionRule `yaml:"partitions,omitempty"`
	// Distros is how an ssh recon reads a Linux-on-phone distribution: where its
	// own device definition lives and how it is spelled. Reference data like
	// everything else here, interpreted by internal/distro.
	Distros []*distro.Distro `yaml:"distros,omitempty"`
	// Bloat is which preloaded packages a phone can lose, read by
	// `adb debloat` and interpreted by internal/bloat.
	Bloat []bloat.Rule `yaml:"bloat,omitempty"`
	// Provision are the device-setup recipes `adb provision` runs, interpreted
	// by internal/provision.
	Provision []*provision.Profile `yaml:"provision,omitempty"`
	// Harvest is where `library harvest` looks for loaders, interpreted by
	// internal/harvest.
	Harvest *harvest.Sources `yaml:"harvest,omitempty"`
	// VendorData namespaces vendor-specific reference tables (CID, carrier, OTA
	// channel) by OEM id, since these schemes are not shared across vendors — a
	// CID means nothing outside Motorola. Keyed by Driver.ID() ("motorola").
	VendorData map[string]VendorReference `yaml:"vendor_data,omitempty"`
}

// VendorReference is one vendor's reference tables (see VendorData). All fields
// are that vendor's own scheme; another vendor's block is independent.
type VendorReference struct {
	CarrierIDs map[uint64]string `yaml:"carrier_ids,omitempty"`
	// UnlockEligibleCIDs is Motorola's published allow-list; absence from it means
	// ineligible, so this is a closed world unlike carrier_ids.
	UnlockEligibleCIDs []uint64 `yaml:"unlock_eligible_cids,omitempty"`
	// CIDReference is a vendor-claimed CID→meaning map (a forum post), kept apart
	// from the package-attested carrier_ids.
	CIDReference map[uint64]string `yaml:"cid_reference,omitempty"`
	// SoftwareChannels maps an OTA channel code (RETUS, VZW, …) to carrier + region.
	SoftwareChannels map[string]string `yaml:"software_channels,omitempty"`
}

type Catalog struct {
	devices    []*Device
	byCode     map[string]*Device
	variants   map[string]string
	aliases    map[string]string
	vendors    map[string]*VendorConfig
	swIDs      map[uint64]string
	efiGUIDs   map[string]string
	partitions map[string]PartitionRule
	distros    []*distro.Distro          // Linux-on-phone distribution profiles
	bloat      []bloat.Rule              // removable-preload rules
	provision  []*provision.Profile      // device-setup recipes
	harvest    harvest.Sources           // loader harvest sources
	vendorRef  map[string]*vendorRefData // per-vendor CID/carrier/channel tables
}

// Harvest returns the loader sources the catalog declares.
func (c *Catalog) Harvest() harvest.Sources {
	if c == nil {
		return harvest.Sources{}
	}
	return c.harvest
}

// Provision returns the device-setup recipes the catalog declares.
func (c *Catalog) Provision() []*provision.Profile {
	if c == nil {
		return nil
	}
	return c.provision
}

// Bloat returns the removable-preload rules the catalog declares, for
// internal/bloat to merge with the protections it holds in code.
func (c *Catalog) Bloat() []bloat.Rule {
	if c == nil {
		return nil
	}
	return c.bloat
}

// Distros returns the distribution profiles the catalog declares, for
// internal/distro to merge with the built-in and code-backed ones.
func (c *Catalog) Distros() []*distro.Distro {
	if c == nil {
		return nil
	}
	return c.distros
}

// vendorRefData is one vendor's resolved reference tables (see VendorData).
type vendorRefData struct {
	carrierIDs   map[uint64]string
	cidReference map[uint64]string // forum-sourced hints
	swChannels   map[string]string // OTA channel code (uppercased) → carrier/region
	unlockCIDs   map[uint64]bool
	hasUnlockCn  bool // an allow-list was loaded, so "absent" means ineligible
}

func newVendorRefData() *vendorRefData {
	return &vendorRefData{
		carrierIDs:   map[uint64]string{},
		cidReference: map[uint64]string{},
		swChannels:   map[string]string{},
		unlockCIDs:   map[uint64]bool{},
	}
}

// Load reads every *.yaml under dir as a device list and merges them.
func Load(dir string) (*Catalog, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	c := &Catalog{
		byCode:     map[string]*Device{},
		variants:   map[string]string{},
		aliases:    map[string]string{},
		vendors:    map[string]*VendorConfig{},
		swIDs:      map[uint64]string{},
		efiGUIDs:   map[string]string{},
		partitions: map[string]PartitionRule{},
		vendorRef:  map[string]*vendorRefData{},
	}

	type fileItem struct {
		filename string
		cf       catalogFile
	}
	var items []fileItem

	// Pass 1: Decode all YAML files and populate global variants, aliases, vendors
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
		items = append(items, fileItem{filename: filepath.Base(f), cf: cf})

		for k, v := range cf.Variants {
			kClean := strings.ToLower(strings.TrimSpace(k))
			vClean := strings.TrimSpace(v)
			if kClean != "" && vClean != "" {
				c.variants[kClean] = vClean
			}
		}
		for k, v := range cf.Aliases {
			kClean := strings.TrimSpace(k)
			vClean := strings.TrimSpace(v)
			if kClean != "" && vClean != "" {
				c.aliases[kClean] = vClean
			}
		}
		for k, v := range cf.Vendors {
			kClean := strings.ToLower(strings.TrimSpace(k))
			if kClean != "" && v != nil {
				c.vendors[kClean] = v
			}
		}
		for k, v := range cf.SWIDs {
			if vClean := strings.TrimSpace(v); vClean != "" {
				c.swIDs[k] = vClean
			}
		}
		for k, v := range cf.EFIGUIDs {
			kClean := strings.ToLower(strings.TrimSpace(k))
			vClean := strings.TrimSpace(v)
			if kClean != "" && vClean != "" {
				c.efiGUIDs[kClean] = vClean
			}
		}
		for k, v := range cf.Partitions {
			kClean := strings.ToLower(strings.TrimSpace(k))
			if kClean != "" {
				c.partitions[kClean] = v
			}
		}
		for _, d := range cf.Distros {
			if d != nil && d.Ident != "" {
				c.distros = append(c.distros, d)
			}
		}
		for _, b := range cf.Bloat {
			if b.Name != "" || b.Prefix != "" {
				c.bloat = append(c.bloat, b)
			}
		}
		for _, p := range cf.Provision {
			if p != nil && p.ID != "" {
				c.provision = append(c.provision, p)
			}
		}
		if cf.Harvest != nil {
			c.harvest.Merge(*cf.Harvest)
		}
		for vendorID, ref := range cf.VendorData {
			vClean := strings.ToLower(strings.TrimSpace(vendorID))
			if vClean == "" {
				continue
			}
			vr := c.vendorRef[vClean]
			if vr == nil {
				vr = newVendorRefData()
				c.vendorRef[vClean] = vr
			}
			for k, v := range ref.CarrierIDs {
				if s := strings.TrimSpace(v); s != "" {
					vr.carrierIDs[k] = s
				}
			}
			for k, v := range ref.CIDReference {
				if s := strings.TrimSpace(v); s != "" {
					vr.cidReference[k] = s
				}
			}
			for k, v := range ref.SoftwareChannels {
				kClean := strings.ToUpper(strings.TrimSpace(k))
				if s := strings.TrimSpace(v); kClean != "" && s != "" {
					vr.swChannels[kClean] = s
				}
			}
			if len(ref.UnlockEligibleCIDs) > 0 {
				vr.hasUnlockCn = true
				for _, cid := range ref.UnlockEligibleCIDs {
					vr.unlockCIDs[cid] = true
				}
			}
		}
	}

	// Pass 2: Process all devices and resolve missing SoC names from variants
	for _, item := range items {
		for _, d := range item.cf.Devices {
			if d.Codename == "" {
				return nil, fmt.Errorf("%s: device missing codename", item.filename)
			}
			if d.Vendor == "" || d.CPUName == "" {
				return nil, fmt.Errorf("%s: %q missing vendor or cpu_name", item.filename, d.Codename)
			}
			for i, j := range d.JTAGIDs {
				j = strings.ToUpper(strings.TrimSpace(j))
				if len(j) != 8 || strings.TrimLeft(j, "0123456789ABCDEF") != "" {
					return nil, fmt.Errorf("%s: %q jtag_id %q is not 8 hex digits", item.filename, d.Codename, d.JTAGIDs[i])
				}
				d.JTAGIDs[i] = j
			}
			// Auto-resolve SoC from variants if not explicitly given in YAML
			if d.SoC == "" {
				d.SoC = c.ResolveVariant(d.CPUName, "")
			}
			if prev, dup := c.byCode[d.Codename]; dup {
				return nil, fmt.Errorf("%s: duplicate codename %q (also vendor %s)", item.filename, d.Codename, prev.Vendor)
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
// its marketing SoC name if any device carries one or if resolved from variants.
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
	if !found {
		return "", false
	}
	if soc == "" {
		soc = c.ResolveVariant(cpu, "")
	}
	return soc, true
}

// DeviceByJTAG returns the first catalog device matching the given 8-character JTAG ID.
func (c *Catalog) DeviceByJTAG(jtag string) (*Device, bool) {
	if c == nil {
		return nil, false
	}
	jtag = strings.ToUpper(strings.TrimSpace(jtag))
	if len(jtag) != 8 || jtag == "00000000" {
		return nil, false
	}
	for _, d := range c.devices {
		for _, j := range d.JTAGIDs {
			if j == jtag {
				return d, true
			}
		}
	}
	return nil, false
}

// SoCByJTAG returns the commercial SoC name for a JTAG ID if any catalog device matches.
func (c *Catalog) SoCByJTAG(jtag string) (string, bool) {
	d, ok := c.DeviceByJTAG(jtag)
	if !ok {
		return "", false
	}
	if d.SoC != "" {
		return d.SoC, true
	}
	if soc := c.ResolveVariant(d.CPUName, ""); soc != "" {
		return soc, true
	}
	return "", false
}

// AddVariant registers or updates an in-memory variant mapping.
func (c *Catalog) AddVariant(token, soc string) {
	if c == nil {
		return
	}
	tClean := strings.ToLower(strings.TrimSpace(token))
	sClean := strings.TrimSpace(soc)
	if tClean != "" && sClean != "" {
		c.variants[tClean] = sClean
	}
}

// Variants returns a copy of all loaded variant-to-SoC mappings.
func (c *Catalog) Variants() map[string]string {
	if c == nil {
		return nil
	}
	out := make(map[string]string, len(c.variants))
	for k, v := range c.variants {
		out[k] = v
	}
	return out
}

// ResolveVariant matches an image variant string or Qualcomm build version string
// against known SoC platform tokens in the catalog.
func (c *Catalog) ResolveVariant(variant, qcVersion string) string {
	if c == nil || len(c.variants) == 0 {
		return ""
	}

	// Sort keys by length descending to match most specific tokens first
	keys := make([]string, 0, len(c.variants))
	for k := range c.variants {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	vLower := strings.ToLower(variant)
	if vLower != "" {
		// Pass 1: exact match or substring with full key
		for _, k := range keys {
			if strings.HasPrefix(vLower, k) || strings.Contains(vLower, k) {
				return c.variants[k]
			}
		}
		// Pass 2: match core token without "soc" prefix (e.g. "socdivar" -> "divar" matches "sm_divar")
		for _, k := range keys {
			core := strings.TrimPrefix(k, "soc")
			if len(core) >= 4 && (strings.Contains(vLower, core) || strings.HasPrefix(vLower, core)) {
				return c.variants[k]
			}
		}
	}

	qUpper := strings.ToUpper(qcVersion)
	if qUpper != "" {
		// First pass: exact token in QCVersion (e.g. SDM7150, MSM8998)
		for _, k := range keys {
			if strings.Contains(qUpper, strings.ToUpper(k)) {
				return c.variants[k]
			}
		}
		// Second pass: core token without "soc" prefix (e.g. "sockailua" -> "KAILUA")
		for _, k := range keys {
			core := strings.TrimPrefix(k, "soc")
			if len(core) >= 4 && strings.Contains(qUpper, strings.ToUpper(core)) {
				return c.variants[k]
			}
		}
	}

	return ""
}

// Aliases returns a copy of all loaded partition filename aliases.
func (c *Catalog) Aliases() map[string]string {
	if c == nil {
		return nil
	}
	out := make(map[string]string, len(c.aliases))
	for k, v := range c.aliases {
		out[k] = v
	}
	return out
}

// CanonicalPartition translates a partition filename into a clean partition label
// using catalog aliases and stripping firmware extensions (.img, .bin, .elf, .mbn).
func (c *Catalog) CanonicalPartition(filename string) string {
	base := filepath.Base(filename)
	if c != nil && len(c.aliases) > 0 {
		if mapped, ok := c.aliases[base]; ok {
			return mapped
		}
		if mapped, ok := c.aliases[strings.ToLower(base)]; ok {
			return mapped
		}
	}
	lower := strings.ToLower(base)
	for _, ext := range []string{".img", ".bin", ".elf", ".mbn"} {
		if strings.HasSuffix(lower, ext) {
			return strings.TrimSuffix(lower, ext)
		}
	}
	return lower
}

// Vendors returns a copy of all loaded vendor configurations.
func (c *Catalog) Vendors() map[string]*VendorConfig {
	if c == nil {
		return nil
	}
	out := make(map[string]*VendorConfig, len(c.vendors))
	for k, v := range c.vendors {
		out[k] = v
	}
	return out
}

// VendorDir returns the upstream repository directory name in bkerler/Loaders
// for vendorID, or vendorID itself as fallback.
func (c *Catalog) VendorDir(vendorID string) string {
	if c != nil {
		if vc, ok := c.vendors[vendorID]; ok && vc != nil && vc.UpstreamDir != "" {
			return vc.UpstreamDir
		}
		if vc, ok := c.vendors[strings.ToLower(vendorID)]; ok && vc != nil && vc.UpstreamDir != "" {
			return vc.UpstreamDir
		}
	}
	return vendorID
}

// SWIDName returns the descriptive firmware stage name for a Qualcomm secboot SW_ID.
func (c *Catalog) SWIDName(swid uint64) string {
	if c != nil && len(c.swIDs) > 0 {
		if name, ok := c.swIDs[swid]; ok && name != "" {
			return name
		}
		// Qualcomm SW_ID splits: bits[31:0] = stage/SW_TYPE, bits[63:32] = anti-rollback version
		stageType := uint64(uint32(swid & 0xFFFFFFFF))
		if name, ok := c.swIDs[stageType]; ok && name != "" {
			return name
		}
	}
	return ""
}

// vendorData returns a vendor's resolved reference tables, or nil. vendor is a
// Driver.ID() ("motorola"); the tables are that vendor's scheme, not shared.
func (c *Catalog) vendorData(vendor string) *vendorRefData {
	if c == nil {
		return nil
	}
	return c.vendorRef[strings.ToLower(strings.TrimSpace(vendor))]
}

// CarrierIDName names the carrier / subsidy channel a vendor's CID denotes,
// accepting the value either as fastboot reports it ("0x0032") or as firmware
// package filenames spell it ("50"). The mapping is attested only by observed
// package filenames, so most CIDs are unknown and callers show the raw value.
func (c *Catalog) CarrierIDName(vendor, cid string) string {
	vr := c.vendorData(vendor)
	if vr == nil {
		return ""
	}
	n, err := parseCID(cid)
	if err != nil {
		return ""
	}
	return vr.carrierIDs[n]
}

// CarrierIDReference names a CID from the vendor-claimed forum table, used only
// as a fallback when CarrierIDName (package-attested) has nothing.
func (c *Catalog) CarrierIDReference(vendor, cid string) string {
	vr := c.vendorData(vendor)
	if vr == nil {
		return ""
	}
	n, err := parseCID(cid)
	if err != nil {
		return ""
	}
	return vr.cidReference[n]
}

// SoftwareChannelName resolves a vendor's OTA channel code (e.g. "RETUS", any
// case) to its carrier + region, or "" if unknown.
func (c *Catalog) SoftwareChannelName(vendor, code string) string {
	vr := c.vendorData(vendor)
	if vr == nil {
		return ""
	}
	return vr.swChannels[strings.ToUpper(strings.TrimSpace(code))]
}

// UnlockEligible reports whether a vendor's unlock portal serves this CID, and
// whether an allow-list was loaded at all. The list is closed-world — Motorola
// states that any CID not on it is ineligible — so a CID the list does not carry
// is a predicted refusal rather than an unknown.
func (c *Catalog) UnlockEligible(vendor, cid string) (eligible, known bool) {
	vr := c.vendorData(vendor)
	if vr == nil || !vr.hasUnlockCn {
		return false, false
	}
	n, err := parseCID(cid)
	if err != nil {
		return false, false
	}
	return vr.unlockCIDs[n], true
}

// parseCID reads a CID in either spelling: fastboot's hex ("0x0032") or the
// decimal token a firmware filename carries ("50").
func parseCID(cid string) (uint64, error) {
	v := strings.TrimSpace(cid)
	base := 10
	if lower := strings.ToLower(v); strings.HasPrefix(lower, "0x") {
		v, base = lower[2:], 16
	}
	return strconv.ParseUint(v, base, 64)
}

// EFIGUIDName returns the human-readable name for a canonical UEFI GUID.
func (c *Catalog) EFIGUIDName(guid string) string {
	if c != nil && len(c.efiGUIDs) > 0 {
		gLower := strings.ToLower(strings.TrimSpace(guid))
		if name, ok := c.efiGUIDs[gLower]; ok && name != "" {
			return name
		}
	}
	return ""
}

// PartitionRule looks up the safeguard classification rule for a partition.
// Checks exact name first, then strips slot suffixes (_a, _b).
func (c *Catalog) PartitionRule(name string) (PartitionRule, bool) {
	if c == nil || len(c.partitions) == 0 {
		return PartitionRule{}, false
	}
	clean := strings.ToLower(strings.TrimSpace(name))
	if r, ok := c.partitions[clean]; ok {
		return r, true
	}
	base := strings.TrimSuffix(strings.TrimSuffix(clean, "_a"), "_b")
	if r, ok := c.partitions[base]; ok {
		return r, true
	}
	return PartitionRule{}, false
}

// IsProtected reports whether a partition holds unique calibration, radio NVRAM,
// or identity data that must be backed up before flashing.
func (c *Catalog) IsProtected(name string) bool {
	r, ok := c.PartitionRule(name)
	if !ok {
		return false
	}
	return r.Action == "backup_and_preserve" || r.Criticality == "irreplaceable" || r.Criticality == "important"
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
// cpu_name, then codename for a stable diff. If a device's SoC matches what is
// derived from its CPUName in the catalog, it is omitted to keep devices.yaml clean.
func Render(devs []*Device) ([]byte, error) {
	sorted := make([]*Device, len(devs))
	for i, d := range devs {
		cp := *d
		if cat, err := Default(); err == nil && cat != nil {
			if cp.SoC == cat.ResolveVariant(cp.CPUName, "") {
				cp.SoC = ""
			}
		}
		sorted[i] = &cp
	}
	sort.Slice(sorted, func(i, j int) bool { return deviceLess(sorted[i], sorted[j]) })
	return yaml.Marshal(catalogFile{Devices: sorted})
}

var (
	defaultCatalogMu sync.Mutex
	defaultCatalog   *Catalog
)

// FindCatalogDir locates the catalog directory by checking UNBRICK_CATALOG,
// "catalog", and searching upwards from the current working directory.
func FindCatalogDir() string {
	if env := os.Getenv("UNBRICK_CATALOG"); env != "" {
		if fi, err := os.Stat(env); err == nil && fi.IsDir() {
			return env
		}
	}
	if fi, err := os.Stat("catalog"); err == nil && fi.IsDir() {
		return "catalog"
	}
	dir, err := os.Getwd()
	if err == nil {
		for {
			cand := filepath.Join(dir, "catalog")
			if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
				files, _ := filepath.Glob(filepath.Join(cand, "*.yaml"))
				if len(files) > 0 {
					return cand
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "catalog"
}

// Default returns a cached Catalog instance loaded from FindCatalogDir().
func Default() (*Catalog, error) {
	defaultCatalogMu.Lock()
	defer defaultCatalogMu.Unlock()
	if defaultCatalog != nil {
		return defaultCatalog, nil
	}
	dir := FindCatalogDir()
	c, err := Load(dir)
	if err != nil {
		return nil, err
	}
	defaultCatalog = c
	return defaultCatalog, nil
}

// SetDefault sets the default catalog instance (useful for testing).
func SetDefault(c *Catalog) {
	defaultCatalogMu.Lock()
	defer defaultCatalogMu.Unlock()
	defaultCatalog = c
}

// MatchesVendor reports whether the filename matches any device, model, or brand
// token associated with vendorID in the YAML catalog.
func (c *Catalog) MatchesVendor(vendorID, filename string) bool {
	if c == nil {
		return false
	}
	base := strings.ToLower(filepath.Base(filename))
	vLower := strings.ToLower(vendorID)
	if strings.Contains(base, vLower) {
		return true
	}

	for _, d := range c.devices {
		if !strings.EqualFold(d.Vendor, vendorID) {
			continue
		}
		// Match against device codename from YAML
		if d.Codename != "" && strings.Contains(base, strings.ToLower(d.Codename)) {
			return true
		}
		// Match against device models from YAML
		for _, m := range d.Models {
			mClean := strings.TrimSpace(strings.ToLower(m))
			if mClean != "" && strings.Contains(base, mClean) {
				return true
			}
		}
		// Match against significant brand/model tokens in device Name from YAML
		if d.Name != "" {
			for _, token := range strings.FieldsFunc(d.Name, func(r rune) bool {
				return r == ' ' || r == '/' || r == '-' || r == '(' || r == ')'
			}) {
				token = strings.ToLower(strings.TrimSpace(token))
				if len(token) >= 3 && !isNumeric(token) && strings.Contains(base, token) {
					return true
				}
			}
		}
	}
	return false
}

// ModelFromFilename searches all catalog devices for any known model number appearing in filename.
func (c *Catalog) ModelFromFilename(filename string) string {
	if c == nil {
		return ""
	}
	base := strings.ToLower(filepath.Base(filename))
	for _, d := range c.devices {
		for _, m := range d.Models {
			mClean := strings.TrimSpace(m)
			if mClean != "" && strings.Contains(base, strings.ToLower(mClean)) {
				return mClean
			}
		}
	}
	return ""
}

// CodenameFromFilename searches all catalog devices for any known codename appearing in filename.
func (c *Catalog) CodenameFromFilename(filename string) string {
	if c == nil {
		return ""
	}
	base := strings.ToLower(filepath.Base(filename))
	for _, d := range c.devices {
		cClean := strings.TrimSpace(d.Codename)
		if cClean != "" && strings.Contains(base, strings.ToLower(cClean)) {
			return cClean
		}
	}
	return ""
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
