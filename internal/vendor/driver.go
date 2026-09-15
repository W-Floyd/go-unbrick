// Package vendor is the seam between the vendor-agnostic core (secboot identity,
// catalog/library, family matching) and the vendor-specific recovery formats.
// Each OEM packages a blankflash/loader and flashes it differently — Motorola
// uses a SINGLE_N_LONELY singleimage driven by qboot; Samsung uses a .pit table
// with Odin or EDL Firehose XML — so those steps live behind a Driver.
package vendor

import (
	"fmt"
	"sort"

	"blankflash-forge/internal/bfforge"
)

// ErrUnsupported marks a vendor operation that is recognized but not implemented.
var ErrUnsupported = fmt.Errorf("not yet implemented for this vendor")

// TargetSource points at the raw inputs for harvesting a device's own stock.
type TargetSource struct {
	Parts      string // dir of raw per-partition dumps
	Bootloader string // packed bootloader image
	GPT        string // partition table file
	Slot       string
}

// AssembleOptions carries the knobs for building the flashable package.
type AssembleOptions struct {
	Slot      string
	Storage   string
	Provision []byte
}

// Recovery platforms — the SoC-level flashing mechanism, orthogonal to OEM.
// One OEM can ship devices on more than one (Motorola has both Qualcomm and
// MediaTek phones), so a driver carries a platform tag as well as a vendor id.
const (
	PlatformQualcomm = "qualcomm" // EDL 9008 / Sahara / Firehose programmer
	PlatformMediaTek = "mediatek" // BROM / Download Agent / SP Flash Tool scatter
)

// Driver implements one recovery-package format, identified by (platform, vendor).
// The vendor-agnostic bfforge.Donor / bfforge.Target / bfforge.ForgeResult types
// are reused as the currency between drivers so the core stays format-neutral.
type Driver interface {
	ID() string       // registry id / catalog vendor id, e.g. "motorola"
	Platform() string // recovery platform, e.g. PlatformQualcomm
	OEMIDs() []string // secboot OEM_ID hex values this vendor signs with (Qualcomm)
	CanIngest(path string) bool
	IngestDonor(path string) (*bfforge.Donor, error)
	HarvestStock(src TargetSource) (*bfforge.Target, error)
	Assemble(d *bfforge.Donor, t *bfforge.Target, opts AssembleOptions) (*bfforge.ForgeResult, error)
}

var registry = map[string]Driver{}

// Register adds a driver; called from driver init functions.
func Register(d Driver) { registry[d.ID()] = d }

// For returns the driver for a catalog vendor id.
func For(id string) (Driver, bool) {
	d, ok := registry[id]
	return d, ok
}

// ForOEMID returns the driver that signs with a given secboot OEM_ID.
func ForOEMID(oem string) (Driver, bool) {
	for _, d := range registry {
		for _, o := range d.OEMIDs() {
			if o == oem {
				return d, true
			}
		}
	}
	return nil, false
}

// Detect returns the driver whose package format matches the path.
func Detect(path string) (Driver, bool) {
	for _, id := range ids() {
		if d := registry[id]; d.CanIngest(path) {
			return d, true
		}
	}
	return nil, false
}

func ids() []string {
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
