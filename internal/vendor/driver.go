// Package vendor is the seam between the vendor-agnostic core (secboot identity,
// catalog/library, family matching) and the vendor-specific recovery formats.
// Each OEM packages a blankflash/loader and flashes it differently — Motorola
// uses a SINGLE_N_LONELY singleimage driven by qboot; Samsung uses a .pit table
// with Odin or EDL Firehose XML — so those steps live behind a Driver.
package vendor

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/catalog"
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
// The vendor-agnostic blankflash.Donor / blankflash.Target / blankflash.ForgeResult types
// are reused as the currency between drivers so the core stays format-neutral.
type Driver interface {
	ID() string       // registry id / catalog vendor id, e.g. "motorola"
	Platform() string // recovery platform, e.g. PlatformQualcomm
	OEMIDs() []string // secboot OEM_ID hex values this vendor signs with (Qualcomm)
	CanIngest(path string) bool
	IngestDonor(path string) (*blankflash.Donor, error)
	HarvestStock(src TargetSource) (*blankflash.Target, error)
	Assemble(d *blankflash.Donor, t *blankflash.Target, opts AssembleOptions) (*blankflash.ForgeResult, error)
}

// StockPackager is an optional Driver capability: recognizing and harvesting an
// OEM's *stock firmware* package (the retail flashable zip), as opposed to the
// blankflash donor a plain Driver ingests. Drivers opt in; DetectStock only
// considers those that do.
type StockPackager interface {
	CanIngestStock(path string) bool
	HarvestStockPackage(path string) (*blankflash.Target, error)
}

// StockIdentifier is an optional Driver capability: naming a harvested stock
// build from the OEM's own build stamp, so the library can keep every distinct
// build of a device rather than overwriting. Each OEM stamps its images
// differently (Motorola writes an MBM signature into every boot partition), so
// this stays behind the vendor seam. Drivers that cannot name a build omit it
// and the library falls back to a content hash.
type StockIdentifier interface {
	StockBuildID(t *blankflash.Target) string
}

// StockBuildID asks a driver to name this stock build, returning "" if the
// driver offers no opinion.
func StockBuildID(d Driver, t *blankflash.Target) string {
	si, ok := d.(StockIdentifier)
	if !ok {
		return ""
	}
	return si.StockBuildID(t)
}

// EDLEntry is an optional Driver capability: the commands that put this OEM's
// bootloader into the SoC's emergency download mode. There is no common one —
// Motorola's ABL enters EDL through `oem blankflash`, other Qualcomm bootloaders
// through `oem edl` or a reboot target — and issuing another vendor's command is
// at best a wasted round trip against a bootloader that may log or refuse it.
// A driver that knows no route omits the capability, which is itself the answer:
// the device has no fastboot path into EDL.
type EDLEntry interface {
	EDLCommands() [][]string
}

// EDLCommands asks a driver how its devices reach EDL, returning nil when the
// driver offers no route.
func EDLCommands(d Driver) [][]string {
	e, ok := d.(EDLEntry)
	if !ok {
		return nil
	}
	return e.EDLCommands()
}

// StockNamer is an optional Driver capability: reading the device codename the
// OEM stamped into a harvested stock image, so an import can identify itself
// rather than relying on a filename or the operator.
type StockNamer interface {
	CodenameFromStock(t *blankflash.Target) string
}

// CodenameFromStock asks a driver to name the device a stock image belongs to,
// returning "" if it cannot.
func CodenameFromStock(d Driver, t *blankflash.Target) string {
	sn, ok := d.(StockNamer)
	if !ok {
		return ""
	}
	return sn.CodenameFromStock(t)
}

// DonorStockHarvester is an optional Driver capability: recovering the donor
// device's OWN stock boot chain from a blankflash package. A blankflash carries
// far more than the loader -- the signed boot partitions and GPT of the device
// it was built for -- so a library of donors is also a library of stock.
type DonorStockHarvester interface {
	HarvestDonorStock(path string) (*blankflash.Target, error)
}

// ExplodeOptions tunes what a stock package is unpacked into.
type ExplodeOptions struct {
	// Super also writes the Android super image, which on a modern package is
	// several gigabytes split across chunks. Off by default: it is the bulk of
	// the download and carries nothing the boot chain needs.
	Super bool
}

// StockExploder is an optional Driver capability: writing out every partition
// image a stock package carries -- both the OEM's own members and the images
// packed inside a container like Motorola's bootloader.img. It writes to a
// directory rather than returning bytes because a full package does not fit
// comfortably in memory.
type StockExploder interface {
	ExplodeStock(path, dir string, opts ExplodeOptions) ([]string, error)
}

// DetectStock returns the driver whose stock-package format matches the path.
func DetectStock(path string) (Driver, StockPackager, bool) {
	for _, id := range ids() {
		sp, ok := registry[id].(StockPackager)
		if ok && sp.CanIngestStock(path) {
			return registry[id], sp, true
		}
	}
	return nil, nil, false
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

// MatchesVendorCatalog reports whether the filename matches any device, model, or brand
// token associated with vendorID in the YAML catalog.
func MatchesVendorCatalog(vendorID, path string) bool {
	cat, err := catalog.Default()
	if err != nil || cat == nil {
		base := strings.ToLower(filepath.Base(path))
		return strings.Contains(base, strings.ToLower(vendorID))
	}
	return cat.MatchesVendor(vendorID, path)
}

