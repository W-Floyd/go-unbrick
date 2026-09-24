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

	"github.com/spf13/cobra"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/catalog"
	"go-unbrick/internal/facts"
	"go-unbrick/internal/fastboot"
	"go-unbrick/internal/library"
	"go-unbrick/internal/unlock"
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

// UnlockSource is an OEM bootloader-unlock input: the get_unlock_data challenge
// string, a raw unlock-record blob (e.g. dumped from the cid partition), or both.
type UnlockSource struct {
	Text string // vendor challenge / wire string
	Blob []byte // raw unlock record
}

// UnlockVerifier is an optional Driver capability: parsing this OEM's unlock
// record into an unlock.Record. Each OEM stores and checks the bootloader-unlock
// code differently (Motorola's DBVAL is a salted double-hash in the cid
// partition; another OEM may use an entirely different construction), so it lives
// behind the vendor seam. This single parser is all a vendor implements — the
// returned Record carries its own verify closure. It only *verifies* a
// vendor-issued code, never derives one.
type UnlockVerifier interface {
	ParseUnlock(src UnlockSource) (*unlock.Record, error)
}

// ParseUnlock tries each registered driver that verifies unlock codes and returns
// the first Record one recognizes, or ErrUnsupported if no vendor claims it.
func ParseUnlock(src UnlockSource) (*unlock.Record, error) {
	var firstErr error
	for _, d := range registry {
		uv, ok := d.(UnlockVerifier)
		if !ok {
			continue
		}
		c, err := uv.ParseUnlock(src)
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, ErrUnsupported
}

// FastbootProfiler is an optional Driver capability: this OEM's fastboot
// personality (middleware, recon probes, capability qualifiers) stacked onto the
// neutral fastboot.Client. Drivers that add nothing omit it and get Generic.
type FastbootProfiler interface {
	FastbootProfile() fastboot.Profile
}

// FastbootProfile returns d's fastboot Profile, or fastboot.Generic if the
// driver declares none.
func FastbootProfile(d Driver) fastboot.Profile {
	if fp, ok := d.(FastbootProfiler); ok {
		return fp.FastbootProfile()
	}
	return fastboot.Generic
}

// UnlockDataProvider is a fastboot Profile capability (asserted from a resolved
// profile): querying the OEM's get_unlock_data token over fastboot, plus the
// vendor's unlock portal and an eligibility outlook for a device's CID.
type UnlockDataProvider interface {
	GetUnlockData(c *fastboot.Client, serial string) (string, error)
	// UnlockPortal is the URL where the token is redeemed.
	UnlockPortal() string
	// UnlockOutlook predicts whether the portal will honour this device's CID,
	// from the catalog allow-list and any harvested subsidy lock. "" if unknown.
	UnlockOutlook(r *fastboot.DeviceRecon, cat *catalog.Catalog, lib *library.Library) string
}

// FastbootEnv is the bundle of command-layer services a vendor's contributed
// fastboot command needs. The command layer implements it; a vendor command uses
// it instead of importing the main package (which would be a cycle). It is passed
// explicitly rather than smuggled through a context so each command's needs stay
// visible and type-checked.
type FastbootEnv interface {
	Client() (*fastboot.Client, error)
	// ResolveSerial picks the device to act on (the one asked for, or the only one).
	ResolveSerial(c *fastboot.Client) (string, error)
	// RequireBootloader errors if the command's OEM verbs aren't served here
	// (e.g. the device is in userspace fastbootd).
	RequireBootloader(c *fastboot.Client, serial, what string) error
	// InstallProfile resolves and installs the device's vendor profile, returning
	// it for capability assertions.
	InstallProfile(c *fastboot.Client, serial string) fastboot.Profile
	Catalog() *catalog.Catalog
	Library() *library.Library
}

// FastbootCommander is an optional Driver capability: extra fastboot subcommands
// this vendor contributes, stacked onto the neutral fastboot command tree. This
// is the command-level analogue of FastbootProfiler — a vendor adds its own
// commands the same way it adds probes and middleware.
type FastbootCommander interface {
	FastbootCommands(env FastbootEnv) []*cobra.Command
}

// FastbootCommands gathers the contributed commands from every registered driver,
// skipping any whose name is already taken (neutral commands win). taken is
// updated with the names that were added.
func FastbootCommands(env FastbootEnv, taken map[string]bool) []*cobra.Command {
	var out []*cobra.Command
	for _, d := range Drivers() {
		fc, ok := d.(FastbootCommander)
		if !ok {
			continue
		}
		for _, c := range fc.FastbootCommands(env) {
			if taken[c.Name()] {
				continue
			}
			taken[c.Name()] = true
			out = append(out, c)
		}
	}
	return out
}

// PartitionHasher is a fastboot Profile capability: hashing a partition in place
// via the OEM's bootloader command.
type PartitionHasher interface {
	OEMPartitionHash(c *fastboot.Client, serial, algo, partition, offset, size string) (*PartitionDigest, error)
}

// PartitionLister is a fastboot Profile capability: reading live partition
// geometry via the OEM's bootloader command.
type PartitionLister interface {
	OEMPartitions(c *fastboot.Client, serial string) ([]PartitionDetail, bool, []string, error)
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

// FactDeriver is an optional Driver capability: the derivations this OEM knows
// — which fact it can produce from which source, at what cost and authority.
// It is how vendor knowledge reaches the neutral planner without the planner
// learning any of it.
type FactDeriver interface {
	FactProviders() []facts.Provider
}

// FactChecker is an optional Driver capability: this OEM's cross-fact
// invariants (an unlock salt that must equal the device UID, a signing CID that
// must match its customer region). Same-fact disagreement needs no vendor code
// — the planner finds it — so only relationships *between* facts belong here.
type FactChecker interface {
	FactChecks() []facts.Check
}

// FactRecognizer is an optional Driver capability: telling this OEM's own
// formats apart by their content, so ingesting a package is a matter of asking
// each member what it is rather than asking the package for names we guessed.
type FactRecognizer interface {
	FactRecognizers() []facts.Recognizer
}

// Recognizers gathers every registered driver's format recognizers.
func Recognizers() []facts.Recognizer {
	var out []facts.Recognizer
	for _, d := range Drivers() {
		if fr, ok := d.(FactRecognizer); ok {
			out = append(out, fr.FactRecognizers()...)
		}
	}
	return out
}

// Providers gathers every registered driver's derivations.
func Providers() []facts.Provider {
	var out []facts.Provider
	for _, d := range Drivers() {
		if fd, ok := d.(FactDeriver); ok {
			out = append(out, fd.FactProviders()...)
		}
	}
	return out
}

// Checks gathers every registered driver's cross-fact invariants.
func Checks() []facts.Check {
	var out []facts.Check
	for _, d := range Drivers() {
		if fc, ok := d.(FactChecker); ok {
			out = append(out, fc.FactChecks()...)
		}
	}
	return out
}

// FactGraph is the derivation graph of everything the registered vendors know.
func FactGraph() *facts.Graph { return facts.New(Providers(), Checks()) }

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

// Drivers returns every registered driver, ordered by id for determinism.
func Drivers() []Driver {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Driver, 0, len(ids))
	for _, id := range ids {
		out = append(out, registry[id])
	}
	return out
}

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
