package fastboot

import (
	"strings"
	"time"
)

// Profile is a vendor's fastboot personality, stacked onto the neutral Client to
// mutate behaviour (middleware), add vendor-only recon probes, and declare which
// operations the bootloader actually supports. Every method beyond Name is an
// opt-in sub-interface (like the vendor.Driver capabilities), so a plain vendor
// implements only what it needs and the neutral core assumes nothing.
//
// The concrete profiles live in internal/vendor next to each Driver; the neutral
// core never names a vendor. A Driver hands its Profile to the Client via
// vendor.FastbootProfile.
type Profile interface {
	// Name identifies the profile, e.g. "motorola" or "generic".
	Name() string
}

// RunFunc executes one fastboot invocation with a timeout. It is the unit that
// Middleware wraps.
type RunFunc func(timeout time.Duration, args ...string) (string, error)

// Middleware decorates command execution: retries for a flaky bootloader,
// per-command timeout overrides, response normalization, error translation. A
// profile's middlewares are folded outermost-first, so the first in the slice
// runs first on the way in and last on the way out.
type Middleware func(next RunFunc) RunFunc

// MiddlewareProfile is an optional Profile capability: execution decorators
// stacked onto the Client's runner. This is the "stack vendor behaviour on the
// generic provider" seam.
type MiddlewareProfile interface {
	Middleware() []Middleware
}

// ReconProbe is one vendor-specific query run after the neutral `getvar all`.
// Run issues whatever commands it needs through the Client (so middleware and
// follow-up probes like ProbePartitions are available) and folds results into
// the DeviceRecon — typically its Extras bag, keyed by Name.
type ReconProbe struct {
	Name string
	Run  func(c *Client, serial string, r *DeviceRecon)
}

// ReconProber is an optional Profile capability: extra recon probes. The Client
// runs them in order during a full recon.
type ReconProber interface {
	ReconProbes() []ReconProbe
}

// Support states whether an operation works on this vendor's bootloader.
type Support int

const (
	// Native: the bootloader supports the operation normally.
	Native Support = iota
	// Broken: the bootloader accepts the operation but mishandles it (e.g.
	// Motorola ACKs a cid write over the lite loader but discards it), so a
	// caller should warn or verify rather than trust the ACK.
	Broken
	// Unsupported: the bootloader rejects the operation outright.
	Unsupported
)

// Op names a standard operation whose support a profile may qualify.
type Op string

const (
	OpFlash     Op = "flash"
	OpRebootEDL Op = "reboot-edl"
	OpWriteCID  Op = "write-cid"
)

// CapabilityProfile is an optional Profile capability: qualifying which standard
// operations work. A profile that does not implement it is assumed Native for
// everything.
type CapabilityProfile interface {
	Support(op Op) Support
}

// genericProfile is the neutral default: a name, no middleware, no probes, and
// Native support for everything. Used when a Driver supplies no Profile.
type genericProfile struct{}

// Generic is the vendor-neutral Profile.
var Generic Profile = genericProfile{}

func (genericProfile) Name() string { return "generic" }

// UseProfile installs a vendor Profile so subsequent Exec calls apply its
// middleware and RunProbes runs its probes. Passing nil restores Generic.
func (c *Client) UseProfile(p Profile) {
	if p == nil {
		p = Generic
	}
	c.profile = p
}

// Profile returns the installed Profile (Generic if none was set).
func (c *Client) Profile() Profile {
	if c.profile == nil {
		return Generic
	}
	return c.profile
}

// Exec runs a fastboot command for serial through the installed profile's
// middleware. It is the surface a vendor profile's probes and capabilities use.
func (c *Client) Exec(serial string, timeout time.Duration, args ...string) (string, error) {
	return c.wrapped()(timeout, appendSerial(serial, args...)...)
}

// wrapped folds the installed profile's middleware over the base runner.
func (c *Client) wrapped() RunFunc {
	run := RunFunc(c.run)
	if mp, ok := c.profile.(MiddlewareProfile); ok {
		mws := mp.Middleware()
		for i := len(mws) - 1; i >= 0; i-- {
			run = mws[i](run)
		}
	}
	return run
}

// Supports reports how the installed profile qualifies op (Native if the profile
// declares no opinion).
func (c *Client) Supports(op Op) Support {
	if cp, ok := c.profile.(CapabilityProfile); ok {
		return cp.Support(op)
	}
	return Native
}

// ReportLine is one label/value row in a recon report.
type ReportLine struct{ Label, Value string }

// ReportSection is a titled group of report lines plus free-form notes. A blank
// Title appends the lines under the caller's current heading.
type ReportSection struct {
	Title string
	Lines []ReportLine
	Notes []string
}

// ReconReporter is an optional Profile capability: rendering the vendor-specific
// parts of a recon report (its Extras) as sections, so the command layer prints
// them generically and never names a vendor.
type ReconReporter interface {
	ReconReport(r *DeviceRecon, redact bool) []ReportSection
}

// RawReporter is an optional Profile capability: the vendor-specific part of the
// `--raw` dump (e.g. an OEM command's raw bytes).
type RawReporter interface {
	RawReport(r *DeviceRecon, redact bool) []ReportSection
}

// EDLNoter is an optional Profile capability: a one-line caveat about this
// vendor's EDL entry (e.g. a factory gate the OEM lock does not lift).
type EDLNoter interface {
	EDLNote() string
}

// EDLNote returns the installed profile's EDL caveat, or "".
func (c *Client) EDLNote() string {
	if n, ok := c.profile.(EDLNoter); ok {
		return n.EDLNote()
	}
	return ""
}

// ReconSections returns the installed profile's vendor report sections, or nil.
func (c *Client) ReconSections(r *DeviceRecon, redact bool) []ReportSection {
	if rr, ok := c.profile.(ReconReporter); ok {
		return rr.ReconReport(r, redact)
	}
	return nil
}

// RawSections returns the installed profile's vendor raw-dump sections, or nil.
func (c *Client) RawSections(r *DeviceRecon, redact bool) []ReportSection {
	if rr, ok := c.profile.(RawReporter); ok {
		return rr.RawReport(r, redact)
	}
	return nil
}

// Mask redacts a per-device identifier: first four and last four characters kept,
// the middle elided; a short value is fully masked. Passthrough when redact is
// false or the string is empty. A neutral helper vendors reuse for their own
// secrets (e.g. a device digest).
func Mask(redact bool, s string) string {
	if !redact || s == "" {
		return s
	}
	if len(s) <= 8 {
		return strings.Repeat("•", len(s))
	}
	return s[:4] + "…" + s[len(s)-4:]
}

// ReconPlanner is an optional Profile capability run before the probes. It does
// the cheap up-front discovery whose result decides how many sub-steps the probes
// will add (e.g. reading the partition table to learn how many partitions the
// confirm will check), folding what it learns into r so the probes need not
// repeat it, and returns that sub-step count. Knowing it before beginProgress lets
// the bar span every step from the start instead of growing mid-run.
type ReconPlanner interface {
	PlanReconSteps(c *Client, serial string, r *DeviceRecon) int
}

// RunProbes runs the installed profile's recon probes, folding each into r.
func (c *Client) RunProbes(serial string, r *DeviceRecon) {
	pr, ok := c.profile.(ReconProber)
	if !ok || r == nil {
		return
	}
	probes := pr.ReconProbes()
	extra := 0
	if planner, ok := c.profile.(ReconPlanner); ok {
		extra = planner.PlanReconSteps(c, serial, r)
	}
	c.beginProgress(len(probes) + extra)
	for _, probe := range probes {
		c.describeStep("querying " + probe.Name)
		probe.Run(c, serial, r)
		c.advanceStep()
	}
}
