package linuxdev

// The ssh route as a recon transport: one connection, one collection, and the
// partition bytes on request.

import (
	"go-unbrick/internal/facts"
	"go-unbrick/internal/transport"
)

// Device is a phone booted into a Linux distribution, reached over ssh. It
// implements transport.Transport, plus both partition capabilities — listing,
// because the running kernel knows the whole table, and reading, because with
// root it will hand any of it over.
type Device struct {
	C *Client
	R *Recon
	// collectErr is what would not read during collection. Surfaced as a
	// finding by Sources rather than failing the recon: a section that a
	// hardened install refuses is a gap in the report, not the end of it.
	collectErr error
}

var (
	_ transport.Transport       = (*Device)(nil)
	_ transport.PartitionLister = (*Device)(nil)
	_ transport.PartitionReader = (*Device)(nil)
)

// Open connects to target and collects. The connection stays up for whatever
// the recon asks next; Close drops it.
func Open(target string, o Options) (*Device, error) {
	c, err := NewClient(target, o)
	if err != nil {
		return nil, err
	}
	r, cerr := Collect(c)
	if r == nil {
		_ = c.Close()
		return nil, cerr
	}
	return &Device{C: c, R: r, collectErr: cerr}, nil
}

func (d *Device) Name() string { return transport.SSH }

func (d *Device) Describe() string {
	if os := d.R.OS.Describe(); os != "" {
		return "ssh " + d.R.Target + " (" + os + ")"
	}
	return "ssh " + d.R.Target
}

func (d *Device) Close() error { return d.C.Close() }

// Sources puts the collected recon in the Bag. It is the one source this route
// yields; everything the report shows about the device is derived from it by
// the graph, including by the vendor rules, which is why the struct goes in
// whole rather than pre-digested.
func (d *Device) Sources(b *facts.Bag) []facts.Finding {
	facts.Set(b, SourceLinux, d.R,
		facts.Provenance{Source: "ssh " + d.R.Target, Authority: facts.Attested})
	if d.collectErr != nil {
		return []facts.Finding{transport.Gap("collecting over ssh", d.collectErr)}
	}
	return nil
}

// Partitions is the live table as the running kernel presents it — the same
// table a GPT traversal recovers, read without EDL and without trusting a
// package's manifest for it.
func (d *Device) Partitions() []transport.Partition { return d.R.Partitions }

// Slot is the booted A/B slot.
func (d *Device) Slot() string { return d.R.Slot() }

func (d *Device) ReadPartition(p transport.Partition, budget uint64) ([]byte, error) {
	return ReadPartition(d.C, p, budget)
}

// ReadCost prices one read on the fact graph's scale (a local parse is 1, a
// paced getvar 100): a dd over a phone's USB-ethernet link is a real transfer
// but an unremarkable one, and cheaper per byte than anything EDL does.
func (d *Device) ReadCost() int { return 50 }

// PrepareReads settles and proves elevation, so a run does not discover per
// partition that it cannot read any of them.
func (d *Device) PrepareReads() error { return PrepareElevation(d.C, d.R) }

// DeviceSerial is androidboot.serialno from the kernel cmdline, when the
// bootloader passed it through; used only to recognise the same physical device
// across a session's routes.
func (d *Device) DeviceSerials() []string {
	return transport.NonEmpty(d.R.Serial(), d.R.StorSerial)
}
