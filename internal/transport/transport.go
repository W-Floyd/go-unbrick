// Package transport is the seam between a recon and the route it reached the
// device by. A bootloader in fastboot mode, a booted Linux distribution over
// ssh, an Android userspace over adb and an EDL programmer are four different
// conversations with one phone; what each can be *asked* differs, but what is
// done with the answers does not.
//
// So a transport's whole obligation is to put what the device said into the
// Bag as source facts. Everything after that — the derivations, the
// cross-checks, the report — is the fact graph's, and is written once.
//
// Capabilities are opt-in sub-interfaces, the way vendor.Driver and
// fastboot.Profile do it: a transport implements only what its route can
// honestly do, and the command layer asks with a type assertion rather than
// assuming. A bootloader will describe a partition but never hand it over; a
// root shell hands over the bytes; EDL hands over the bytes of a device that
// cannot boot at all. None of them has to pretend to be the others.
package transport

import (
	"fmt"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// The routes. A transport's name is what a report calls it and what a --via
// flag selects.
//
// File is deliberately one of them. A firmware package is not a device, but the
// seam's whole obligation is "put what this thing says into the Bag as source
// facts", and that is exactly what ingesting a package does — which is why a
// package fact and a device fact can already meet in one Bag. Naming it a
// transport is what lets one command hold both: read the device by one route,
// the firmware it should be running by another, and let the cross-checks fall
// out of the graph instead of a special case.
//
// Odin (Samsung download mode, as Heimdall speaks it) belongs on this list and
// is not implemented: it is a different protocol again, with a .pit table where
// Qualcomm has a GPT, and it reads partitions on devices that have no other
// route in. The seam is shaped to take it — a Transport with a PartitionLister
// over the .pit and a PartitionReader over Heimdall's dump verb.
const (
	Fastboot = "fastboot" // the bootloader's own protocol
	SSH      = "ssh"      // a booted Linux distribution (postmarketOS, Mobian, …)
	ADB      = "adb"      // a booted Android userspace
	EDL      = "edl"      // Qualcomm emergency download / Firehose
	File     = "file"     // a firmware package, image or dump on disk
	Odin     = "odin"     // Samsung download mode (Heimdall) — not implemented
)

// Transport is one route to a device.
type Transport interface {
	// Name is the route, one of the constants above.
	Name() string
	// Describe names this device as reached: "ssh user@fogona (postmarketOS edge)".
	Describe() string
	// Sources collects what the device says about itself into the Bag as source
	// facts. Findings, not an error, for what went wrong on the way: a section
	// of a collection that would not read is a gap in the report, not a failed
	// recon, and the caller prints it beside everything that did work.
	Sources(b *facts.Bag) []facts.Finding
	// Close releases the connection, the control socket, the loader session.
	Close() error
}

// PartitionLister is the optional capability of knowing the device's partition
// table. What the entries carry varies by route — a bootloader gives names and
// sizes, a booted kernel gives device nodes too — so Partition holds the union
// and a reader is what makes sense of its Handle.
type PartitionLister interface {
	Partitions() []Partition
	// Slot is the booted A/B slot ("a", "b", or ""), which decides which copy of
	// a slotted partition is the running one.
	Slot() string
}

// PartitionReader is the optional capability of handing over a partition's
// bytes. This is the capability that separates the routes: `fastboot` has no
// read verb at all, a booted userspace has one for anything root can open, and
// EDL has one for a device with no working software on it.
type PartitionReader interface {
	// ReadPartition returns the whole partition, as selected by a Partition the
	// same transport listed. budget bounds the transfer: it is the partition's
	// own size where the device reported one, and the recon's read cap where it
	// did not — an unrooted adb shell cannot read /sys/class/block at all, and a
	// bounded read of an unknown-size partition is better than no read, as long
	// as one that hits the bound is reported as the fragment it is.
	ReadPartition(p Partition, budget uint64) ([]byte, error)
	// ReadCost is what one read costs relative to the fact graph's scale (a
	// local parse is 1): it is what makes a report say whether reading is cheap
	// enough to do by default. A root shell over USB ethernet is fast; the same
	// read over Firehose is not.
	ReadCost() int
}

// Partition is one entry of a device's partition table, however the transport
// learned it.
type Partition struct {
	Name      string // label as the table spells it, e.g. "xbl_a"
	SizeBytes uint64
	// Handle is how this transport addresses the partition — a device node
	// (/dev/block/sde11), a LUN and sector range, or nothing where the name is
	// the address. Opaque to everyone but the transport that produced it.
	Handle string
}

// Base is the partition name with its A/B suffix removed.
func (p Partition) Base() string {
	for _, suf := range []string{"_a", "_b"} {
		if strings.HasSuffix(p.Name, suf) {
			return strings.TrimSuffix(p.Name, suf)
		}
	}
	return p.Name
}

// Slot is the A/B slot a partition belongs to, empty for a slotless one.
func (p Partition) Slot() string {
	switch {
	case strings.HasSuffix(p.Name, "_a"):
		return "a"
	case strings.HasSuffix(p.Name, "_b"):
		return "b"
	}
	return ""
}

// Disk is one whole block device (an internal UFS LUN or eMMC, an SD card).
type Disk struct {
	Name      string
	SizeBytes uint64
}

// Finding is the shorthand a transport uses for what went wrong while
// collecting: a gap, not a failure.
func Gap(what string, err error) facts.Finding {
	return facts.Finding{Severity: facts.Warn, Message: fmt.Sprintf("%s: %v", what, err)}
}

// NonEmpty returns the non-empty strings among its arguments, in order.
func NonEmpty(vals ...string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
