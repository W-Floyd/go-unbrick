package linuxdev

// Reading partition bytes off a booted device. This is what an ssh recon can do
// that no fastboot recon can: on a locked device the bootloader will answer
// questions about a partition but never hand it over, and getting at the bytes
// otherwise means EDL. A root shell on the phone reads them straight out of
// /dev/block/by-name, and the transport seam's own recon rules take it from
// there — which partitions are worth reading, and what their content means, are
// not this route's business.

import (
	"fmt"
	"strings"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/transport"
)

// ReadTimeout is the budget for one partition read. Generous: the transfer is
// bounded by the phone's link, which is neither fast nor predictable.
const ReadTimeout = 5 * time.Minute

// ReadPartition returns one partition's bytes, straight off the ssh channel:
// the channel is 8-bit clean and no tty is allocated, so an image needs no
// encoding to survive the trip.
func ReadPartition(c *Client, p transport.Partition, budget uint64) ([]byte, error) {
	if p.Handle == "" {
		return nil, fmt.Errorf("%s: no device node", p.Name)
	}
	// dd rather than cat: a block device read wants a sane block size, and dd's
	// count bounds what a mis-sized table entry — or a size the device would not
	// report — could pull. Its stderr is left alone: the record counts are noise
	// only while the read works, and its complaint is the whole explanation when
	// it does not.
	script := c.elevated(fmt.Sprintf("dd if=%s bs=65536 count=%d", shellQuote(p.Handle),
		(budget+65535)/65536))
	data, err := c.RunRaw(ReadTimeout, script)
	if err != nil {
		// dd's own complaint rides along in the error, so this says what went
		// wrong without guessing — a denied read and a dropped connection are
		// different problems and must not be reported as the same one.
		return nil, fmt.Errorf("reading %s: %w", p.Name, err)
	}
	if len(data) == 0 {
		// Nothing, no complaint: the block device opened and gave nothing, which
		// is what a refused read looks like once the shell has swallowed it.
		return nil, fmt.Errorf("reading %s: empty — %s", p.Name, permissionHint(c))
	}
	return data, nil
}

// permissionHint explains an empty read, which is what a denied block-device
// open looks like when nothing was said about why.
func permissionHint(c *Client) string {
	if c.elevate == "" {
		return "the login cannot read block devices (log in as root, or give it sudo/doas)"
	}
	return c.elevate + " ran but the device returned nothing"
}

// PrepareElevation settles how partition reads will get at the block devices,
// and proves it works before any read is attempted — twenty partitions failing
// one by one is not a diagnosis.
//
// It is separate from Collect because it may prompt: a recon that was not asked
// to read partitions must never ask for a password.
func PrepareElevation(c *Client, r *Recon) error {
	if r.UID == 0 {
		c.elevate, c.elevatePass = "", ""
		return nil
	}
	if c.opts.Elevate == "none" {
		return fmt.Errorf("elevation is disabled (--elevate=none) and the login is uid %d, which cannot read block devices", r.UID)
	}
	// A helper that needs no password is the whole story.
	if r.ElevateOK != "" {
		c.elevate, c.elevatePass = r.ElevateOK, ""
		return nil
	}
	helper := r.Elevate
	if c.opts.Elevate == "sudo" || c.opts.Elevate == "doas" {
		helper = c.opts.Elevate
	}
	if helper == "" {
		return fmt.Errorf("the login is uid %d and neither doas nor sudo is installed on the device: reading partitions needs root", r.UID)
	}
	// doas reads its password from the tty, never from stdin, so there is
	// nothing to offer it over an ssh session with no tty.
	if helper == "doas" {
		return fmt.Errorf("doas on the device wants a password and reads it only from a terminal, which an ssh session has none of: "+
			"give this login a passwordless doas rule, or log in as root (uid %d now)", r.UID)
	}
	pw, err := loginPassword(c.target)
	if err != nil {
		return fmt.Errorf("%s on the device wants a password: %w", helper, err)
	}
	c.elevate, c.elevatePass = helper, pw
	// Prove it once. A wrong password otherwise looks exactly like a partition
	// that cannot be read.
	if _, err := c.Run(CommandTimeout, c.elevated("true")+"\n"); err != nil {
		c.elevate, c.elevatePass = "", ""
		return fmt.Errorf("%s on the device rejected the password: %w", helper, err)
	}
	return nil
}

// shellQuote makes a path safe to interpolate into the remote script. Device
// nodes are tame, but the table's names come from the device.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
