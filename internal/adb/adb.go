// Package adb is a phone booted into Android userspace, reached over adb and
// treated as a recon source the same way a bootloader or an ssh-reachable Linux
// install is.
//
// An Android userspace is the most common state a phone is actually found in,
// and it answers a great deal: the build fingerprint and security patch level,
// the property system's whole view of the hardware, /proc/cmdline as the
// bootloader left it, the partition table by name — and, with root, the
// partition bytes.
//
// The transport is Go's own (github.com/electricbubble/gadb), speaking the adb
// *server* protocol rather than shelling out per command. One caveat, stated
// here because it decides what the error messages have to say: that protocol is
// served by the local adb server, so one has to be running. The `adb` binary is
// what starts it, and this package will start it that way if the binary is
// there — but on a host with no platform-tools at all there is nothing to talk
// to, which is a different failure from "no device".
package adb

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/electricbubble/gadb"
)

// Options tune how the device is reached.
type Options struct {
	Serial string // which device, when more than one is attached
	Host   string // adb server host; empty is localhost
	Port   int    // adb server port; 0 is 5037
	// ADBPath is the adb binary used to start a server if none is running.
	// Empty resolves "adb" from PATH; "none" disables starting one.
	ADBPath string
	// Elevate names the root helper for partition reads ("su", "none"); empty
	// or "auto" uses whatever the device proves works.
	Elevate string
}

// CommandTimeout is what the transport allows one command. It is gadb's own
// default (60s), restated here because this package relies on it: gadb offers
// no per-call deadline, and its DefaultAdbReadTimeout is not a Duration in the
// usual sense — the value is multiplied by time.Second where the deadline is
// set, so overriding it with `5 * time.Minute` asks for five minutes of
// seconds. Left alone rather than fought with; a collection that needs longer
// than a minute of wall clock is a device in trouble, and a partition read of a
// few megabytes over USB is seconds.
const CommandTimeout = 60 * time.Second

// Client runs commands on one device over the adb server protocol.
type Client struct {
	dev     gadb.Device
	serial  string
	opts    Options
	elevate string // resolved root helper for reads
}

// NewClient connects to the adb server and selects a device.
func NewClient(o Options) (*Client, error) {
	cli, err := dialServer(o)
	if err != nil {
		return nil, err
	}
	devs, err := cli.DeviceList()
	if err != nil {
		return nil, fmt.Errorf("listing adb devices: %w", err)
	}
	if len(devs) == 0 {
		return nil, fmt.Errorf("no device is attached over adb (check the cable, and that USB debugging is enabled and this host is authorised)")
	}
	if o.Elevate == "auto" {
		o.Elevate = ""
	}
	if o.Serial != "" {
		for _, d := range devs {
			if d.Serial() == o.Serial {
				return &Client{dev: d, serial: d.Serial(), opts: o}, nil
			}
		}
		return nil, fmt.Errorf("no adb device with serial %q (attached: %s)", o.Serial, serials(devs))
	}
	if len(devs) > 1 {
		return nil, fmt.Errorf("more than one device is attached over adb (%s): name one with --serial", serials(devs))
	}
	return &Client{dev: devs[0], serial: devs[0].Serial(), opts: o}, nil
}

// dialServer connects to the adb server, starting one with the adb binary if
// nothing is listening — which is what the binary is for here, and the only
// thing this package uses it for.
func dialServer(o Options) (gadb.Client, error) {
	host := o.Host
	if host == "" {
		host = "localhost"
	}
	dial := func() (gadb.Client, error) {
		if o.Port != 0 {
			return gadb.NewClientWith(host, o.Port)
		}
		return gadb.NewClientWith(host)
	}
	cli, err := dial()
	if err == nil {
		return cli, nil
	}
	if o.ADBPath == "none" || o.Host != "" {
		return gadb.Client{}, fmt.Errorf("no adb server at %s: %w", host, err)
	}
	bin := o.ADBPath
	if bin == "" {
		p, lerr := exec.LookPath("adb")
		if lerr != nil {
			return gadb.Client{}, fmt.Errorf("no adb server is running and no adb binary to start one with (install Android platform-tools, or start a server elsewhere and pass --adb-host): %w", err)
		}
		bin = p
	}
	if out, serr := exec.Command(bin, "start-server").CombinedOutput(); serr != nil {
		return gadb.Client{}, fmt.Errorf("starting an adb server with %s: %w (%s)", bin, serr, strings.TrimSpace(string(out)))
	}
	cli, err = dial()
	if err != nil {
		return gadb.Client{}, fmt.Errorf("adb server started but would not answer: %w", err)
	}
	return cli, nil
}

func serials(devs []gadb.Device) string {
	var out []string
	for _, d := range devs {
		out = append(out, d.Serial())
	}
	return strings.Join(out, ", ")
}

// Serial identifies the device.
func (c *Client) Serial() string { return c.serial }

// Close is a no-op: the server connection is per command, and the server itself
// outlives this process on purpose — killing it would disturb whatever else on
// the host is using adb.
func (c *Client) Close() error { return nil }

// Run executes a shell script on the device and returns its stdout.
//
// The script goes as one command string, which adbd hands to /system/bin/sh
// -c: no quoting layer of our own, and no assumptions about the shell beyond
// POSIX, which toybox/mksh satisfies.
func (c *Client) Run(script string) (string, error) {
	out, err := c.dev.RunShellCommandWithBytes(script)
	return string(out), err
}

// Elevate is the root helper in use for partition reads, or "" when the shell
// is already root or nothing usable was found.
func (c *Client) Elevate() string { return c.elevate }

// elevated wraps a command in the root helper. Android's su takes a command
// with -c rather than reading a password from anywhere: either this shell can
// become root or it cannot, so there is nothing to prompt for and nothing to
// fall back to.
func (c *Client) elevated(cmd string) string {
	if c.elevate == "" {
		return cmd
	}
	return c.elevate + " -c " + shellQuote(cmd)
}

// shellQuote makes a command safe to pass through su -c.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
