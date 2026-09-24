// Package linuxdev is a phone booted into a Linux distribution — postmarketOS,
// Mobian, any of them — reached over ssh and treated as a recon source the same
// way a bootloader in fastboot mode is: one round trip collects what the running
// system says about itself, and the derivation graph makes the facts.
//
// A booted Linux userspace answers questions no bootloader will: the distro and
// kernel actually installed, the device package's own idea of which device this
// is, the SoC as the silicon reports it through sysfs, the whole partition table
// by name — and, with root, the partition *bytes*, which is the one recon source
// that otherwise needs EDL.
//
// The transport is Go's own ssh (golang.org/x/crypto/ssh): one connection, a
// session per command, and no host binary in the way. Both the collected shell
// script and a partition read travel the same channel, which is 8-bit clean, so
// an image arrives as the bytes it is. The host `ssh` binary remains available
// as a fallback transport (Options.SSHPath) for what a library cannot do —
// ~/.ssh/config aliases, ProxyJump, an agent-forwarded bastion.
package linuxdev

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"go-unbrick/internal/distro"
)

// Options tune how the device is reached. Everything here has a working
// default: no options at all means "connect as the user in the target, with the
// agent and the default keys, verifying the host key against known_hosts".
type Options struct {
	User     string // overrides any user in the target string
	Port     string // default 22
	Identity string // private key file; otherwise the agent and the default keys

	// HostKeys is the verification policy: HostKeysStrict (default),
	// HostKeysAcceptNew, or HostKeysOff. A phone reflashed between sessions
	// presents a new key under the same address, which is exactly the case
	// strict checking exists to surface — so relaxing it is the operator's
	// explicit decision, not a default.
	HostKeys   string
	KnownHosts string // default ~/.ssh/known_hosts

	// Elevate names the privilege helper for partition reads ("sudo", "doas",
	// "none"); empty or "auto" uses whatever the device proves works.
	Elevate string

	// Distros is the distribution table a recon reads this install with (see
	// internal/distro). Nil falls back to the built-in profiles, so a client
	// without a catalog still identifies what the code knows first-hand.
	Distros *distro.Set

	Dial time.Duration // budget for connecting and authenticating

	// SSHPath and Args select the fallback transport: the host ssh binary,
	// invoked with these extra arguments. Set SSHPath to use it.
	SSHPath string
	Args    []string
}

// Host-key policies.
const (
	HostKeysStrict    = "strict"     // refuse an unknown or changed key
	HostKeysAcceptNew = "accept-new" // learn an unknown key, refuse a changed one
	HostKeysOff       = "off"        // verify nothing
)

// Timeouts. Dial is generous because connecting is where a passphrase or a
// password is typed; a collected command is a handful of sysfs reads and has no
// business taking longer than Command.
const (
	DialTimeout    = 90 * time.Second
	CommandTimeout = 30 * time.Second
)

// route is one way of running a shell script on the device: the native ssh
// connection, or the host ssh binary. It is the *ssh* route, a layer below
// internal/transport's seam — that names which conversation a recon is having
// with the device, this names how these bytes get there.
type route interface {
	// run feeds script to /bin/sh on the device and returns its stdout. The
	// stream is binary-clean, so a partition read needs no encoding.
	run(ctx context.Context, script string) ([]byte, error)
	close() error
	describe() string
}

// Client runs commands on one target. The connection is opened on first use and
// shared by every command after it, so a recon that asks twenty questions
// authenticates once.
type Client struct {
	target string
	opts   Options
	tr     route
	// elevate is the privilege helper a partition read will use, and elevatePass
	// the password to feed it when it insists on one. Resolved by Collect and
	// PrepareElevation from what the device proved it has.
	elevate     string
	elevatePass string
}

// NewClient prepares a client for target ("user@host", "host", "host:port", or
// — with Options.SSHPath — any alias the operator's ssh config resolves). It
// does not connect; the first command does.
func NewClient(target string, o Options) (*Client, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("no ssh target given (expected user@host)")
	}
	if o.Elevate == "auto" {
		o.Elevate = ""
	}
	return &Client{target: strings.TrimSpace(target), opts: o}, nil
}

// Target is the destination as the operator spelled it.
func (c *Client) Target() string { return c.target }

// Transport names the route in use, for a report that should say how it got in.
func (c *Client) Transport() string {
	if c.tr == nil {
		if c.opts.SSHPath != "" {
			return "host ssh binary"
		}
		return "ssh"
	}
	return c.tr.describe()
}

// Close drops the connection.
func (c *Client) Close() error {
	if c.tr == nil {
		return nil
	}
	err := c.tr.close()
	c.tr = nil
	return err
}

// connect opens the transport, once.
func (c *Client) connect() error {
	if c.tr != nil {
		return nil
	}
	budget := c.opts.Dial
	if budget <= 0 {
		budget = DialTimeout
	}
	var tr route
	var err error
	if c.opts.SSHPath != "" {
		tr, err = newExecTransport(c.target, c.opts)
	} else {
		tr, err = dialNative(c.target, c.opts, budget)
	}
	if err != nil {
		return err
	}
	c.tr = tr
	return nil
}

// Run executes a POSIX shell script on the device and returns its stdout. The
// script goes over stdin rather than the command line, so it needs no quoting
// and no assumptions about the login shell — /bin/sh reads it, which on
// postmarketOS is busybox ash.
func (c *Client) Run(timeout time.Duration, script string) (string, error) {
	out, err := c.RunRaw(timeout, script)
	return string(out), err
}

// RunRaw is Run for output that is not text — a partition's bytes.
func (c *Client) RunRaw(timeout time.Duration, script string) ([]byte, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = CommandTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Partial output is still returned: a collection script whose last section
	// failed has already printed the rest, and that rest is recon.
	return c.tr.run(ctx, script)
}

// Elevate is the privilege helper in use: "" when the login is already root or
// nothing usable is available, else "sudo" or "doas". Resolved by Collect.
func (c *Client) Elevate() string { return c.elevate }

// elevated wraps a command in the privilege helper, if one is needed.
//
// With no password to offer, both helpers get -n: the remote shell has no tty
// to type one on, so a helper that wants a password must fail immediately
// rather than hang — and that it wants one is a finding the report states once,
// not twenty times.
//
// With a password (the stock postmarketOS login: a normal user whose sudo
// prompts), it goes to sudo's stdin as a here-document. Not on the command
// line: argv is world-readable through /proc on the device, while the script
// body only ever exists inside the encrypted channel and sudo's own memory.
func (c *Client) elevated(cmd string) string {
	if c.elevate == "" {
		return cmd
	}
	if c.elevatePass == "" {
		return c.elevate + " -n " + cmd
	}
	// -S reads the password from stdin, -p '' silences the prompt that would
	// otherwise land in the middle of a partition's bytes.
	return fmt.Sprintf("%s -S -p '' %s <<'%s'\n%s\n%s\n",
		c.elevate, cmd, pwHeredoc, c.elevatePass, pwHeredoc)
}

// pwHeredoc delimits the password. Quoted in the script so the shell does no
// expansion on it, and named so it cannot collide with a password's content.
const pwHeredoc = "__UNBRICK_SUDO_PW__"

// errTail is the last few lines of a failed command's stderr, which is where
// the reason lands (permission denied, no such device, a busybox complaint).
func errTail(b []byte) string {
	s := strings.TrimSpace(string(bytes.TrimRight(b, "\x00")))
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 4 {
		lines = lines[len(lines)-4:]
	}
	return " (" + strings.Join(lines, "; ") + ")"
}
