package linuxdev

// The fallback transport: the host's own ssh binary. It exists for what a
// library cannot do — a ~/.ssh/config alias, a ProxyJump through a bastion, an
// agent-forwarded chain, a smartcard — and for driving the recon against a
// stand-in during tests. Connections are multiplexed over a control socket, so
// a recon that asks twenty questions still authenticates once.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type execTransport struct {
	bin    string
	target string
	opts   Options
	ctlDir string
}

func newExecTransport(target string, o Options) (route, error) {
	bin := o.SSHPath
	if bin == "" || bin == "ssh" {
		p, err := exec.LookPath("ssh")
		if err != nil {
			return nil, fmt.Errorf("ssh binary not found in PATH: %w", err)
		}
		bin = p
	}
	dir, err := os.MkdirTemp("", "unbrick-ssh")
	if err != nil {
		return nil, fmt.Errorf("control socket directory: %w", err)
	}
	t := &execTransport{bin: bin, target: target, opts: o, ctlDir: dir}
	// Connect once with the terminal attached, so ssh can prompt for a password,
	// a passphrase or a host-key confirmation exactly as it would by hand —
	// which is half the reason this transport exists.
	if err := t.dial(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return t, nil
}

func (t *execTransport) describe() string { return "ssh(1) " + t.target }

func (t *execTransport) close() error {
	cmd := exec.Command(t.bin, append(t.args(), "-O", "exit", t.target)...)
	_ = cmd.Run()
	return os.RemoveAll(t.ctlDir)
}

// ctlPath is the multiplexing socket, kept short: a unix socket path is capped
// well below PATH_MAX (104 bytes on darwin).
func (t *execTransport) ctlPath() string { return filepath.Join(t.ctlDir, "m") }

func (t *execTransport) args() []string {
	args := []string{
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + t.ctlPath(),
		"-o", "ControlPersist=60",
		"-o", "ConnectTimeout=10",
	}
	switch t.opts.HostKeys {
	case HostKeysAcceptNew:
		args = append(args, "-o", "StrictHostKeyChecking=accept-new")
	case HostKeysOff:
		args = append(args, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
	}
	if t.opts.KnownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+t.opts.KnownHosts)
	}
	if t.opts.User != "" {
		args = append(args, "-l", t.opts.User)
	}
	if t.opts.Port != "" {
		args = append(args, "-p", t.opts.Port)
	}
	if t.opts.Identity != "" {
		args = append(args, "-i", t.opts.Identity)
	}
	return append(args, t.opts.Args...)
}

func (t *execTransport) dial() error {
	cmd := exec.Command(t.bin, append(t.args(), t.target, "true")...)
	cmd.Stdin = os.Stdin
	var errBuf safeBuffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh %s failed: %w%s", t.target, err, errTail(errBuf.Bytes()))
	}
	return nil
}

// run pipes the script to /bin/sh on the device. stdout is a pipe, not a tty —
// no -t is passed — so the bytes of a partition arrive unchanged.
func (t *execTransport) run(ctx context.Context, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, t.bin, append(t.args(), t.target, "/bin/sh", "-s")...)
	cmd.Stdin = strings.NewReader(script)
	var out, errBuf safeBuffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), fmt.Errorf("ssh %s: command timed out", t.target)
	}
	if err != nil {
		return out.Bytes(), fmt.Errorf("ssh %s: %w%s", t.target, err, errTail(errBuf.Bytes()))
	}
	return out.Bytes(), nil
}
