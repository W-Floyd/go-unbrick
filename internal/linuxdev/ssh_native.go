package linuxdev

// The native transport: one ssh connection, a session per command. Auth is the
// order a person expects — agent, then the key they named or the default ones,
// then a password — and host keys are checked against known_hosts, because a
// phone that presents a new key under the same address after a reflash is
// exactly the event strict checking exists to surface.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// PasswordEnv carries the login password for an unattended run. A password on
// the command line would sit in the process table for every local user to read;
// the interactive prompt is the normal route and this is the automation one.
const PasswordEnv = "UNBRICK_SSH_PASSWORD"

type nativeTransport struct {
	conn *ssh.Client
	addr string
	user string
}

func (t *nativeTransport) describe() string { return "ssh " + t.user + "@" + t.addr }
func (t *nativeTransport) close() error     { return t.conn.Close() }

// dialNative connects and authenticates.
func dialNative(target string, o Options, budget time.Duration) (route, error) {
	user, host, port := splitTarget(target, o)
	if user == "" {
		return nil, fmt.Errorf("no login user for %s: give it as user@host, or with --user", target)
	}
	hostKey, err := hostKeyCallback(o)
	if err != nil {
		return nil, err
	}
	auth, err := authMethods(o, user, host)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, port)
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         budget,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh %s@%s: %w", user, addr, err)
	}
	return &nativeTransport{conn: conn, addr: addr, user: user}, nil
}

// run executes one script in its own session. The session's stdout is an ssh
// channel, which carries bytes unchanged — so a partition read needs no
// encoding around it.
func (t *nativeTransport) run(ctx context.Context, script string) ([]byte, error) {
	sess, err := t.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	sess.Stdin = strings.NewReader(script)
	var out, errBuf safeBuffer
	sess.Stdout = &out
	sess.Stderr = &errBuf

	done := make(chan error, 1)
	if err := sess.Start("/bin/sh -s"); err != nil {
		return nil, fmt.Errorf("starting remote shell: %w", err)
	}
	go func() { done <- sess.Wait() }()

	select {
	case <-ctx.Done():
		// Closing the session unblocks Wait; the connection stays up for the
		// next command, which is the point of holding one.
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return out.Bytes(), fmt.Errorf("%s: command timed out", t.describe())
	case err := <-done:
		if err != nil {
			return out.Bytes(), fmt.Errorf("%s: %w%s", t.describe(), err, errTail(errBuf.Bytes()))
		}
		return out.Bytes(), nil
	}
}

// splitTarget pulls the login, host and port out of "user@host:port", with the
// options and the local username filling what it does not say.
func splitTarget(target string, o Options) (user, host, port string) {
	host = target
	if u, rest, ok := strings.Cut(target, "@"); ok {
		user, host = u, rest
	}
	// An IPv6 literal is bracketed; anything else with a colon carries a port.
	if h, p, err := net.SplitHostPort(host); err == nil {
		host, port = h, p
	}
	if o.User != "" {
		user = o.User
	}
	if o.Port != "" {
		port = o.Port
	}
	if port == "" {
		port = "22"
	}
	return user, host, port
}

// authMethods is the order a person expects: keys first — the agent, then the
// one they named or the usual ones — and a password only if none worked.
//
// Every public key goes in *one* method on purpose. An ssh client tries each
// method name once: two publickey methods mean the second is skipped the moment
// the first is tried, so an empty agent would shadow the key on disk and a
// device set up with ssh-copy-id would still be asked for a password.
func authMethods(o Options, user, host string) ([]ssh.AuthMethod, error) {
	keys := defaultKeyFiles()
	if o.Identity != "" {
		keys = []string{o.Identity}
	}
	// A named key that cannot be read is the operator's mistake, and worth
	// failing on before a connection is made rather than falling back to a
	// password they did not ask for.
	if o.Identity != "" {
		if _, err := os.Stat(o.Identity); err != nil {
			return nil, fmt.Errorf("reading identity %s: %w", o.Identity, err)
		}
	}

	// Resolved when the server asks for publickey, not before: an unused key
	// file is never read and a passphrase is never prompted for.
	signers := func() ([]ssh.Signer, error) {
		var out []ssh.Signer
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if conn, err := net.Dial("unix", sock); err == nil {
				if agentSigners, err := agent.NewClient(conn).Signers(); err == nil {
					out = append(out, agentSigners...)
				}
			}
		}
		for _, path := range keys {
			signer, err := loadKey(path, o.Identity != "")
			if err != nil {
				if o.Identity != "" {
					return nil, err
				}
				continue // a default key that is simply not there
			}
			if signer != nil {
				out = append(out, signer)
			}
		}
		return out, nil
	}

	return append([]ssh.AuthMethod{ssh.PublicKeysCallback(signers)},
		ssh.PasswordCallback(func() (string, error) { return devicePassword(user, host) }),
		// postmarketOS's sshd offers keyboard-interactive as well as password;
		// the answer to its single prompt is the same password.
		ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			if len(qs) == 0 {
				return nil, nil
			}
			pw, err := devicePassword(user, host)
			if err != nil {
				return nil, err
			}
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = pw
			}
			return ans, nil
		})), nil
}

// devicePassword reads the login password: from the environment for an
// unattended run, else from the terminal. It is asked for at most once per
// process — ssh may call back for both password and keyboard-interactive, and
// the same password is usually what the device's sudo wants too.
func devicePassword(user, host string) (string, error) {
	return askPassword(user+"@"+host+"'s password: ",
		fmt.Sprintf("no key worked and there is no terminal to ask for a password on; set %s or use --identity", PasswordEnv))
}

// loginPassword is the password already in hand, or one asked for now — what a
// password-prompting sudo on the device is given.
func loginPassword(target string) (string, error) {
	return askPassword("password for "+target+" (for sudo on the device): ",
		fmt.Sprintf("there is no terminal to ask for one on; set %s, or give this login passwordless sudo on the device", PasswordEnv))
}

func askPassword(prompt, noTTY string) (string, error) {
	cachedMu.Lock()
	defer cachedMu.Unlock()
	if cached != "" {
		return cached, nil
	}
	if pw, ok := os.LookupEnv(PasswordEnv); ok {
		cached = pw
		return pw, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New(noTTY)
	}
	defer tty.Close()
	beforePrompt()
	fmt.Fprint(tty, prompt)
	pw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	cached = strings.TrimRight(string(pw), "\r\n")
	return cached, nil
}

// BeforePrompt, if set, runs before anything is asked on the terminal — for the
// caller to take down a spinner that would otherwise draw over the prompt.
var BeforePrompt func()

func beforePrompt() {
	if BeforePrompt != nil {
		BeforePrompt()
	}
}

// cached holds the password for the life of the process, so one recon does not
// prompt per auth method and then again for sudo. It never leaves this package.
var (
	cachedMu sync.Mutex
	cached   string
)

func defaultKeyFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		out = append(out, filepath.Join(home, ".ssh", name))
	}
	return out
}

// loadKey reads a private key, prompting for its passphrase if it has one.
func loadKey(path string, named bool) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading identity %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer, nil
	}
	var needsPass *ssh.PassphraseMissingError
	if !errors.As(err, &needsPass) {
		return nil, fmt.Errorf("parsing identity %s: %w", path, err)
	}
	tty, terr := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if terr != nil {
		// An encrypted default key with nobody to ask is simply one more method
		// that is not available; a named one is an error.
		if named {
			return nil, fmt.Errorf("identity %s is passphrase-protected and there is no terminal to ask on", path)
		}
		return nil, nil
	}
	defer tty.Close()
	beforePrompt()
	fmt.Fprintf(tty, "passphrase for %s: ", path)
	pass, rerr := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if rerr != nil {
		return nil, fmt.Errorf("reading passphrase: %w", rerr)
	}
	return ssh.ParsePrivateKeyWithPassphrase(data, pass)
}

// hostKeyCallback builds the verification the policy asks for.
func hostKeyCallback(o Options) (ssh.HostKeyCallback, error) {
	if o.HostKeys == HostKeysOff {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path := o.KnownHosts
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("locating known_hosts: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	// A missing file is an empty one: every host is unknown, which under
	// accept-new is how the first connection is meant to go.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
		}
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			_ = f.Close()
		}
	}
	known, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	acceptNew := o.HostKeys == HostKeysAcceptNew

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := known(hostname, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if !errors.As(err, &ke) {
			return err
		}
		// Want non-empty: the host is known and presents a *different* key.
		// Never accepted silently — on a phone it usually means "reflashed",
		// but it is also what interception looks like, so the operator decides.
		if len(ke.Want) > 0 {
			var where []string
			for _, k := range ke.Want {
				where = append(where, fmt.Sprintf("%s:%d", k.Filename, k.Line))
			}
			return fmt.Errorf("host key for %s has changed (known key at %s). "+
				"A reflashed device is the usual cause; remove the stale line, or pass --host-keys=off to skip verification",
				hostname, strings.Join(where, ", "))
		}
		if !acceptNew {
			return fmt.Errorf("host key for %s is unknown (%s %s). "+
				"Pass --host-keys=accept-new to record it, or add it to %s yourself",
				hostname, key.Type(), ssh.FingerprintSHA256(key), path)
		}
		return appendKnownHost(path, hostname, remote, key)
	}, nil
}

// appendKnownHost records a newly learned key, the way ssh's own accept-new
// does: the address as dialled, plus the hostname when they differ.
func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	addrs := []string{hostname}
	if r := remote.String(); r != hostname {
		addrs = append(addrs, r)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("recording host key in %s: %w", path, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, knownhosts.Line(addrs, key)); err != nil {
		return fmt.Errorf("recording host key in %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "learned host key for %s (%s %s)\n",
		hostname, key.Type(), ssh.FingerprintSHA256(key))
	return nil
}

// safeBuffer collects a session's output. The ssh session writes it from its own
// goroutine, and a timed-out command reads what arrived before giving up, so the
// two need not race.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}
