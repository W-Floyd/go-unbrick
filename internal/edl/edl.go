// Package edl provisions and drives bkerler/edl (the Python edlclient) so
// go-unbrick can run Sahara/Firehose operations end to end instead of only
// emitting a bundle for the user to flash by hand.
//
// edlclient is a Python package, not a shippable binary, so it is installed into
// a managed virtualenv under the user cache dir on first use and reused after.
// Two host prerequisites are outside our control and only detected, not fixed:
// python3 and libusb (plus USB access — root/udev on Linux, a libusb driver on
// Windows).
package edl

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultSpec is the pip requirement installed into the venv. edlclient is
// published only from its git repo, not PyPI. Callers may override with a pinned
// ref, e.g. "git+https://github.com/bkerler/edl.git@3.62".
const DefaultSpec = "git+https://github.com/bkerler/edl.git"

// Options configures provisioning. Empty fields take defaults. The command layer
// fills these from viper (config < env UNBRICK_EDL_* < flags), so the package
// itself reads no environment.
type Options struct {
	Dir  string // cache root override; "" -> <UserCacheDir>/go-unbrick/edl
	Spec string // pip spec override; "" -> DefaultSpec
}

// Runner holds a provisioned edl installation.
type Runner struct {
	dir string // cache root (venv lives at <dir>/venv)
	bin string // resolved edl entry point
}

// ResolveDir returns the cache root, applying the override or the default
// <UserCacheDir>/go-unbrick/edl.
func ResolveDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating user cache dir: %w", err)
	}
	return filepath.Join(cache, "go-unbrick", "edl"), nil
}

// venvBin returns the path to an executable inside a venv, honoring the
// platform's layout (Scripts on Windows, bin elsewhere).
func venvBin(venv, name string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(venv, "Scripts", name+".exe")
	}
	return filepath.Join(venv, "bin", name)
}

// python resolves the host interpreter, preferring python3.
func python() (string, error) {
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("python3 not found in PATH; install Python 3 (macOS: `brew install python`, Debian/Ubuntu: `apt install python3 python3-venv`)")
}

// Ensure provisions the managed venv (creating it and installing edlclient on
// first use) and returns a Runner. Progress is streamed to progress. Reprovision
// forces a reinstall even if edl is already present (for upgrades/repair).
func Ensure(ctx context.Context, opts Options, progress io.Writer, reprovision bool) (*Runner, error) {
	dir, err := ResolveDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	venv := filepath.Join(dir, "venv")
	bin := venvBin(venv, "edl")

	if !reprovision {
		if _, err := os.Stat(bin); err == nil {
			return &Runner{dir: dir, bin: bin}, nil
		}
	}

	py, err := python()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating cache dir %s: %w", dir, err)
	}

	if _, err := os.Stat(venvBin(venv, "python")); err != nil {
		fmt.Fprintf(progress, "Creating virtualenv at %s\n", venv)
		if err := stream(ctx, progress, "", py, "-m", "venv", venv); err != nil {
			return nil, fmt.Errorf("creating virtualenv (need python3-venv): %w", err)
		}
	}

	spec := opts.Spec
	if spec == "" {
		spec = DefaultSpec
	}
	fmt.Fprintf(progress, "Installing %s (first run; cached afterwards)\n", spec)
	vpy := venvBin(venv, "python")
	if err := stream(ctx, progress, "", vpy, "-m", "pip", "install", "--disable-pip-version-check", "--upgrade", spec); err != nil {
		return nil, fmt.Errorf("pip install %s: %w", spec, err)
	}
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("edl entry point not found after install at %s", bin)
	}
	return &Runner{dir: dir, bin: bin}, nil
}

// BinaryPath returns the resolved edl entry point.
func (r *Runner) BinaryPath() string { return r.bin }

// Doctor verifies the install can actually reach USB, catching a missing libusb
// backend before a flash is attempted. Returns nil when edl runs cleanly.
func (r *Runner) Doctor(ctx context.Context) error {
	out, err := capture(ctx, r.bin, "--help")
	if err == nil {
		return nil
	}
	if strings.Contains(out, "No backend available") || strings.Contains(strings.ToLower(out), "libusb") {
		return fmt.Errorf("edl cannot reach USB — libusb backend missing.\n"+
			"  macOS:        brew install libusb\n"+
			"  Debian/Ubuntu: apt install libusb-1.0-0\n(edl output: %s)", strings.TrimSpace(out))
	}
	return fmt.Errorf("edl --help failed: %w (output: %s)", err, strings.TrimSpace(out))
}

// Run executes edl with args, with workdir as the working directory (the bundle
// dir, so relative filenames in rawprogram/patch/read XML resolve). Output is
// streamed live to progress.
func (r *Runner) Run(ctx context.Context, workdir string, progress io.Writer, args ...string) error {
	return stream(ctx, progress, workdir, r.bin, args...)
}

// stream runs a command, forwarding stdout/stderr to w live.
func stream(ctx context.Context, w io.Writer, workdir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = workdir
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", filepath.Base(name), strings.Join(args, " "), err)
	}
	return nil
}

// capture runs a command and returns combined output, without streaming.
func capture(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
