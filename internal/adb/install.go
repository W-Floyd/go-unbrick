package adb

// Installing an APK, and the device facts a provisioning preflight needs.
//
// The install is a push followed by `pm install`, not `adb install`: this
// package speaks the adb server protocol rather than driving the binary, and
// the sync (push) service is part of that protocol. The staged file goes to
// /data/local/tmp, which the shell user owns, and is removed afterwards
// whichever way the install went.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// InstallAPK pushes a local APK to the device and installs it. reinstall keeps
// the existing app's data (-r); grantRuntime grants the runtime permissions the
// manifest declares (-g), which is what makes a headless setup possible.
func InstallAPK(c *Client, path string, reinstall, grantRuntime bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("reading the APK: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("reading the APK: %w", err)
	}
	if st.Size() == 0 {
		return fmt.Errorf("%s is empty", path)
	}

	// A staged name that cannot collide with a concurrent run or be guessed
	// into by something else on the device.
	remote := fmt.Sprintf("/data/local/tmp/unbrick-%d-%s", time.Now().UnixNano(),
		sanitizeName(filepath.Base(path)))
	if err := c.dev.Push(f, remote, st.ModTime(), 0o644); err != nil {
		return fmt.Errorf("pushing the APK to %s: %w", remote, err)
	}
	// The staged copy is removed whether or not the install works: leaving a
	// 30 MB APK in /data/local/tmp is not this tool's business.
	defer func() { _, _ = c.Run("rm -f " + shellQuote(remote)) }()

	flags := ""
	if reinstall {
		flags += " -r"
	}
	if grantRuntime {
		flags += " -g"
	}
	out, err := c.Run("pm install" + flags + " " + shellQuote(remote))
	if err != nil {
		return fmt.Errorf("installing %s: %w", filepath.Base(path), err)
	}
	if strings.Contains(out, "Success") {
		return nil
	}
	return fmt.Errorf("installing %s: %s", filepath.Base(path), shellFailure(out))
}

// sanitizeName keeps a pushed filename to characters that need no quoting
// thought on the device side.
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "app.apk"
	}
	return b.String()
}

// SDK is the device's API level, or 0 when it will not say.
func (c *Client) SDK() int {
	out, err := c.Run("getprop ro.build.version.sdk")
	if err != nil {
		return 0
	}
	n, cerr := strconv.Atoi(strings.TrimSpace(out))
	if cerr != nil {
		return 0
	}
	return n
}

// Shell runs one command and returns its output, which is what a provisioning
// plan executes through.
func (c *Client) Shell(cmd string) (string, error) { return c.Run(cmd) }

// InstallAPKFile satisfies the provisioning Device interface.
func (c *Client) InstallAPKFile(path string, reinstall, grantRuntime bool) error {
	return InstallAPK(c, path, reinstall, grantRuntime)
}
