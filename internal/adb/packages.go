package adb

// The package manager over adb: what is installed, and the two verbs that can
// remove a preload from a device that is neither rooted nor unlocked.
//
// `pm uninstall --user 0` removes a package *for the current user* without
// touching a partition. The APK stays where the image put it, dm-verity is
// undisturbed, the bootloader stays locked, and `cmd package install-existing`
// puts it back — as does a factory reset. That is what makes debloating safe to
// offer here: it is a per-user state change, not a flash.
//
// `pm disable-user` is the fallback for a package the shell may not uninstall.
// It is weaker (the package still runs if something re-enables it) and it is
// what the shell is allowed to do on more of the system than uninstall is.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/transport"
)

// Package is one installed package as the package manager reports it.
type Package struct {
	Name string
	// APK is the path the package is installed from, which is how a preload is
	// told from a user install: /product/app, /system/… and /vendor/… are the
	// image's, /data/app is the user's.
	APK      string
	System   bool // shipped in the image (pm list packages -s)
	Disabled bool // already disabled for this user
	// Uninstalled is a system package already removed for user 0: the APK is
	// still in the image, so it is restorable, and it must not be offered for
	// removal again.
	Uninstalled bool
}

// FromImage reports whether this package's APK lives in a read-only image
// partition. That decides whether a removal is locally reversible — only an APK
// that is still there can be restored with `install-existing`.
//
// It does not decide whether a package is bloat: the sponsored apps a delivery
// agent installs during setup land in /data/app like anything the owner chose.
func (p Package) FromImage() bool {
	if p.System {
		return true
	}
	// A package under /product or /vendor that pm does not call "system" is a
	// carrier or OEM preload all the same — the games and the ad agents live
	// exactly there.
	switch {
	case strings.HasPrefix(p.APK, "/product/"), strings.HasPrefix(p.APK, "/vendor/"),
		strings.HasPrefix(p.APK, "/system/"), strings.HasPrefix(p.APK, "/system_ext/"),
		strings.HasPrefix(p.APK, "/oem/"), strings.HasPrefix(p.APK, "/odm/"):
		return true
	}
	return false
}

// packageScript asks the package manager four questions in one round trip, in
// the section form the rest of the collection uses. -u includes packages that
// are uninstalled for this user but still in the image, which is how a second
// run knows what it already removed.
const packageScript = `
u() { printf '\n===unbrick:%s===\n' "$1"; }
u packages
pm list packages -f -u --user 0 2>/dev/null
u system
pm list packages -s --user 0 2>/dev/null
u disabled
pm list packages -d --user 0 2>/dev/null
u uninstalled
pm list packages -u --user 0 2>/dev/null
u installed
pm list packages --user 0 2>/dev/null
`

// Packages returns every package the device knows for user 0.
func Packages(c *Client) ([]Package, error) {
	out, err := c.Run(packageScript)
	if strings.TrimSpace(out) == "" {
		if err == nil {
			err = fmt.Errorf("the package manager returned nothing")
		}
		return nil, err
	}
	return parsePackages(out), err
}

func parsePackages(out string) []Package {
	secs := transport.SplitSections(out)
	system := nameSet(secs["system"])
	disabled := nameSet(secs["disabled"])
	installed := nameSet(secs["installed"])

	byName := map[string]*Package{}
	var order []string
	// "package:/product/app/Temu/Temu.apk=com.einnovation.temu" — the path may
	// itself contain '=' in theory, so the *last* one separates name from path.
	for _, line := range transport.NonEmptyLines(secs["packages"]) {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "package:")
		if !ok {
			continue
		}
		apk, name := "", rest
		if i := strings.LastIndex(rest, "="); i >= 0 {
			apk, name = rest[:i], rest[i+1:]
		}
		if name == "" {
			continue
		}
		if _, seen := byName[name]; !seen {
			order = append(order, name)
			byName[name] = &Package{Name: name}
		}
		p := byName[name]
		p.APK = apk
		p.System = system[name]
		p.Disabled = disabled[name]
		p.Uninstalled = !installed[name]
	}
	sort.Strings(order)
	out2 := make([]Package, 0, len(order))
	for _, n := range order {
		out2 = append(out2, *byName[n])
	}
	return out2
}

func nameSet(section string) map[string]bool {
	set := map[string]bool{}
	for _, line := range transport.NonEmptyLines(section) {
		if n, ok := strings.CutPrefix(strings.TrimSpace(line), "package:"); ok && n != "" {
			set[n] = true
		}
	}
	return set
}

// Uninstall removes a package for user 0. Nothing is flashed and nothing is
// deleted from the image: the APK stays, so Reinstall — or a factory reset —
// brings it back.
func Uninstall(c *Client, pkg string) error {
	out, err := c.Run("pm uninstall --user 0 " + shellQuote(pkg))
	return pmResult("uninstall", pkg, out, err)
}

// Reinstall restores a package previously uninstalled for user 0.
func Reinstall(c *Client, pkg string) error {
	out, err := c.Run("cmd package install-existing --user 0 " + shellQuote(pkg))
	if err != nil {
		return fmt.Errorf("restoring %s: %w", pkg, err)
	}
	// install-existing answers "Package X installed for user: 0" rather than
	// "Success", so anything that is not an error counts.
	low := strings.ToLower(out)
	if strings.Contains(low, "installed for user") || strings.Contains(low, "success") {
		return nil
	}
	return fmt.Errorf("restoring %s: %s", pkg, firstMeaningfulLine(out))
}

// Disable is the fallback where uninstall is refused: the package stays
// installed but is disabled for this user.
func Disable(c *Client, pkg string) error {
	out, err := c.Run("pm disable-user --user 0 " + shellQuote(pkg))
	if err != nil {
		return fmt.Errorf("disabling %s: %w", pkg, err)
	}
	if strings.Contains(strings.ToLower(out), "new state") {
		return nil
	}
	return fmt.Errorf("disabling %s: %s", pkg, shellFailure(out))
}

// Enable undoes Disable, so a package that could only be disabled is restorable
// too.
func Enable(c *Client, pkg string) error {
	out, err := c.Run("pm enable --user 0 " + shellQuote(pkg))
	if err != nil {
		return fmt.Errorf("enabling %s: %w", pkg, err)
	}
	if strings.Contains(strings.ToLower(out), "new state") {
		return nil
	}
	return fmt.Errorf("enabling %s: %s", pkg, shellFailure(out))
}

// pmResult reads the package manager's answer, which is "Success" or a
// "Failure [REASON]" the caller wants verbatim — DELETE_FAILED_INTERNAL_ERROR
// on a package the shell may not touch reads very differently from
// DELETE_FAILED_DEVICE_POLICY_MANAGER on one a device owner protects.
func pmResult(verb, pkg, out string, err error) error {
	if err != nil {
		return fmt.Errorf("%s %s: %w", verb, pkg, err)
	}
	if strings.Contains(out, "Success") {
		return nil
	}
	return fmt.Errorf("%s %s: %s", verb, pkg, shellFailure(out))
}
