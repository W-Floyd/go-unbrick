package linuxdev

import (
	"fmt"
	"strings"

	"go-unbrick/internal/distro"
	"go-unbrick/internal/transport"
)

// Recon is everything one collection round trip learned about a booted device:
// the shell recon every route brings back, plus what only a Linux distribution
// can say — which distribution it is, which kernel it runs, and what its device
// package claims the hardware is.
type Recon struct {
	*transport.ShellRecon
	Target string // as the operator spelled it

	OS     OSRelease
	Kernel Kernel

	// Distro is the profile that claimed this install, nil when no entry
	// recognised it — which is not a failure: everything that does not depend
	// on the distribution (the partition table, the device tree, the cmdline,
	// the SoC) is collected either way.
	Distro distro.Profile
	// Claim is what that distribution's own device definition says the hardware
	// is. It is the packager's claim, not the hardware's, which is why facts
	// from it are Derived and those from sysfs are not.
	Claim distro.Claim
	// DeviceInfo is that definition's full key/value set, for the report and
	// for whatever the Claim has no field for.
	DeviceInfo map[string]string
	// Missing is what this install would have to have for the recon to see more
	// of it — an uninstalled device package, a definition that moved.
	Missing []distro.Precondition
}

// OSRelease is /etc/os-release: which distribution is actually installed.
type OSRelease struct {
	ID         string // "postmarketos", "debian", "arch"
	Name       string
	PrettyName string
	Version    string
	VersionID  string
	BuildID    string
	Raw        map[string]string
}

// IDLike is the distributions this one declares itself derived from, which is
// how a Debian derivative is recognised when nothing claims its own id.
func (o OSRelease) IDLike() []string {
	return strings.Fields(strings.ReplaceAll(o.Raw["ID_LIKE"], ",", " "))
}

// Kernel is what uname reports.
type Kernel struct {
	Sys     string // "Linux"
	Release string // "6.6.0-postmarketos-qcom-sm6225"
	Machine string // "aarch64"
}

// collectScript is the common shell collection plus what identifies a Linux
// distribution: its os-release, its kernel, the helper commands it has, and
// every device-definition file any known distribution keeps.
//
// The file list comes from the distro table, so supporting another
// distribution's definition adds a path to data rather than a round trip here:
// all candidates are read in this one script and the profile that matches
// decides which of them it wanted. Only paths are taken from data — never a
// command — so the table can extend what is *read* without being able to
// extend what is *run*.
func collectScript(set *distro.Set) string {
	var b strings.Builder
	b.WriteString(transport.CommonShellScript)
	b.WriteString(`
u os-release
cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null
u uname
uname -s -r -m 2>/dev/null
u commands
for c in getprop lsblk blockdev dd base64 sha256sum mmcli; do
	command -v "$c" >/dev/null 2>&1 && echo "$c"
done
u distro-files
`)
	for _, path := range set.DeviceFiles() {
		fmt.Fprintf(&b, "if [ -r %s ]; then printf '##%%s\\n' %s; cat %s; echo; fi\n",
			shellQuote(path), shellQuote(path), shellQuote(path))
	}
	return b.String()
}

// Collect runs the collection script and parses it. A failure that still
// produced output is reported as a finding by the caller rather than an error:
// one unreadable section (a locked-down sysfs, a missing /proc/device-tree) is
// not a failed recon.
func Collect(c *Client) (*Recon, error) {
	set := c.opts.Distros
	if set == nil {
		// No table given: the built-in profiles still identify what they know.
		set = distro.Builtin()
	}
	out, err := c.Run(CommandTimeout, collectScript(set))
	if strings.TrimSpace(out) == "" && err != nil {
		return nil, err
	}
	r := Parse(out, set)
	r.Target = c.Target()
	// What a partition read would use, if one is asked for. PrepareElevation
	// settles it for real — this is only what is available without prompting.
	c.elevate = r.passwordlessElevation(c.opts.Elevate)
	return r, err
}

// passwordlessElevation is the helper usable with no password at all: the
// operator's override when they gave one, else whatever the device proved.
func (r *Recon) passwordlessElevation(override string) string {
	switch override {
	case "none":
		return ""
	case "sudo", "doas":
		return override
	}
	if r.UID == 0 {
		return ""
	}
	return r.ElevateOK
}

// Parse turns collection output into a Recon. Exported so the parsers are
// testable against captured output without a device.
func Parse(out string, set *distro.Set) *Recon {
	sh := transport.ParseShell(out)
	r := &Recon{ShellRecon: sh, DeviceInfo: map[string]string{}}
	r.OS = parseOSRelease(sh.Sections["os-release"])
	if f := strings.Fields(sh.Sections["uname"]); len(f) >= 3 {
		r.Kernel = Kernel{Sys: f[0], Release: f[1], Machine: f[2]}
	}

	// Which distribution this is, and therefore which of the collected
	// definition files is the one that names the device.
	dtName, dtVendor := sh.DTCodename()
	env := distro.Env{
		ID: r.OS.ID, Name: r.OS.Name, Version: r.OS.Version,
		VersionID: r.OS.VersionID, BuildID: r.OS.BuildID,
		Files:      parseDistroFiles(sh.Sections["distro-files"]),
		Commands:   commandSet(sh.Sections["commands"]),
		Sections:   sh.Sections,
		DTCodename: dtName, DTVendor: dtVendor,
	}
	if p := set.Match(r.OS.ID, r.OS.IDLike()); p != nil {
		r.Distro = p
		r.Claim, r.DeviceInfo = p.Device(env)
		r.Missing = p.Preconditions(env)
		if r.DeviceInfo == nil {
			r.DeviceInfo = map[string]string{}
		}
	}
	return r
}

// parseDistroFiles splits the collected device-definition files, which the
// script marks with a "##<path>" line before each one's contents.
func parseDistroFiles(section string) map[string]string {
	out := map[string]string{}
	path := ""
	var body []string
	flush := func() {
		if path != "" {
			// The script echoes after each file, so the trailing blank is the
			// separator rather than content.
			out[path] = strings.TrimRight(strings.Join(body, "\n"), "\n")
		}
		body = body[:0]
	}
	for _, line := range strings.Split(section, "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "##"); ok && strings.HasPrefix(p, "/") {
			flush()
			path = p
			continue
		}
		if path != "" {
			body = append(body, line)
		}
	}
	flush()
	return out
}

func commandSet(section string) map[string]bool {
	out := map[string]bool{}
	for _, l := range transport.NonEmptyLines(section) {
		out[strings.TrimSpace(l)] = true
	}
	return out
}

// parseOSRelease reads the os-release key=value format, whose values are
// optionally double- or single-quoted.
func parseOSRelease(s string) OSRelease {
	raw := map[string]string{}
	for _, line := range transport.NonEmptyLines(s) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		raw[strings.ToUpper(strings.TrimSpace(k))] = transport.Unquote(v)
	}
	return OSRelease{
		ID:         raw["ID"],
		Name:       raw["NAME"],
		PrettyName: raw["PRETTY_NAME"],
		Version:    raw["VERSION"],
		VersionID:  raw["VERSION_ID"],
		BuildID:    raw["BUILD_ID"],
		Raw:        raw,
	}
}

// Describe names the installed distribution the way a report should print it:
// the pretty name if there is one, else the name and version assembled, else
// the bare id. A rolling release (postmarketOS edge) carries its build id,
// which is the only thing that distinguishes two installs of "edge".
func (o OSRelease) Describe() string {
	out := o.PrettyName
	if out == "" {
		out = strings.TrimSpace(o.Name + " " + firstNonEmpty(o.Version, o.VersionID))
	}
	if out == "" {
		out = o.ID
	}
	if o.BuildID != "" && !strings.Contains(out, o.BuildID) {
		out = fmt.Sprintf("%s (build %s)", out, o.BuildID)
	}
	return out
}

// Codename is the OEM codename for this device: what the distribution's own
// device definition claims, else what the device tree calls itself. Either way
// it is the string the bootloader answers `getvar product` with, which is what
// makes it resolvable against the device catalog.
func (r *Recon) Codename() string {
	if r.Claim.Codename != "" {
		return r.Claim.Codename
	}
	name, _ := r.DTCodename()
	return name
}

// VendorID is the OEM the device belongs to, as a catalog vendor id.
func (r *Recon) VendorID() string {
	if r.Claim.VendorID != "" {
		return r.Claim.VendorID
	}
	if _, v := r.DTCodename(); v != "" {
		return v
	}
	// Last resort: the manufacturer the definition declares ("Motorola"), whose
	// first word is the catalog's vendor id for every OEM it names.
	if f := strings.Fields(r.Claim.Manufacturer); len(f) > 0 {
		return strings.ToLower(f[0])
	}
	return ""
}

// DistroName is how a report spells the installed distribution: the profile's
// name when one claimed it, else whatever os-release called itself.
func (r *Recon) DistroName() string {
	if r.Distro != nil {
		return r.Distro.Name()
	}
	return r.OS.Name
}

// CanReadPartitions reports whether a partition read can succeed: the login is
// root, a helper elevates without a password, or it is sudo — which takes one
// on stdin, so the session can supply it. doas is deliberately not on that
// list: it reads a password only from a terminal, and an ssh session has none.
func (r *Recon) CanReadPartitions() bool {
	return r.UID == 0 || r.ElevateOK != "" || r.Elevate == "sudo"
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s != "" {
			return s
		}
	}
	return ""
}
