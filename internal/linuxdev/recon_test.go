package linuxdev

import (
	"strings"
	"testing"

	"go-unbrick/internal/distro"
)

// collected is one real-shaped collection from a Motorola fogona running
// postmarketOS: the common shell sections (tested in internal/transport) plus
// the ones this route adds — os-release, uname, the helper commands, and the
// device-definition files the distro table asked for.
const collected = `
===unbrick:whoami===
uid=1000
user=user
===unbrick:hostname===
fogona
===unbrick:elevate===
doas
sudo
===unbrick:elevate-ok===
doas
===unbrick:cmdline===
console=ttyMSM0,115200n8 androidboot.slot_suffix=_a androidboot.serialno=ZLTEST0001 androidboot.verifiedbootstate=orange
===unbrick:soc0===
machine=SM6225
===unbrick:dt-model===
Motorola fogona
===unbrick:dt-compatible===
motorola,fogona
qcom,sm6225
===unbrick:partitions===
cid	/dev/sdf5	256
xbl_a	/dev/sdd1	8192
xbl_b	/dev/sdd2	8192
===unbrick:disks===
sdd	16384
===unbrick:os-release===
NAME="postmarketOS"
ID=postmarketos
ID_LIKE="alpine"
PRETTY_NAME="postmarketOS edge"
VERSION_ID="24.06"
BUILD_ID="20240612-0132"
===unbrick:uname===
Linux 6.6.32-postmarketos-qcom-sm6225 aarch64
===unbrick:commands===
lsblk
dd
base64
===unbrick:distro-files===
##/usr/share/deviceinfo/deviceinfo
deviceinfo_format_version="0"
deviceinfo_name="Motorola Moto G Play (2024)"
deviceinfo_manufacturer="Motorola"
deviceinfo_codename="motorola-fogona"
deviceinfo_year="2024"
deviceinfo_chassis="handset"
deviceinfo_arch="aarch64"
`

func parse(t *testing.T, out string) *Recon {
	t.Helper()
	return Parse(out, distro.Builtin())
}

func TestParseInstalledSystem(t *testing.T) {
	r := parse(t, collected)

	if r.OS.ID != "postmarketos" || r.OS.PrettyName != "postmarketOS edge" {
		t.Errorf("os-release = %+v", r.OS)
	}
	// A rolling release is only distinguishable by its build id, so Describe
	// must carry it.
	if got := r.OS.Describe(); got != "postmarketOS edge (build 20240612-0132)" {
		t.Errorf("OS.Describe() = %q", got)
	}
	if got := r.OS.IDLike(); len(got) != 1 || got[0] != "alpine" {
		t.Errorf("IDLike() = %v", got)
	}
	if r.Kernel.Release != "6.6.32-postmarketos-qcom-sm6225" || r.Kernel.Machine != "aarch64" {
		t.Errorf("kernel = %+v", r.Kernel)
	}
	// The common shell fields are there too, via the embedded recon.
	if r.Hostname != "fogona" || r.UID != 1000 || len(r.Partitions) != 3 {
		t.Errorf("shell recon = %+v", r.ShellRecon)
	}
}

func TestDistroProfileClaimsTheDevice(t *testing.T) {
	r := parse(t, collected)

	if r.Distro == nil || r.Distro.ID() != "postmarketos" {
		t.Fatalf("distro = %v, want the postmarketOS profile", r.Distro)
	}
	if r.DistroName() != "postmarketOS" {
		t.Errorf("DistroName() = %q", r.DistroName())
	}
	// pmOS names device packages "<vendor>-<codename>"; the catalog is keyed by
	// the codename alone.
	if got := r.Codename(); got != "fogona" {
		t.Errorf("Codename() = %q, want fogona", got)
	}
	if got := r.VendorID(); got != "motorola" {
		t.Errorf("VendorID() = %q, want motorola", got)
	}
	if r.Claim.Name != "Motorola Moto G Play (2024)" || r.Claim.Manufacturer != "Motorola" {
		t.Errorf("claim = %+v", r.Claim)
	}
	// The report says which file made the claim.
	if r.Claim.From != "/usr/share/deviceinfo/deviceinfo" {
		t.Errorf("claim came from %q", r.Claim.From)
	}
	if len(r.Missing) != 0 {
		t.Errorf("preconditions reported on a complete install: %v", r.Missing)
	}
}

// An install with no device package: the distribution is still identified, the
// codename still comes from the device tree, and what is missing is named along
// with the fix.
func TestInstallWithoutDeviceInfo(t *testing.T) {
	r := parse(t, strings.Split(collected, "===unbrick:distro-files===")[0]+"===unbrick:distro-files===\n")

	if r.Distro == nil {
		t.Fatal("distro profile not matched without a deviceinfo file")
	}
	if r.Claim.Codename != "" {
		t.Errorf("claim codename = %q, want none", r.Claim.Codename)
	}
	if got := r.Codename(); got != "fogona" {
		t.Errorf("Codename() = %q, want the device tree's answer", got)
	}
	if len(r.Missing) != 1 {
		t.Fatalf("preconditions = %v, want one", r.Missing)
	}
	if !strings.Contains(r.Missing[0].Fix, "device-") {
		t.Errorf("precondition names no package to install: %+v", r.Missing[0])
	}
}

// A distribution no profile claims is not a failed recon: everything that does
// not depend on the distribution is still collected and derived.
func TestUnknownDistribution(t *testing.T) {
	r := parse(t, strings.Replace(collected, "ID=postmarketos", "ID=nixos", 1))

	if r.Distro != nil {
		t.Errorf("distro = %v, want nil for an unclaimed id", r.Distro.ID())
	}
	if got := r.Codename(); got != "fogona" {
		t.Errorf("Codename() = %q, want the device tree's answer", got)
	}
	if got := r.Slot(); got != "a" {
		t.Errorf("Slot() = %q", got)
	}
	if len(r.Partitions) != 3 {
		t.Errorf("partitions = %d, want the table regardless of distribution", len(r.Partitions))
	}
}

// What a helper being installed, versus proving it needs no password, means for
// a read. doas that prompts is unusable (it reads only from a terminal, and an
// ssh session has none); sudo that prompts is usable, since it takes the
// password on stdin.
func TestElevationStates(t *testing.T) {
	noPasswordless := strings.Replace(collected, "===unbrick:elevate-ok===\ndoas\n", "===unbrick:elevate-ok===\n", 1)

	doasOnly := parse(t, strings.Replace(noPasswordless, "doas\nsudo\n", "doas\n", 1))
	if doasOnly.Elevate != "doas" || doasOnly.ElevateOK != "" {
		t.Errorf("elevate/elevate-ok = %q/%q", doasOnly.Elevate, doasOnly.ElevateOK)
	}
	if doasOnly.CanReadPartitions() {
		t.Error("CanReadPartitions() = true with only a prompting doas")
	}

	// The stock postmarketOS login: sudo installed, wants a password.
	sudoOnly := parse(t, strings.Replace(noPasswordless, "doas\nsudo\n", "sudo\n", 1))
	if !sudoOnly.CanReadPartitions() {
		t.Error("CanReadPartitions() = false with a prompting sudo, which takes a password on stdin")
	}

	// Root needs no helper at all.
	asRoot := parse(t, strings.Replace(noPasswordless, "uid=1000", "uid=0", 1))
	if !asRoot.CanReadPartitions() {
		t.Error("CanReadPartitions() = false as root")
	}

	// And a passwordless helper is the simple case.
	if !parse(t, collected).CanReadPartitions() {
		t.Error("CanReadPartitions() = false with passwordless doas")
	}
}

// The collection script asks for every device-definition file the table knows,
// so a distribution added to the table is read without a code change — and it
// asks for paths only, never a command from data.
func TestCollectScriptAsksForTableFiles(t *testing.T) {
	set := distro.New([]*distro.Distro{{
		Ident: "exampleos",
		Files: []distro.FileSpec{{Path: "/etc/exampleos-device"}},
	}})
	script := collectScript(set)

	for _, want := range []string{"/etc/exampleos-device", "/usr/share/deviceinfo/deviceinfo"} {
		if !strings.Contains(script, want) {
			t.Errorf("script does not read %s", want)
		}
	}
	// Each path is quoted where it is interpolated, so a table entry cannot
	// become a command.
	if !strings.Contains(script, "'/etc/exampleos-device'") {
		t.Error("a table path was interpolated unquoted")
	}
}

func TestParseDistroFiles(t *testing.T) {
	got := parseDistroFiles("##/etc/one\nalpha=1\n##/etc/two\nbeta=2\n")
	if got["/etc/one"] != "alpha=1" || got["/etc/two"] != "beta=2" {
		t.Errorf("parseDistroFiles = %q", got)
	}
	if len(parseDistroFiles("")) != 0 {
		t.Error("an empty section yielded files")
	}
}

func TestParseEmpty(t *testing.T) {
	r := parse(t, "")
	if r.Codename() != "" || r.Distro != nil || len(r.Partitions) != 0 {
		t.Errorf("empty collection yielded %+v", r)
	}
	if r.OS.Describe() != "" {
		t.Errorf("OS.Describe() = %q off nothing", r.OS.Describe())
	}
}
