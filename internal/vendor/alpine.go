package vendor

import (
	"path"
	"regexp"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// alpine: Alpine Electronics head-unit firmware, packaged in Fujitsu Ten's OTA
// container -- a zip (seen named e.g. fjhdmi20.update) holding exactly three
// PKWARE-encrypted members: a sha512 manifest (fbdmisha512), an inventory
// (update.ini, whose MODEL_TYPE line names the release), and the payload
// (update.zip: an Android OTA -- boot.img/recovery.img/system.img -- over a
// Telechips lk.rom/dtb.img, hence PlatformTelechips). Only recognition and the
// container's password; there is no recovery path.
//
// All three members share one password. Confirmed so far only for the
// iLX-F411/iLX-F409 V1.3.13 (2022.03.08) release, by brute force (no known
// derivation): "FBDMI", which turns out to equal that release's own
// MODEL_TYPE. Whether that is the rule (another model's fixed password being
// its own model code) or this one release's coincidence is unconfirmed --
// this is what has been seen, not a derivation, so it is tried everywhere
// this container shape appears and may simply fail on a different model.
type alpine struct{}

func init() { Register(alpine{}) }

func (alpine) ID() string                 { return "alpine" }
func (alpine) Platform() string           { return PlatformTelechips }
func (alpine) OEMIDs() []string           { return nil }
func (alpine) CanIngest(path string) bool { return false }

func (alpine) IngestDonor(string) (*blankflash.Donor, error) { return nil, ErrUnsupported }
func (alpine) HarvestStock(TargetSource) (*blankflash.Target, error) {
	return nil, ErrUnsupported
}
func (alpine) Assemble(*blankflash.Donor, *blankflash.Target, AssembleOptions) (*blankflash.ForgeResult, error) {
	return nil, ErrUnsupported
}

// AlpineVersion is this file's own cache.VersionFuncs entry (cmd_recon_registry.go):
// raise it whenever ZipPasswords, ParseFjhdmiUpdateIni or ParseFjhdmiManifest
// changes what they'd report for bytes already seen.
const AlpineVersion = 1

// fjhdmiPasswords are every password confirmed for this container so far
// (one, for now): tried regardless of model, since nothing yet says the
// password varies by one.
var fjhdmiPasswords = []string{"FBDMI"}

// isFjhdmiMember says whether name is one of this container's three fixed
// members (its base name, however deep the member sits).
func isFjhdmiMember(name string) bool {
	switch strings.ToLower(path.Base(name)) {
	case "fbdmisha512", "update.ini", "update.zip":
		return true
	}
	return false
}

// ZipPasswords implements ZipPassworder. It cannot read zip's own children to
// confirm the container's shape (ZipPasswords is called while zip's children
// are still being expanded, from the same call), so it keys purely off the
// member's own name -- distinctive enough, and harmless to try even where it
// happens not to apply: a wrong candidate just fails the header check like
// any other vendor's guess would.
func (alpine) ZipPasswords(_ *carve.Node, member string) []string {
	if !isFjhdmiMember(member) {
		return nil
	}
	return fjhdmiPasswords
}

// FjhdmiInfo is update.ini's own account of the release it ships: a handful
// of "#KEY = VALUE" lines, SYSTEM_UPDATE/MICOM_UPDATE being "1"/"0" flags
// rather than free text.
type FjhdmiInfo struct {
	ModelType     string
	UpdateVersion string
	SystemUpdate  bool
	MicomUpdate   bool
}

var fjhdmiIniLine = regexp.MustCompile(`(?m)^\s*#\s*([A-Za-z_]+)\s*=\s*(.*?)\s*$`)

// ParseFjhdmiUpdateIni reads update.ini's "#KEY = VALUE" lines. Unrecognised
// keys are ignored; a missing one leaves its field zero rather than erroring,
// since every field here is cosmetic (nothing downstream depends on all four
// being present).
func ParseFjhdmiUpdateIni(data []byte) FjhdmiInfo {
	var info FjhdmiInfo
	for _, m := range fjhdmiIniLine.FindAllSubmatch(data, -1) {
		key, val := strings.ToUpper(string(m[1])), string(m[2])
		switch key {
		case "MODEL_TYPE":
			info.ModelType = val
		case "UPDATE_VERSION":
			info.UpdateVersion = val
		case "SYSTEM_UPDATE":
			info.SystemUpdate = val == "1"
		case "MICOM_UPDATE":
			info.MicomUpdate = val == "1"
		}
	}
	return info
}

// FjhdmiManifestEntry is one line of fbdmisha512: the sha512 of Name (a
// "./"-relative path, a sibling member of fbdmisha512 itself), in the
// sha512sum -b output format ("<128 hex> *<name>", binary mode marked by the
// "*"; a plain sha512sum's single-space two-char separator is accepted too).
type FjhdmiManifestEntry struct {
	Hash string // lowercase hex, 128 chars
	Name string // as written, "./update.zip" for example
}

var fjhdmiManifestLine = regexp.MustCompile(`(?m)^([0-9a-fA-F]{128})[ \t]+\*?(\S+)\s*$`)

// ParseFjhdmiManifest reads fbdmisha512's lines.
func ParseFjhdmiManifest(data []byte) []FjhdmiManifestEntry {
	var out []FjhdmiManifestEntry
	for _, m := range fjhdmiManifestLine.FindAllSubmatch(data, -1) {
		out = append(out, FjhdmiManifestEntry{Hash: strings.ToLower(string(m[1])), Name: string(m[2])})
	}
	return out
}
