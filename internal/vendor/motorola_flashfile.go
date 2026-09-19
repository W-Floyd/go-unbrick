package vendor

// Motorola stock-package manifest (flashfile.xml) reader. It is the authoritative
// source for what a package targets — notably cid_value, the carrier CID the
// bootloader matches against, which is NOT the same as the CID baked into the
// vbmeta HAB_META property (that one is a signing/base value, constant across a
// device's carrier variants). Motorola-specific, so it lives behind the seam.

import "regexp"

// Flashfile is the subset of flashfile.xml worth surfacing.
type Flashfile struct {
	CIDValue        string // authoritative carrier CID, e.g. "0x0033"
	SoftwareVersion string // full build string
	SubsidyLock     string // subsidy_lock_config name (slcf_*.nvm), "" if none
	CIDTemplate     string // cid_template_config name
}

var (
	ffCIDRe      = regexp.MustCompile(`cid_value\s+value="([^"]+)"`)
	ffSWRe       = regexp.MustCompile(`software_version\s+version="([^"]+)"`)
	ffSubsidyRe  = regexp.MustCompile(`subsidy_lock_config\b[^>]*\bname="([^"]+)"`)
	ffTemplateRe = regexp.MustCompile(`cid_template_config\b[^>]*\bname="([^"]+)"`)
)

// ParseFlashfile extracts the key fields from a flashfile.xml.
func ParseFlashfile(data []byte) *Flashfile {
	first := func(re *regexp.Regexp) string {
		if m := re.FindSubmatch(data); m != nil {
			return string(m[1])
		}
		return ""
	}
	return &Flashfile{
		CIDValue:        first(ffCIDRe),
		SoftwareVersion: first(ffSWRe),
		SubsidyLock:     first(ffSubsidyRe),
		CIDTemplate:     first(ffTemplateRe),
	}
}
