package vendor

// Motorola stock-package manifest (flashfile.xml) reader. It is the authoritative
// source for what a package targets — notably cid_value, the carrier CID the
// bootloader matches against, which is NOT the same as the CID baked into the
// vbmeta HAB_META property (that one is a signing/base value, constant across a
// device's carrier variants). Motorola-specific, so it lives behind the seam.

import (
	"regexp"
	"strings"
)

// Flashfile is the subset of flashfile.xml worth surfacing.
type Flashfile struct {
	CIDValue        string // authoritative carrier CID, e.g. "0x0033"
	SoftwareVersion string // full build string
	SubsidyLock     string // subsidy_lock_config name (slcf_*.nvm), "" if none
	CIDTemplate     string // cid_template_config name
}

// MemberDigest is one member the manifest names together with the digest it
// declares for it — from a <step> or a *_config entry. Algo is "md5" or "sha1".
type MemberDigest struct {
	Name string
	Algo string
	Hex  string // lowercase expected digest
}

var (
	ffMD5AttrRe  = regexp.MustCompile(`\bMD5="([0-9a-fA-F]{32})"`)
	ffSHA1AttrRe = regexp.MustCompile(`\bSHA1="([0-9a-fA-F]{40})"`)
	ffNameAttrRe = regexp.MustCompile(`\b(?:filename|name)="([^"]+)"`)
	ffTagRe      = regexp.MustCompile(`<[a-z_]+\b[^>]*/>`)
)

// FlashfileDigests returns every (member, digest) the manifest declares, so a
// package's members can be checked against what it says they should be. A tag
// with a digest but no filename, or with only a SHA1 of empty content (an absent
// eLabel), is skipped — there is nothing to verify.
func FlashfileDigests(data []byte) []MemberDigest {
	const sha1Empty = "da39a3ee5e6b4b0d3255bfef95601890afd80709" // SHA1("")
	var out []MemberDigest
	seen := map[string]bool{}
	for _, tag := range ffTagRe.FindAll(data, -1) {
		nm := ffNameAttrRe.FindSubmatch(tag)
		if nm == nil {
			continue
		}
		name := string(nm[1])
		var d MemberDigest
		if m := ffMD5AttrRe.FindSubmatch(tag); m != nil {
			d = MemberDigest{Name: name, Algo: "md5", Hex: strings.ToLower(string(m[1]))}
		} else if m := ffSHA1AttrRe.FindSubmatch(tag); m != nil {
			hex := strings.ToLower(string(m[1]))
			if hex == sha1Empty {
				continue
			}
			d = MemberDigest{Name: name, Algo: "sha1", Hex: hex}
		} else {
			continue
		}
		key := d.Name + d.Hex
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
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
