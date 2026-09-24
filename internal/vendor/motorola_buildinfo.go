package vendor

// Parser for the Motorola "BUILD REQUEST INFO" sheet a stock package ships as
// <name>.info.txt — a plain-text summary of what the build is: the AOSP build
// fingerprint, the marketing model, and the modem/FSG/MBM component versions.
// Motorola-specific, so it lives behind the seam. It is the only member that
// carries the ro.build.fingerprint in the clear, which is the same identity a
// device reports over getvar — so it is what lets a package be checked against
// the unit in front of you.

import "regexp"

// BuildInfo is the subset of the info.txt sheet worth surfacing.
type BuildInfo struct {
	Fingerprint   string // ro.build.fingerprint, e.g. motorola/fogona_g/fogona:14/...
	MarketingName string // "moto g play - 2024"
	Modem         string // baseband/modem version
	FSG           string
	MBM           string // bootloader (MBM) version
	BuildDate     string
	ABUpdate      string // "AB Update Enabled" value, "" if the sheet omits it
}

var biField = map[string]*regexp.Regexp{
	"fp":     regexp.MustCompile(`(?m)^Build Fingerprint:\s*(.+?)\s*$`),
	"model":  regexp.MustCompile(`(?m)^Model Number:\s*(.+?)\s*$`),
	"modem":  regexp.MustCompile(`(?m)^Modem Version:\s*(.+?)\s*$`),
	"fsg":    regexp.MustCompile(`(?m)^FSG Version:\s*(.+?)\s*$`),
	"mbm":    regexp.MustCompile(`(?m)^MBM Version:\s*(.+?)\s*$`),
	"date":   regexp.MustCompile(`(?m)^Build Date:\s*(.+?)\s*$`),
	"ab":     regexp.MustCompile(`(?m)^AB Update Enabled:\s*(.+?)\s*$`),
	"marker": regexp.MustCompile(`BUILD REQUEST INFO:|Build Fingerprint:`),
}

// ParseBuildInfo reads an info.txt sheet. Returns nil if it is not one (no build
// marker), so it doubles as the recognizer's content test.
func ParseBuildInfo(data []byte) *BuildInfo {
	if !biField["marker"].Match(data) {
		return nil
	}
	first := func(key string) string {
		if m := biField[key].FindSubmatch(data); m != nil {
			return string(m[1])
		}
		return ""
	}
	bi := &BuildInfo{
		Fingerprint:   first("fp"),
		MarketingName: first("model"),
		Modem:         first("modem"),
		FSG:           first("fsg"),
		MBM:           first("mbm"),
		BuildDate:     first("date"),
		ABUpdate:      first("ab"),
	}
	// A sheet with none of the fields we care about is not worth a fact.
	if bi.Fingerprint == "" && bi.MarketingName == "" && bi.Modem == "" {
		return nil
	}
	return bi
}

// MBMDate pulls the YYMMDD build date embedded in an MBM version string
// (MBM-3.0-<codename>-<hash>-<date>-<build>), or "" if not present. The same
// date the on-device MBM stamps into each boot partition.
var mbmDateRe = regexp.MustCompile(`-(\d{6})-`)

func (b *BuildInfo) MBMDate() string {
	if m := mbmDateRe.FindStringSubmatch(b.MBM); m != nil {
		return m[1]
	}
	return ""
}
