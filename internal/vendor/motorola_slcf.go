package vendor

// Motorola subsidy-lock config (SLCF) parser. A stock package ships it as
// subsidy_lock_config (slcf_*.nvm): a newline-separated list of NV-write records
// in ASCII hex, with "<CK-N>" placeholders marking where the N-digit carrier
// unlock control key is substituted at provisioning. Records set the subsidy NV
// items and carry the MCC/MNC (PLMN) networks the device is locked to.
//
// This is Motorola-specific (other vendors lock differently), so it lives behind
// the vendor seam. It surfaces what the lock means — enabled or not, control-key
// length, locked networks — without Motorola's provisioning key. A zero-length
// .nvm (retail / subsidy-DEFAULT) parses as an unlocked SLCFConfig.

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// slcfNVItemNames names the subsidy NV items (little-endian after the 0x8021
// record prefix) worth calling out.
var slcfNVItemNames = map[uint16]string{
	0xea60: "subsidy-lock state",
	0xea6b: "subsidy-lock flags",
	0xea62: "subsidy-lock config (control key + PLMN list)",
}

// PLMN is one locked network (MCC + MNC), with a carrier name when known.
type PLMN struct {
	MCC, MNC string
	Carrier  string
}

func (p PLMN) String() string {
	s := p.MCC + "-" + p.MNC
	if p.Carrier != "" {
		s += " (" + p.Carrier + ")"
	}
	return s
}

// SLCFConfig is a parsed Motorola subsidy-lock config.
type SLCFConfig struct {
	Locked           bool     // any NV records present (a non-empty .nvm)
	ControlKeyDigits int      // from the <CK-N> placeholder, 0 if none
	NVItems          []uint16 // distinct subsidy NV items the file writes
	PLMNs            []PLMN   // distinct locked networks
}

var (
	slcfCKRe = regexp.MustCompile(`<CK-(\d+)>`)
	// A PLMN entry: MCC(3) 0x03 MNC(2-3), followed by a small status byte (<0x10).
	// The status filter rejects numeric runs from other fields (e.g. an id whose
	// digits happen to look like MCC/MNC but are followed by high bytes).
	slcfPLMNRe = regexp.MustCompile(`(\d{3})\x03(\d{2,3})[\x00-\x0f]`)
)

// ParseSLCF reads an slcf_*.nvm. An empty file (retail default) yields Locked=false.
func ParseSLCF(data []byte) (*SLCFConfig, error) {
	c := &SLCFConfig{}
	itemSeen := map[uint16]bool{}
	plmnSeen := map[string]bool{}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		c.Locked = true

		if m := slcfCKRe.FindStringSubmatch(line); m != nil {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			if n > c.ControlKeyDigits {
				c.ControlKeyDigits = n
			}
		}
		// Drop the placeholder(s); each surrounding hex run is even-length, so the
		// remaining hex stays byte-aligned for NV-id and PLMN extraction.
		raw, err := hex.DecodeString(slcfCKRe.ReplaceAllString(line, ""))
		if err != nil {
			return nil, fmt.Errorf("slcf: record is not hex: %w", err)
		}
		if len(raw) >= 4 && raw[0] == 0x80 && raw[1] == 0x21 {
			id := uint16(raw[2]) | uint16(raw[3])<<8
			if !itemSeen[id] {
				itemSeen[id] = true
				c.NVItems = append(c.NVItems, id)
			}
		}
		for _, m := range slcfPLMNRe.FindAllSubmatch(raw, -1) {
			mcc, mnc := string(m[1]), string(m[2])
			if key := mcc + mnc; !plmnSeen[key] {
				plmnSeen[key] = true
				c.PLMNs = append(c.PLMNs, PLMN{MCC: mcc, MNC: mnc, Carrier: plmnCarrier(mcc, mnc)})
			}
		}
	}
	sort.Slice(c.PLMNs, func(i, j int) bool {
		return c.PLMNs[i].MCC+c.PLMNs[i].MNC < c.PLMNs[j].MCC+c.PLMNs[j].MNC
	})
	return c, nil
}

// SLCFNVItemName names a subsidy NV item, or "" if not one we track.
func SLCFNVItemName(id uint16) string { return slcfNVItemNames[id] }

// knownPLMN maps common US MCC-MNC pairs to a carrier name, enough to make a
// subsidy-lock list readable. Not exhaustive; unknown PLMNs show as raw codes.
var knownPLMN = map[string]string{
	"310240": "T-Mobile", "310260": "T-Mobile", "310160": "T-Mobile",
	"310200": "T-Mobile", "310210": "T-Mobile", "310220": "T-Mobile",
	"310230": "T-Mobile", "310250": "T-Mobile", "310270": "T-Mobile",
	"310310": "T-Mobile", "310490": "T-Mobile", "310530": "T-Mobile",
	"310660": "T-Mobile", "310800": "T-Mobile", "311882": "T-Mobile (Metro)",
	"311480": "Verizon", "310004": "Verizon", "310010": "Verizon", "311270": "Verizon",
	"310410": "AT&T", "310150": "AT&T", "310170": "AT&T", "310280": "AT&T",
	"310380": "AT&T", "311180": "AT&T", "312670": "AT&T (FirstNet)",
}

func plmnCarrier(mcc, mnc string) string { return knownPLMN[mcc+mnc] }
