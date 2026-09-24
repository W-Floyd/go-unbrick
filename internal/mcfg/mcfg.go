// Package mcfg reads a Qualcomm modem configuration blob (mcfg_sw.mbn /
// mcfg_hw.mbn). Each is an ELF wrapping an "MCFG" payload: a header naming the
// config type and item count, a run of NV-item records, and an "MCFG_TRL"
// trailer whose TLV items carry the human identity — the carrier/profile name
// this config is built for. That name is what ties a modem image to a carrier
// (a software config like "W-One") or a hardware variant ("cmcc_subsidized-Divar").
package mcfg

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"sort"
	"strings"
)

// Config is the identity extracted from an MCFG blob.
type Config struct {
	SW       bool   // config_type: software (carrier) vs hardware (platform) config
	NumItems int    // NV items the config sets
	Profile  string // trailer name: the carrier ("W-One") or HW variant profile
	APNs     []string
}

var (
	mcfgMagic = []byte("MCFG")
	mcfgTrl   = []byte("MCFG_TRL")
	// APNs appear as data-profile domain tokens; qualcomm.com is the loopback
	// ePDG test FQDN, not a carrier APN, so it is filtered out.
	apnRe = regexp.MustCompile(`\b[a-z0-9][a-z0-9.\-]*\.(?:com|net|org)\b`)
)

// Parse reads an mcfg blob out of its .mbn (ELF) wrapper. Returns false if the
// bytes carry no MCFG payload.
func Parse(data []byte) (*Config, bool) {
	i := bytes.Index(data, mcfgMagic)
	// Skip a spurious hit inside "MCFG_TRL" if the real header is elsewhere.
	for i >= 0 && bytes.HasPrefix(data[i:], mcfgTrl) {
		next := bytes.Index(data[i+4:], mcfgMagic)
		if next < 0 {
			i = -1
			break
		}
		i += 4 + next
	}
	if i < 0 || i+12 > len(data) {
		return nil, false
	}
	blob := data[i:]
	c := &Config{
		SW:       binary.LittleEndian.Uint16(blob[6:8]) == 1,
		NumItems: int(binary.LittleEndian.Uint32(blob[8:12])),
	}
	c.Profile = trailerName(blob)
	c.APNs = apns(blob)
	return c, true
}

// trailerName reads the profile name from the MCFG_TRL trailer: a TLV
// {type 0x03, len u16 LE, value} whose value is the printable carrier/variant
// name. The surrounding items carry version words rather than a fixed layout, so
// the name is found by its tag and a printable, sensibly-sized value.
func trailerName(blob []byte) string {
	t := bytes.Index(blob, mcfgTrl)
	if t < 0 {
		return ""
	}
	tr := blob[t:]
	for p := 8; p+3 <= len(tr); p++ {
		if tr[p] != 0x03 {
			continue
		}
		ln := int(binary.LittleEndian.Uint16(tr[p+1 : p+3]))
		if ln < 2 || ln > 64 || p+3+ln > len(tr) {
			continue
		}
		v := tr[p+3 : p+3+ln]
		if printable(v) {
			return strings.TrimRight(string(v), "\x00")
		}
	}
	return ""
}

func printable(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 || c > 0x7e) && c != 0 {
			return false
		}
	}
	return len(b) > 0 && b[0] >= 0x20
}

// apns returns the distinct access-point names the config's data profiles set.
func apns(blob []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range apnRe.FindAll(blob, -1) {
		a := string(m)
		if seen[a] || strings.HasSuffix(a, "qualcomm.com") {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
