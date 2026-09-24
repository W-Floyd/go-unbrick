package library

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"
)

// The harvester names its copies <sha256[:16]>_<md5[:16]>_<original name>.
// bkerler/Loaders names share the shape but lead with a real HW_ID, so the
// prefix is only a harvest prefix when it matches the file's own digests.
var reHarvestPrefix = regexp.MustCompile(`^([0-9a-f]{16})_([0-9a-f]{16})_(.+)$`)

// OriginalName strips a verified harvest prefix from name; ok reports whether
// one was stripped. raw is the file as the harvester hashed it.
func OriginalName(name string, raw []byte) (string, bool) {
	base := filepath.Base(name)
	m := reHarvestPrefix.FindStringSubmatch(base)
	if m == nil {
		return base, false
	}
	s := sha256.Sum256(raw)
	d := md5.Sum(raw)
	if hex.EncodeToString(s[:])[:16] != m[1] && hex.EncodeToString(d[:])[:16] != m[2] {
		return base, false
	}
	return m[3], true
}

// FamilyJTAG is the JTAG a loader is filed under: the cert's, else the one a
// bkerler-style name leads with (<HW_ID>_<cert hash>_…), else 00000000. name
// must already be free of any harvest prefix (see OriginalName).
func FamilyJTAG(certJTAG, name string) string {
	if certJTAG != "" && certJTAG != "00000000" {
		return strings.ToUpper(certJTAG)
	}
	first, _, _ := strings.Cut(filepath.Base(name), "_")
	if len(first) == 16 && isHexString(first) && strings.Trim(first[:8], "0") != "" {
		return strings.ToUpper(first[:8])
	}
	return "00000000"
}

func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
