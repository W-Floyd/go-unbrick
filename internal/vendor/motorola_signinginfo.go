package vendor

// Parser for Motorola's signing-info.txt (a stock-package member): the HAB
// secure-boot binding — product, signing CID, security (anti-rollback) version,
// customer region, OTA key path, the region→CID map, and the per-image
// anti-rollback version table. Motorola-specific, so it lives behind the seam.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SigningInfo is the parsed signing-info.txt.
type SigningInfo struct {
	Product         string
	Region          string
	OTAKey          string
	HABCID          int // signing/base CID (decimal), -1 if absent
	SecurityVersion int // HAB anti-rollback version, -1 if absent
	CustomerSigned  bool
	RegionCIDs      map[string]int // e.g. Retail->50, RetailLocked->51
	EnforceOTARoll  bool           // enforce_anti_rollback_check_in_ota
	Rollback        map[string]int // image name -> anti-rollback version
	RollbackBumped  []string       // images whose version is non-zero
}

var (
	siKV     = regexp.MustCompile(`^(HAB_PRODUCT|HAB_SECURITY_VERSION|HAB_CID|HAB_CUSTOMER_REGION|OTA_KEY)\s+(.+)$`)
	siRegion = regexp.MustCompile(`^(\w+)\s*=>\s*(\d+)\s*$`)
	siRoll   = regexp.MustCompile(`^([\w.]+)=0x([0-9a-fA-F]+)\s*$`)
)

// ParseSigningInfo reads signing-info.txt. Returns nil if it has no HAB fields.
func ParseSigningInfo(data []byte) *SigningInfo {
	si := &SigningInfo{HABCID: -1, SecurityVersion: -1, RegionCIDs: map[string]int{}, Rollback: map[string]int{}}
	inRoll := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "[anti_rollback_version_begin]":
			inRoll = true
			continue
		case line == "[anti_rollback_version_end]":
			inRoll = false
			continue
		case strings.HasPrefix(line, "enforce_anti_rollback_check_in_ota="):
			si.EnforceOTARoll = strings.HasSuffix(line, "true")
			continue
		case strings.Contains(line, "customer signed"):
			si.CustomerSigned = true
			continue
		}
		if inRoll {
			if m := siRoll.FindStringSubmatch(line); m != nil {
				v, _ := strconv.ParseInt(m[2], 16, 32)
				si.Rollback[m[1]] = int(v)
				if v != 0 {
					si.RollbackBumped = append(si.RollbackBumped, m[1])
				}
			}
			continue
		}
		if m := siKV.FindStringSubmatch(line); m != nil {
			val := strings.TrimSpace(m[2])
			switch m[1] {
			case "HAB_PRODUCT":
				si.Product = val
			case "HAB_CUSTOMER_REGION":
				si.Region = val
			case "OTA_KEY":
				si.OTAKey = val
			case "HAB_CID":
				si.HABCID, _ = strconv.Atoi(val)
			case "HAB_SECURITY_VERSION":
				si.SecurityVersion, _ = strconv.Atoi(val)
			}
			continue
		}
		if m := siRegion.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[2])
			si.RegionCIDs[m[1]] = n
		}
	}
	if si.Product == "" && si.HABCID < 0 && si.SecurityVersion < 0 {
		return nil
	}
	sort.Strings(si.RollbackBumped)
	return si
}
