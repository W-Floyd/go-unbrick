package fastboot

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/library"
)

// SlotInfo describes the status of a specific A/B slot.
type SlotInfo struct {
	Slot       string
	Successful bool
	Unbootable bool
	RetryCount int
}

// Bootable reports whether the bootloader can still select this slot. The
// slot-unbootable flag is not the whole answer: a slot that has never booted
// successfully and has no retries left is one the bootloader will pass over,
// even though nothing has marked it unbootable yet.
func (s SlotInfo) Bootable() bool {
	return !s.Unbootable && (s.Successful || s.RetryCount > 0)
}

// DeviceRecon represents extracted parameters from a fastboot getvar all query.
type DeviceRecon struct {
	Serial            string
	Product           string
	HWRev             string
	SKU               string
	CarrierID         string
	ChannelID         string
	Carrier           string
	UID               string
	JTAGID            string
	ChipID            string
	IMEI              string
	FRPState          string
	VerityState       string
	CPU               string
	StorageType       string
	RAM               string
	BatteryVoltage    string
	BatterySocOK      string
	Secure            bool
	Unlocked          bool
	SecureState       string
	IsUserspace       bool // true if running inside recovery fastbootd, false if in bootloader ABL
	CurrentSlot       string
	SlotCount         int
	SlotStatus        map[string]*SlotInfo
	DisplayID         string
	Fingerprint       string
	Baseband          string
	BootloaderVersion string
	XBLBuild          string
	HardwareFeatures  *OEMHardwareInfo
	SecurityVersions  *SecurityVersions
	LivePartitions    []PartitionDetail
	UnpopulatedSlotB  bool
	UnpopulatedParts  []string
	PartitionSizes    map[string]uint64
	// PartitionFacts holds what the bootloader itself says about the partitions
	// whose classification was inferred rather than read — the dynamic ones and
	// the empty ones. Absent for partitions that were never in doubt.
	PartitionFacts map[string]PartitionFacts
	// ComponentBuilds maps each boot-chain partition to the MBM stamp it reports
	// under git:<name>. Every component of one release shares a build date, so a
	// date that disagrees with the rest is a partially flashed chain — something
	// the single version-bootloader string cannot show.
	ComponentBuilds map[string]string
	// QCBaseline is ro.build.version.qcom, the Qualcomm LA vendor baseline. It
	// names the SoC family independently of the qboot cpu_name label.
	QCBaseline string
	// Flashing geometry, all as the bootloader reports it: the largest single
	// transfer it will accept, the sparse chunk size it wants, and the storage
	// block sizes a rawprogram must be aligned to.
	MaxDownloadSize  uint64
	MaxSparseSize    uint64
	LogicalBlockSize uint64
	EraseBlockSize   uint64
	BootLUN          string // running-boot-lun: which UFS LUN the live boot chain is in
	// Factory provenance and security posture, none of it derivable from firmware.
	ManufactureDate string
	BattID          string
	PCBPartNo       string
	PrimaryDisplay  string
	LCSState        string
	TokenState      string
	FactoryModes    string
	WarrantyVoid    string
	FDRAllowed      string
	BootReason      string
	RawVars         map[string]string
}

// reVarIndex matches the [n] suffix fastboot appends when a value is split
// across several lines ("git:abl[0]").
var reVarIndex = regexp.MustCompile(`\[\d+\]$`)

// parseSize reads a bootloader-reported size, which may be hex or decimal.
func parseSize(val string) uint64 {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(strings.ToLower(val), "0x") {
		n, _ := strconv.ParseUint(val[2:], 16, 64)
		return n
	}
	n, _ := strconv.ParseUint(val, 10, 64)
	return n
}

// OEMHardwareInfo is the parsed output of `oem hw`. Despite the name, `oem hw`
// is Motorola's utags editor (the utags/utagsBackup partition), not a hardware
// query: bare or `oem hw <name>` it reads, but `oem hw <name> <value>`, `+`, `-`,
// `clear` and `lock` all WRITE. Only ever call it with no arguments — the sensor
// bits and UTags below are read from that listing.
type OEMHardwareInfo struct {
	DualSIM   bool
	ECompass  bool
	ESIM      bool
	FPS       bool // Fingerprint sensor
	NFC       bool
	RadioType string
	// UTags is every utag the SKU declares (from `.features`), each with the value
	// this unit carries and the range of values the family ships. This is the
	// configuration matrix reported by the device itself — the same variant space
	// the catalog otherwise infers from firmware filenames.
	UTags []UTag
}

// UTag is one Motorola utag from `oem hw`: its value on this unit, the options the
// family offers (`.range`), and, when the value is autodetected from the fused
// HW_ID rather than chosen, the rule that derives it (`.auto`, e.g.
// "key=hwid;index=2;map=1:ATT,2:RET").
type UTag struct {
	Name    string
	Value   string
	Range   []string // sibling configurations, e.g. ["4GB","6GB"]
	HWIDMap string   // the `.auto` derivation rule, when it keys off hwid
}

// SecurityVersions contains anti-rollback and security version indices from 'oem read_sv'.
type SecurityVersions struct {
	VbmetaRIL int
	RIL0      int
	RIL2      int
	RawLines  []string
}

// PartitionDetail describes a partition entry from 'oem partition'.
type PartitionDetail struct {
	Name     string
	OffsetKB uint64
	SizeKB   uint64
	IsSuper  bool // true if dynamic partition inside 'super'
}

// ParseGetVarOutput parses the stdout/stderr lines of 'fastboot getvar all'.
// Handles standard "(bootloader) key: value", "key: value", and multiline array entries.
func ParseGetVarOutput(text string) *DeviceRecon {
	recon := &DeviceRecon{
		SlotStatus:      make(map[string]*SlotInfo),
		PartitionSizes:  make(map[string]uint64),
		ComponentBuilds: make(map[string]string),
		RawVars:         make(map[string]string),
	}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "all:") || strings.HasPrefix(trimmed, "finished.") {
			continue
		}

		// Strip "(bootloader) " prefix if present
		trimmed = strings.TrimPrefix(trimmed, "(bootloader)")
		trimmed = strings.TrimSpace(trimmed)

		var key, val string
		if idx := strings.Index(trimmed, ": "); idx >= 0 {
			key = strings.TrimSpace(trimmed[:idx])
			val = strings.TrimSpace(trimmed[idx+2:])
		} else if idx := strings.Index(trimmed, ":"); idx >= 0 {
			key = strings.TrimSpace(trimmed[:idx])
			val = strings.TrimSpace(trimmed[idx+1:])
		} else {
			continue
		}
		if key == "" {
			continue
		}

		recon.RawVars[key] = val
		keyLower := strings.ToLower(key)

		switch {
		case keyLower == "product":
			recon.Product = val
		case keyLower == "hwrev":
			recon.HWRev = val
		case keyLower == "sku":
			recon.SKU = val
		case keyLower == "cid":
			recon.CarrierID = val
		case keyLower == "channelid":
			recon.ChannelID = val
		case keyLower == "cpu":
			recon.CPU = val
		case keyLower == "storage-type":
			recon.StorageType = strings.ToLower(val)
		case keyLower == "ram":
			recon.RAM = val
		case keyLower == "battery-voltage":
			recon.BatteryVoltage = val
		case keyLower == "battery-soc-ok":
			recon.BatterySocOK = val
		case keyLower == "secure":
			recon.Secure = strings.EqualFold(val, "yes") || strings.EqualFold(val, "true")
		case keyLower == "unlocked":
			recon.Unlocked = strings.EqualFold(val, "yes") || strings.EqualFold(val, "true")
		case keyLower == "securestate":
			recon.SecureState = val
			if strings.Contains(strings.ToLower(val), "unlocked") {
				recon.Unlocked = true
			}
		case keyLower == "is-userspace":
			recon.IsUserspace = strings.EqualFold(val, "yes") || strings.EqualFold(val, "true")
		case keyLower == "current-slot":
			recon.CurrentSlot = strings.TrimPrefix(strings.ToLower(val), "_")
		case keyLower == "slot-count":
			if n, err := strconv.Atoi(val); err == nil {
				recon.SlotCount = n
			}
		case keyLower == "uid":
			recon.UID = val
			if len(val) == 16 {
				recon.JTAGID = strings.ToUpper(val[8:])
			}
		case keyLower == "chipid":
			recon.ChipID = val
		case keyLower == "imei":
			recon.IMEI = val
		case keyLower == "ro.carrier":
			recon.Carrier = val
		case keyLower == "frp-state":
			recon.FRPState = val
		case keyLower == "verity-state":
			recon.VerityState = val
		case strings.HasPrefix(keyLower, "git:"):
			// Every boot-chain partition stamps its own build here. Note the
			// exact-match on xbl: "git:xbl_config" shares the prefix and used to
			// overwrite XBLBuild, which went unnoticed only because the two
			// normally carry the same stamp.
			comp := reVarIndex.ReplaceAllString(strings.TrimPrefix(keyLower, "git:"), "")
			recon.ComponentBuilds[comp] += val
			if comp == "xbl" {
				recon.XBLBuild = recon.ComponentBuilds[comp]
			}
		case keyLower == "ro.build.version.qcom" || strings.HasPrefix(keyLower, "ro.build.version.qcom["):
			recon.QCBaseline += val
		case keyLower == "max-download-size":
			recon.MaxDownloadSize = parseSize(val)
		case keyLower == "max-sparse-size":
			recon.MaxSparseSize = parseSize(val)
		case keyLower == "logical-block-size":
			recon.LogicalBlockSize = parseSize(val)
		case keyLower == "erase-block-size":
			recon.EraseBlockSize = parseSize(val)
		case keyLower == "running-boot-lun":
			recon.BootLUN = val
		case keyLower == "date":
			recon.ManufactureDate = val
		case keyLower == "battid":
			recon.BattID = val
		case keyLower == "pcb-part-no":
			recon.PCBPartNo = val
		case keyLower == "primary-display":
			recon.PrimaryDisplay = val
		case keyLower == "lcs-state":
			recon.LCSState = val
		case keyLower == "token":
			recon.TokenState = val
		case keyLower == "factory-modes":
			recon.FactoryModes = val
		case keyLower == "iswarrantyvoid":
			recon.WarrantyVoid = val
		case keyLower == "fdr-allowed":
			recon.FDRAllowed = val
		case keyLower == "reason":
			recon.BootReason = val
		case strings.HasPrefix(keyLower, "version-bootloader"):
			if recon.BootloaderVersion == "" {
				recon.BootloaderVersion = val
			} else {
				recon.BootloaderVersion += val
			}
		case strings.HasPrefix(keyLower, "ro.build.display.id"):
			recon.DisplayID = val
		case strings.HasPrefix(keyLower, "ro.build.fingerprint"):
			if recon.Fingerprint == "" {
				recon.Fingerprint = val
			} else {
				recon.Fingerprint += val // Reconstruct split fingerprints
			}
		case strings.HasPrefix(keyLower, "version-baseband"):
			recon.Baseband = val

		// Slot attributes: slot-successful:_a, slot-unbootable:_a, slot-retry-count:_a
		case strings.HasPrefix(keyLower, "slot-successful:"):
			slot := strings.TrimPrefix(strings.TrimPrefix(key, "slot-successful:"), "_")
			slot = strings.ToLower(strings.TrimSpace(slot))
			info := recon.getOrCreateSlot(slot)
			info.Successful = strings.EqualFold(val, "yes") || strings.EqualFold(val, "true")

		case strings.HasPrefix(keyLower, "slot-unbootable:"):
			slot := strings.TrimPrefix(strings.TrimPrefix(key, "slot-unbootable:"), "_")
			slot = strings.ToLower(strings.TrimSpace(slot))
			info := recon.getOrCreateSlot(slot)
			info.Unbootable = strings.EqualFold(val, "yes") || strings.EqualFold(val, "true")

		case strings.HasPrefix(keyLower, "slot-retry-count:"):
			slot := strings.TrimPrefix(strings.TrimPrefix(key, "slot-retry-count:"), "_")
			slot = strings.ToLower(strings.TrimSpace(slot))
			info := recon.getOrCreateSlot(slot)
			if n, err := strconv.Atoi(val); err == nil {
				info.RetryCount = n
			}

		// Partition sizes: partition-size:xbl_a: 0x400000
		case strings.HasPrefix(keyLower, "partition-size:"):
			part := strings.TrimPrefix(key, "partition-size:")
			part = strings.TrimPrefix(part, " ")
			recon.PartitionSizes[part] = parseSize(val)
		}
	}

	// If storage type wasn't explicitly reported, infer from ufs/emmc keys
	if recon.StorageType == "" {
		if ufsVal, ok := recon.RawVars["ufs"]; ok && ufsVal != "" && ufsVal != "false" {
			recon.StorageType = "ufs"
		} else if emmcVal, ok := recon.RawVars["emmc"]; ok && emmcVal != "" && emmcVal != "false" {
			recon.StorageType = "emmc"
		}
	}

	return recon
}

func (r *DeviceRecon) getOrCreateSlot(slot string) *SlotInfo {
	if info, ok := r.SlotStatus[slot]; ok {
		return info
	}
	info := &SlotInfo{Slot: slot}
	r.SlotStatus[slot] = info
	return info
}

// MatchCatalog resolves the fastboot device against the go-unbrick device catalog.
func MatchCatalog(c *catalog.Catalog, recon *DeviceRecon) (*catalog.Device, []string) {
	if c == nil || recon == nil {
		return nil, nil
	}

	var notes []string

	// 1. Try matching by exact product/codename
	if recon.Product != "" {
		if d, ok := c.Device(recon.Product); ok {
			notes = append(notes, fmt.Sprintf("matched codename %q in catalog", recon.Product))
			return d, notes
		}
	}

	// 2. Try matching by SKU / aliases
	if recon.SKU != "" {
		if d, ok := c.Device(recon.SKU); ok {
			notes = append(notes, fmt.Sprintf("matched SKU %q in catalog", recon.SKU))
			return d, notes
		}
	}

	return nil, notes
}

// LibraryMatchResult contains matches found in the local library.
type LibraryMatchResult struct {
	StockBuilds     []string
	ExactStockMatch string
	// BootChainMatch is a stored build whose XBL is the very one running — same
	// git hash — but which is not an exact match: the package was built on a
	// different date, or carries a different AP build. The boot chain is what a
	// blankflash replaces, so this build is the right donor even though the
	// installed firmware as a whole is not the packaged one.
	BootChainMatch string
	CandidateLoader string
	LoaderCount     int
	Compatible      bool
	JTAGMatch       bool
	// CIDCompatible are stored builds whose declared cid_value matches the CID the
	// device reports; CIDForeign those declaring a different one. The bootloader
	// compares the two before flashing, so a foreign build is not a candidate for
	// this unit however well its build id matches. Builds that declare no CID
	// (service packages, hand-assembled dumps) appear in neither list.
	CIDCompatible []string
	CIDForeign    []string
}

// CheckLibrary inspects local firmware storage for stock builds and candidate loaders.
func CheckLibrary(lib *library.Library, dev *catalog.Device, recon *DeviceRecon) *LibraryMatchResult {
	res := &LibraryMatchResult{}
	if lib == nil || dev == nil {
		return res
	}

	// Check stored stock builds
	builds := lib.StockBuilds(dev.Vendor, dev.Codename)
	devCID := ""
	if recon != nil {
		devCID = library.NormalizeCID(recon.CarrierID)
	}
	for _, b := range builds {
		res.StockBuilds = append(res.StockBuilds, b.Build)

		// Check for exact stock build match
		switch {
		case recon != nil && matchesStockBuild(b.Build, recon):
			res.ExactStockMatch = b.Build
		case recon != nil && matchesBootChain(b.Build, recon):
			res.BootChainMatch = b.Build
		}
		if devCID != "" && b.Meta.CID != "" {
			if library.NormalizeCID(b.Meta.CID) == devCID {
				res.CIDCompatible = append(res.CIDCompatible, b.Build)
			} else {
				res.CIDForeign = append(res.CIDForeign, fmt.Sprintf("%s (%s)", b.Build, b.Meta.CID))
			}
		}
	}

	// Check candidate loaders
	loaders := lib.CandidateLoaders(dev)
	res.LoaderCount = len(loaders)
	if len(loaders) > 0 {
		first := loaders[0]
		res.CandidateLoader = fmt.Sprintf("%s (%s, SW_ID=%d)", first.Build, first.Family, first.Meta.SWID)
		res.Compatible = true

		if recon != nil && recon.JTAGID != "" {
			for _, l := range loaders {
				if strings.EqualFold(l.Family.JTAGID, recon.JTAGID) {
					res.JTAGMatch = true
					res.CandidateLoader = fmt.Sprintf("%s (%s, SW_ID=%d)", l.Build, l.Family, l.Meta.SWID)
					break
				}
			}
		}
	}

	sort.Strings(res.StockBuilds)
	sort.Strings(res.CIDCompatible)
	sort.Strings(res.CIDForeign)
	return res
}

// BootChainDates groups the boot-chain components by the release date each one
// stamps, newest first. Components of one release share a date whatever their
// individual git hashes are, so more than one group means the chain was flashed
// from more than one package — a partial or interrupted flash.
func (r *DeviceRecon) BootChainDates() map[string][]string {
	out := map[string][]string{}
	for comp, stamp := range r.ComponentBuilds {
		m := reMBMDate.FindStringSubmatch(stamp)
		if m == nil {
			continue
		}
		out[m[1]] = append(out[m[1]], comp)
	}
	for _, comps := range out {
		sort.Strings(comps)
	}
	return out
}

// reMBMDate pulls the trailing build date out of an MBM stamp. The stamp may
// carry a build id after it ("…-250618-U1TF34.100-35-14-98d43"), so the date is
// matched where it sits rather than at the end.
var reMBMDate = regexp.MustCompile(`(?i)MBM-[0-9.]+-[a-z0-9_]+-[0-9a-f]{6,}-(\d{6})`)

// reMBMHash pulls the git hash out of the build signature Motorola stamps into
// every boot partition ("MBM-3.0-fogona-2902df5ac-250618"). The hash identifies
// the boot chain's source; the trailing date is only when that source was built,
// and the same hash does recur under different dates.
var reMBMHash = regexp.MustCompile(`(?i)MBM-[0-9.]+-[a-z0-9_]+-([0-9a-f]{6,})-\d{6}`)

// matchesBootChain reports whether a stored build ("<YYMMDD>-<githash>") carries
// the XBL the device is running, judged on the hash alone.
func matchesBootChain(buildName string, recon *DeviceRecon) bool {
	if buildName == "" || recon == nil {
		return false
	}
	m := reMBMHash.FindStringSubmatch(recon.XBLBuild)
	if m == nil {
		m = reMBMHash.FindStringSubmatch(recon.BootloaderVersion)
	}
	if m == nil {
		return false
	}
	hash := strings.ToLower(m[1])
	for _, tok := range strings.Split(strings.ToLower(buildName), "-") {
		if tok == hash {
			return true
		}
	}
	return false
}

func matchesStockBuild(buildName string, recon *DeviceRecon) bool {
	if buildName == "" || recon == nil {
		return false
	}
	if recon.DisplayID != "" && strings.EqualFold(buildName, recon.DisplayID) {
		return true
	}
	parts := strings.Split(buildName, "-")
	matchedParts := 0
	for _, p := range parts {
		pTrimmed := strings.TrimSpace(p)
		if pTrimmed == "" {
			continue
		}
		if (recon.XBLBuild != "" && strings.Contains(strings.ToLower(recon.XBLBuild), strings.ToLower(pTrimmed))) ||
			(recon.BootloaderVersion != "" && strings.Contains(strings.ToLower(recon.BootloaderVersion), strings.ToLower(pTrimmed))) ||
			(recon.Fingerprint != "" && strings.Contains(strings.ToLower(recon.Fingerprint), strings.ToLower(pTrimmed))) {
			matchedParts++
		}
	}
	return matchedParts == len(parts) && matchedParts > 0
}

// ParseOEMHwOutput parses the output of 'fastboot oem hw'. Beyond the sensor
// booleans it captures each feature's value, the range of values the family
// ships, and the hwid-derivation rule when the value is fused rather than chosen.
func ParseOEMHwOutput(text string) *OEMHardwareInfo {
	hw := &OEMHardwareInfo{}
	feats := map[string]*UTag{} // by feature name
	var order []string               // from the `.features` list
	hasAny := false

	get := func(name string) *UTag {
		f, ok := feats[name]
		if !ok {
			f = &UTag{Name: name}
			feats[name] = f
		}
		return f
	}

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		if trimmed == "" || strings.HasPrefix(trimmed, "OKAY") || strings.HasPrefix(trimmed, "Finished") {
			continue
		}
		// The `.features` list wraps across lines; a continuation has no colon and
		// starts with the comma that joined it to the previous line.
		if strings.HasPrefix(trimmed, ",") {
			order = append(order, splitCSV(trimmed)...)
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		keyLower := strings.ToLower(key)

		switch {
		case keyLower == ".features":
			order = append(order, splitCSV(val)...)
			continue
		case strings.HasPrefix(keyLower, ".") || keyLower == "":
			continue // .attributes, .version
		}

		// A feature line is either "<feat>" (the value) or "<feat>/.<attr>".
		name, attr, hasAttr := strings.Cut(keyLower, "/")
		switch {
		case !hasAttr:
			get(name).Value = val
			hasAny = true
		case attr == ".range":
			get(name).Range = splitCSV(val)
		case attr == ".auto" && strings.Contains(val, "hwid"):
			// The fused-HW_ID derivation, e.g. "key=hwid;index=2;map=1:ATT,2:RET".
			get(name).HWIDMap = val
		}
	}

	if !hasAny {
		return nil
	}

	// Mirror the well-known sensor bits from the collected values.
	valOf := func(n string) string {
		if f, ok := feats[n]; ok {
			return f.Value
		}
		return ""
	}
	hw.DualSIM = strings.EqualFold(valOf("dualsim"), "true")
	hw.ECompass = strings.EqualFold(valOf("ecompass"), "true")
	hw.ESIM = strings.EqualFold(valOf("esim"), "true")
	hw.FPS = strings.EqualFold(valOf("fps"), "true")
	hw.NFC = strings.EqualFold(valOf("nfc"), "true")
	hw.RadioType = valOf("radio")

	// Emit features in the device's declared order, appending any it valued but
	// left out of `.features`.
	seen := map[string]bool{}
	for _, n := range order {
		if f, ok := feats[n]; ok && !seen[n] {
			hw.UTags = append(hw.UTags, *f)
			seen[n] = true
		}
	}
	for _, n := range sortedKeysHW(feats) {
		if !seen[n] {
			hw.UTags = append(hw.UTags, *feats[n])
		}
	}
	return hw
}

// splitCSV splits a comma list, trimming blanks — the empty tail of a wrapped
// list yields nothing rather than an empty entry.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sortedKeysHW(m map[string]*UTag) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseOEMReadSVOutput parses the security versions / anti-rollback registers from 'fastboot oem read_sv'.
func ParseOEMReadSVOutput(text string) *SecurityVersions {
	sv := &SecurityVersions{}
	hasAny := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "(bootloader)")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" || strings.HasPrefix(trimmed, "OKAY") || strings.HasPrefix(trimmed, "Finished") {
			continue
		}
		sv.RawLines = append(sv.RawLines, trimmed)
		if strings.Contains(trimmed, "RIL #0 =") {
			parts := strings.Split(trimmed, "=")
			if len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					sv.RIL0 = n
					hasAny = true
				}
			}
		} else if strings.Contains(trimmed, "RIL #2 =") {
			parts := strings.Split(trimmed, "=")
			if len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					sv.RIL2 = n
					hasAny = true
				}
			}
		} else if strings.Contains(trimmed, "vbmeta RIL is") {
			parts := strings.Fields(trimmed)
			if len(parts) > 0 {
				lastToken := strings.TrimSuffix(parts[len(parts)-1], ".")
				if n, err := strconv.Atoi(lastToken); err == nil {
					sv.VbmetaRIL = n
					hasAny = true
				}
			}
		}
	}
	if !hasAny && len(sv.RawLines) == 0 {
		return nil
	}
	return sv
}

// ParseOEMPartitionOutput parses the partition table and dynamic super partition layout from 'fastboot oem partition'.
func ParseOEMPartitionOutput(text string) ([]PartitionDetail, bool, []string) {
	var partitions []PartitionDetail
	var unpopulated []string
	var superOffset uint64
	hasSuper := false

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "(bootloader)")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" || strings.HasPrefix(trimmed, "OKAY") || strings.HasPrefix(trimmed, "Finished") {
			continue
		}

		idxColon := strings.Index(trimmed, ":")
		if idxColon == -1 {
			continue
		}
		name := strings.TrimSpace(trimmed[:idxColon])
		rest := trimmed[idxColon+1:]

		var offsetKB, sizeKB uint64
		for _, token := range strings.Split(rest, ",") {
			token = strings.TrimSpace(token)
			if strings.HasPrefix(token, "offset=") {
				valStr := strings.TrimSuffix(strings.TrimPrefix(token, "offset="), "KB")
				offsetKB, _ = strconv.ParseUint(valStr, 10, 64)
			} else if strings.HasPrefix(token, "size=") {
				valStr := strings.TrimSuffix(strings.TrimPrefix(token, "size="), "KB")
				sizeKB, _ = strconv.ParseUint(valStr, 10, 64)
			}
		}

		if name == "super" {
			superOffset = offsetKB
			hasSuper = true
		}

		isDynamic := hasSuper && offsetKB == superOffset && name != "super"

		partitions = append(partitions, PartitionDetail{
			Name:     name,
			OffsetKB: offsetKB,
			SizeKB:   sizeKB,
			IsSuper:  isDynamic,
		})

		if isDynamic && strings.HasSuffix(name, "_b") && sizeKB == 0 {
			unpopulated = append(unpopulated, name)
		}
	}

	return partitions, len(unpopulated) > 0, unpopulated
}
