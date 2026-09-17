// Package safeguard identifies, classifies, and enforces protection for per-device
// calibration, baseband NVRAM, IMEI, and cryptographic identity partitions across
// Qualcomm, MediaTek, and Samsung architectures.
package safeguard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

// Categories classifying partition purposes.
const (
	CategoryRadio       = "radio"       // Baseband NVRAM, RF calibration, IMEI, SIM lock
	CategoryCalibration = "calibration" // Factory sensor, camera, audio, display tuning
	CategoryIdentity    = "identity"    // Device serial, CID, FRP lock, tamper flags
	CategoryBoot        = "boot"        // Replaceable boot chain (XBL, ABL, TZ, etc.)
	CategoryOS          = "os"          // Android payload: kernel, ramdisks, dynamic images, AVB metadata
	CategoryData        = "data"        // User-owned or filesystem state, not per-device identity
	CategoryPlatform    = "platform"    // Firmware scratch, debug policy, padding — flashed by nothing
	CategoryUnknown     = "unknown"
)

// Criticality levels.
const (
	CriticalityIrreplaceable = "irreplaceable" // Unique per-device; loss causes permanent brick or IMEI loss
	CriticalityImportant     = "important"     // Device configuration, calibration, or security tokens
	CriticalityReplaceable   = "replaceable"   // Generic bootloader binaries safely flashable from stock
)

// PartitionMeta describes safeguard metadata for one partition.
type PartitionMeta struct {
	Name        string
	BaseName    string
	Category    string
	Criticality string
	Action      string
	Description string
	Vendor      string
	Protected   bool
}

// Built-in rule map covering canonical Qualcomm, MediaTek, and Samsung partitions.
var builtInRules = map[string]PartitionMeta{
	// Qualcomm Radio & Baseband NVRAM (Irreplaceable)
	"modemst1": {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "qualcomm", Description: "Primary modem NVRAM (IMEI, SIM lock, RF calibration)", Protected: true},
	"modemst2": {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "qualcomm", Description: "Secondary modem NVRAM (IMEI backup, network profiles)", Protected: true},
	"fsg":      {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "qualcomm", Description: "Golden copy of modem file system (radio parameters)", Protected: true},
	"fsc":      {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "qualcomm", Description: "Modem filesystem cookies and encryption keys", Protected: true},

	// MediaTek Baseband & NVRAM
	"nvram":    {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek baseband NVRAM (IMEI, RF calibration, MAC)", Protected: true},
	"nvdata":   {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek dynamic NVRAM data partition", Protected: true},
	"proinfo":  {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek factory product information and barcode/serial", Protected: true},
	"protect1": {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek protected calibration partition 1", Protected: true},
	"protect2": {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek protected calibration partition 2", Protected: true},
	"nvcfg":    {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek non-volatile carrier configuration", Protected: true},

	// Samsung EFS & Baseband
	"efs":     {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "samsung", Description: "Samsung encrypted filesystem (IMEI, MAC, baseband NV)", Protected: true},
	"sec_efs": {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "samsung", Description: "Samsung secondary secure EFS backup", Protected: true},
	"nv_data": {Category: CategoryRadio, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "samsung", Description: "Samsung baseband NVRAM data", Protected: true},

	// Calibration
	"persist":     {Category: CategoryCalibration, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "qualcomm", Description: "Factory sensor, camera, audio, display and DRM calibration", Protected: true},
	"prodpersist": {Category: CategoryCalibration, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "motorola", Description: "Motorola production persist partition (factory calibration)", Protected: true},
	"sns":         {Category: CategoryCalibration, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "qualcomm", Description: "Sensor subsystem hardware calibration", Protected: true},
	"sensorhub":   {Category: CategoryCalibration, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "qualcomm", Description: "Context hub / sensor fusion calibration", Protected: true},
	"kpan":        {Category: CategoryCalibration, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "motorola", Description: "Motorola kernel panic & diagnostic calibration logs", Protected: true},
	"carrier":     {Category: CategoryCalibration, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "generic", Description: "Carrier customization and APN provisioning", Protected: true},

	// Identity & Cryptographic State
	"cid":         {Category: CategoryIdentity, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "motorola", Description: "Carrier / Customer ID and device software channel lock", Protected: true},
	"frp":         {Category: CategoryIdentity, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "generic", Description: "Factory Reset Protection lock state and persistent tokens", Protected: true},
	"devinfo":     {Category: CategoryIdentity, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "qualcomm", Description: "Device bootloader lock flags, tamper bits, integrity tokens", Protected: true},
	"utags":       {Category: CategoryIdentity, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "motorola", Description: "Motorola NV configuration tags (serial number, bar code, SKU)", Protected: true},
	"utagsbackup": {Category: CategoryIdentity, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "motorola", Description: "Motorola redundant backup of UTAGs configuration", Protected: true},
	"hw":          {Category: CategoryIdentity, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "motorola", Description: "Hardware revision and board variant identifier", Protected: true},
	"sp":          {Category: CategoryIdentity, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "motorola", Description: "Secure partition / security processor key store", Protected: true},
	"misc":        {Category: CategoryIdentity, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "generic", Description: "BCB bootloader control block and recovery command buffer", Protected: true},
	"seccfg":      {Category: CategoryIdentity, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek security configuration and lock status", Protected: true},
	"tee1":        {Category: CategoryIdentity, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek primary Trusted Execution Environment keystore", Protected: true},
	"tee2":        {Category: CategoryIdentity, Criticality: CriticalityIrreplaceable, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek secondary Trusted Execution Environment keystore", Protected: true},
	"para":        {Category: CategoryIdentity, Criticality: CriticalityImportant, Action: "backup_and_preserve", Vendor: "mediatek", Description: "MediaTek parameter configuration", Protected: true},

	// Bootloader Components (Replaceable)
	"xbl":        {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "eXtensible Boot Loader core", Protected: false},
	"xbl_config": {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "XBL multi-image configuration data", Protected: false},
	"abl":        {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Android Bootloader (fastboot)", Protected: false},
	"tz":         {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Qualcomm TrustZone / QSEE monitor", Protected: false},
	"rpm":        {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Resource & Power Manager firmware", Protected: false},
	"aop":        {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Always-On Processor firmware", Protected: false},
	"hyp":        {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Qualcomm hypervisor", Protected: false},
	"qupfw":      {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Universal Peripheral firmware", Protected: false},
	"devcfg":     {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Device configuration blob", Protected: false},
	"keymaster":  {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Keymaster secure applet", Protected: false},
	"uefisecapp": {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "UEFI secure applet", Protected: false},
	"storsec":    {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Storage security controller", Protected: false},
	"prov":       {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Storage provisioning helper", Protected: false},
	"cmnlib":     {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Common 32-bit runtime library", Protected: false},
	"cmnlib64":   {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Common 64-bit runtime library", Protected: false},

	// Peripheral firmware. Replaceable from stock, but note modem/dsp carry only
	// the executable images — the per-device radio calibration they run against
	// lives in modemst1/2 and fsg, which are irreplaceable.
	"modem":     {Category: CategoryRadio, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Baseband firmware image (NON-HLOS)", Protected: false},
	"bluetooth": {Category: CategoryRadio, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "Bluetooth controller firmware", Protected: false},
	"dsp":       {Category: CategoryBoot, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "qualcomm", Description: "aDSP/cDSP firmware (audio, sensors, compute)", Protected: false},

	// Android payload. All replaceable from a matching stock package; none carry
	// per-device state, so a blankflash neither backs them up nor needs them.
	"boot":          {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Kernel and generic ramdisk", Protected: false},
	"init_boot":     {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Generic init ramdisk (split from boot in Android 13+)", Protected: false},
	"vendor_boot":   {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Vendor ramdisk and kernel modules needed to mount /", Protected: false},
	"recovery":      {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Recovery ramdisk", Protected: false},
	"dtbo":          {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Device tree overlays applied to the board DTB", Protected: false},
	"vbmeta":        {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Android Verified Boot root metadata (hashes, rollback index)", Protected: false},
	"vbmeta_system": {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "AVB metadata chained for the system images", Protected: false},
	"logo":          {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "motorola", Description: "Boot splash and bootloader warning screens", Protected: false},
	"super":         {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Dynamic partition container (system, vendor, product, …)", Protected: false},
	"system":        {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Android system image", Protected: false},
	"system_ext":    {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "OEM extensions to the system image", Protected: false},
	"product":       {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Product-specific apps and configuration", Protected: false},
	"vendor":        {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Vendor HALs and board support", Protected: false},
	"odm":           {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "ODM customization image", Protected: false},
	"system_dlkm":   {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "GKI kernel modules shipped with system", Protected: false},
	"vendor_dlkm":   {Category: CategoryOS, Criticality: CriticalityReplaceable, Action: "flash_and_skip_backup", Vendor: "generic", Description: "Vendor kernel modules", Protected: false},

	// User-owned state. Not per-device identity, so nothing here is preserved by a
	// blankflash — but metadata holds the file-based-encryption keys that make
	// userdata readable, so wiping one without the other strands the data.
	"userdata": {Category: CategoryData, Criticality: CriticalityImportant, Action: "none", Vendor: "generic", Description: "User data and apps (/data, encrypted)", Protected: false},
	"metadata": {Category: CategoryData, Criticality: CriticalityImportant, Action: "none", Vendor: "generic", Description: "File-based-encryption keys and AVB state for /data", Protected: false},

	// Firmware scratch and diagnostics: written by the boot chain at runtime,
	// flashed by no package, and rebuilt when blank.
	"ramdump":      {Category: CategoryPlatform, Criticality: CriticalityReplaceable, Action: "none", Vendor: "qualcomm", Description: "Crash RAM dump capture region", Protected: false},
	"logfs":        {Category: CategoryPlatform, Criticality: CriticalityReplaceable, Action: "none", Vendor: "qualcomm", Description: "UEFI log filesystem", Protected: false},
	"uefivarstore": {Category: CategoryPlatform, Criticality: CriticalityReplaceable, Action: "none", Vendor: "qualcomm", Description: "UEFI variable store", Protected: false},
	"apdp":         {Category: CategoryPlatform, Criticality: CriticalityReplaceable, Action: "none", Vendor: "qualcomm", Description: "Application processor debug policy", Protected: false},
	"msadp":        {Category: CategoryPlatform, Criticality: CriticalityReplaceable, Action: "none", Vendor: "qualcomm", Description: "Modem subsystem debug policy", Protected: false},
	"limits":       {Category: CategoryPlatform, Criticality: CriticalityReplaceable, Action: "none", Vendor: "qualcomm", Description: "Thermal and current limit management configuration", Protected: false},
	"ddr":          {Category: CategoryPlatform, Criticality: CriticalityReplaceable, Action: "none", Vendor: "qualcomm", Description: "DDR training parameters cached by XBL (retrained when blank)", Protected: false},
	"spunvm":       {Category: CategoryPlatform, Criticality: CriticalityReplaceable, Action: "none", Vendor: "qualcomm", Description: "Secure processing unit non-volatile storage", Protected: false},
}

// rePadPartition matches the fillers Motorola's GPT carries at the tail of each
// UFS LUN ("last_parti4") and between regions ("pad3"). They hold no image; the
// index in the name is the filler's own, not a LUN number.
var rePadPartition = regexp.MustCompile(`^(last_parti|pad)\d*$`)

// CanonicalMotorolaProtected lists the default partitions every genuine Motorola blankflash preserves.
var CanonicalMotorolaProtected = []string{
	"cid",
	"frp",
	"hw",
	"misc",
	"persist",
	"prodpersist",
	"utags",
	"devinfo",
	"sp",
	"modemst1",
	"modemst2",
	"fsg",
	"fsc",
}

// NormalizeBaseName removes slot suffixes (_a, _b, _1, _2) and downcases.
func NormalizeBaseName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	base := strings.TrimSuffix(strings.TrimSuffix(lower, "_a"), "_b")
	base = strings.TrimSuffix(strings.TrimSuffix(base, "_1"), "_2")
	return base
}

// Classify returns safeguard metadata for a partition name.
func Classify(name string) PartitionMeta {
	raw := strings.TrimSpace(name)
	base := NormalizeBaseName(raw)
	if meta, ok := builtInRules[base]; ok {
		meta.Name = raw
		meta.BaseName = base
		return meta
	}
	if rePadPartition.MatchString(base) {
		return PartitionMeta{
			Name:        raw,
			BaseName:    base,
			Category:    CategoryPlatform,
			Criticality: CriticalityReplaceable,
			Action:      "none",
			Description: "GPT filler (no image; tail of a UFS LUN or inter-region padding)",
			Vendor:      "motorola",
		}
	}
	// Fallback heuristic for unknown partitions
	return PartitionMeta{
		Name:        raw,
		BaseName:    base,
		Category:    CategoryUnknown,
		Criticality: CriticalityReplaceable,
		Action:      "none",
		Description: "Unclassified partition",
		Vendor:      "unknown",
		Protected:   false,
	}
}

// IsProtected reports whether the partition holds irreplaceable or critical per-device data.
func IsProtected(name string) bool {
	return Classify(name).Protected
}

// SynthesizeDirectives generates safe Motorola recipe <backup> and <restore> directives.
//
// If targetPartitions is non-empty, any protected partitions detected in the target's
// partition table are included. If none are detected or targetPartitions is empty,
// CanonicalMotorolaProtected is used.
//
// flashOrder specifies bootloader components being flashed that should be marked
// skip="true" so qboot does not waste RAM backing up clean images being overwritten.
func SynthesizeDirectives(targetPartitions []string, flashOrder []string) (backups []string, restores []string) {
	// 1. Determine which protected partitions to back up
	protectSet := make(map[string]bool)
	var orderedProtect []string

	if len(targetPartitions) > 0 {
		for _, name := range targetPartitions {
			meta := Classify(name)
			if meta.Protected && !protectSet[meta.Name] {
				protectSet[meta.Name] = true
				orderedProtect = append(orderedProtect, meta.Name)
			}
		}
	}

	// Always ensure core canonical partitions are covered
	for _, canon := range CanonicalMotorolaProtected {
		if !protectSet[canon] {
			protectSet[canon] = true
			orderedProtect = append(orderedProtect, canon)
		}
	}

	// 2. Build backup directives
	backups = append(backups, "\t<!-- Backup partitions that contain per-device configuration -->")
	for _, p := range orderedProtect {
		backups = append(backups, fmt.Sprintf("\t<backup name=\"%s\"/>", p))
	}

	// 3. Skip boot components being flashed (both _a and _b slots)
	if len(flashOrder) > 0 {
		backups = append(backups, "")
		backups = append(backups, "\t<!-- Skip BL components should they be marked for backup in GPT -->")
		seenSkip := make(map[string]bool)
		for _, slot := range []string{"a", "b"} {
			for _, part := range flashOrder {
				base := NormalizeBaseName(part)
				targetName := fmt.Sprintf("%s_%s", base, slot)
				if !seenSkip[targetName] {
					seenSkip[targetName] = true
					backups = append(backups, fmt.Sprintf("\t<backup name=\"%-12s\" skip=\"true\"/>", targetName+"\""))
				}
			}
		}
	}

	// 4. Commit directive
	backups = append(backups, "")
	backups = append(backups, "\t<!-- Commit all listed above plus those specified in device GPT -->")
	backups = append(backups, "\t<backup commit=\"1\"/>")

	// 5. Restore directive
	restores = append(restores, "\t<!-- Restore backups -->")
	restores = append(restores, "\t<restore dummy=\"foo\"/>")

	return backups, restores
}

// PartitionAudit contains the audit result for a single partition.
type PartitionAudit struct {
	Name        string
	BaseName    string
	Category    string
	Criticality string
	Description string
	Protected   bool
}

// AuditReport summarizes the safeguard analysis of a partition list.
type AuditReport struct {
	Partitions       []PartitionAudit
	ProtectedCount   int
	ReplaceableCount int
	UnknownCount     int
}

// Audit inspects a list of partition names and returns a complete security audit report.
func Audit(partitions []string) *AuditReport {
	rep := &AuditReport{}
	seen := make(map[string]bool)

	for _, p := range partitions {
		pClean := strings.TrimSpace(p)
		if pClean == "" || seen[pClean] {
			continue
		}
		seen[pClean] = true

		meta := Classify(pClean)
		audit := PartitionAudit{
			Name:        meta.Name,
			BaseName:    meta.BaseName,
			Category:    meta.Category,
			Criticality: meta.Criticality,
			Description: meta.Description,
			Protected:   meta.Protected,
		}
		rep.Partitions = append(rep.Partitions, audit)

		if meta.Protected {
			rep.ProtectedCount++
		} else if meta.Category == CategoryBoot {
			rep.ReplaceableCount++
		} else {
			rep.UnknownCount++
		}
	}

	// Sort partitions by category and name
	sort.Slice(rep.Partitions, func(i, j int) bool {
		if rep.Partitions[i].Protected != rep.Partitions[j].Protected {
			return rep.Partitions[i].Protected // Protected first
		}
		return rep.Partitions[i].Name < rep.Partitions[j].Name
	})

	return rep
}

// PartitionNamesFromGPT extracts partition names from raw GPT disk/image bytes.
func PartitionNamesFromGPT(data []byte) ([]string, error) {
	if len(data) < 512 {
		return nil, fmt.Errorf("data too short for GPT header (%d bytes)", len(data))
	}

	// 1. Support Motorola SINGLE_N_LONELY container packing multiple gpt_main*.bin (UFS devices)
	if bytes.HasPrefix(data, []byte("SINGLE_N_LONELY")) {
		var allNames []string
		seen := make(map[string]bool)
		for off := 0x100; off+0x100 <= len(data); {
			nameBytes := data[off : off+0xf8]
			if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
				nameBytes = nameBytes[:i]
			}
			name := string(nameBytes)
			sz := binary.LittleEndian.Uint64(data[off+0xf8 : off+0x100])
			dataOff := off + 0x100
			if dataOff+int(sz) > len(data) {
				break
			}
			if strings.HasPrefix(name, "gpt_main") {
				if names, err := PartitionNamesFromGPT(data[dataOff : dataOff+int(sz)]); err == nil {
					for _, n := range names {
						if !seen[n] {
							seen[n] = true
							allNames = append(allNames, n)
						}
					}
				}
			}
			if name == "LONELY_N_SINGLE" {
				break
			}
			pad := (0x1000 - int(sz)%0x1000) % 0x1000
			off = dataOff + int(sz) + pad
		}
		if len(allNames) > 0 {
			return allNames, nil
		}
	}

	headerOffset := -1
	sectorSize := 512

	if bytes.HasPrefix(data, []byte("EFI PART")) {
		headerOffset = 0
	} else if len(data) >= 1024 && bytes.Equal(data[512:520], []byte("EFI PART")) {
		headerOffset = 512
	} else if idx := bytes.Index(data, []byte("EFI PART")); idx >= 0 {
		headerOffset = idx
	}

	if headerOffset < 0 {
		return nil, fmt.Errorf("no EFI PART signature found")
	}

	header := data[headerOffset:]
	if len(header) < 92 {
		return nil, fmt.Errorf("truncated GPT header (%d bytes)", len(header))
	}

	currentLBA := binary.LittleEndian.Uint64(header[24:32])
	if currentLBA == 1 && headerOffset > 0 {
		sectorSize = headerOffset
	}

	partEntryLBA := binary.LittleEndian.Uint64(header[72:80])
	numEntries := binary.LittleEndian.Uint32(header[80:84])
	entrySize := binary.LittleEndian.Uint32(header[84:88])

	if entrySize < 128 || numEntries == 0 || numEntries > 1024 {
		return nil, fmt.Errorf("invalid partition entry table: %d entries of %d bytes", numEntries, entrySize)
	}

	var partOffset int
	if currentLBA > 0 && partEntryLBA >= currentLBA {
		partOffset = headerOffset + int(partEntryLBA-currentLBA)*sectorSize
	} else if headerOffset >= sectorSize {
		partOffset = headerOffset - sectorSize + int(partEntryLBA)*sectorSize
	} else {
		partOffset = headerOffset + sectorSize
	}

	if partOffset+int(numEntries*entrySize) > len(data) {
		return nil, fmt.Errorf("partition entries exceed boundary")
	}

	var out []string
	var zeroGUID [16]byte

	for i := uint32(0); i < numEntries; i++ {
		entry := data[partOffset+int(i*entrySize) : partOffset+int((i+1)*entrySize)]
		var typeGUID [16]byte
		copy(typeGUID[:], entry[0:16])
		if typeGUID == zeroGUID {
			continue
		}

		nameRaw := entry[56:128]
		u16 := make([]uint16, 36)
		for j := 0; j < 36; j++ {
			u16[j] = binary.LittleEndian.Uint16(nameRaw[j*2 : j*2+2])
		}
		name := strings.TrimRight(string(utf16.Decode(u16)), "\x00 ")
		if name != "" {
			out = append(out, name)
		}
	}

	return out, nil
}
