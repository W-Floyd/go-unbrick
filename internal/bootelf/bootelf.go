// Package bootelf inspects mobile bootloader and firmware ELFs (xbl, abl,
// programmer, tz, devcfg, qupfw). Beyond cryptographic secboot identities, it
// decodes program headers, extracts Qualcomm build and platform variants,
// auto-detects storage hardware protocols (UFS vs eMMC), and surfaces embedded
// UEFI/fastboot firmware contents.
package bootelf

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	yaml "go.yaml.in/yaml/v4"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/efi"
	"go-unbrick/internal/secboot"
)

// ELF machine architecture codes (e_machine), mapped to debug/elf.
const (
	MachineNone    uint16 = uint16(elf.EM_NONE)
	Machine386     uint16 = uint16(elf.EM_386)
	MachineARM     uint16 = uint16(elf.EM_ARM)
	MachineX86_64  uint16 = uint16(elf.EM_X86_64)
	MachineQDSP6   uint16 = uint16(elf.EM_QDSP6) // Qualcomm Hexagon DSP
	MachineAArch64 uint16 = uint16(elf.EM_AARCH64) // ARM 64-bit
	MachineRISCV   uint16 = uint16(elf.EM_RISCV)
)

// ELF object file types (e_type), mapped to debug/elf.
const (
	TypeNone uint16 = uint16(elf.ET_NONE)
	TypeRel  uint16 = uint16(elf.ET_REL)
	TypeExec uint16 = uint16(elf.ET_EXEC)
	TypeDyn  uint16 = uint16(elf.ET_DYN)
	TypeCore uint16 = uint16(elf.ET_CORE)
)

// Segment holds properties of one ELF program header entry.
type Segment struct {
	Index    int
	Type     uint32
	Flags    uint32
	Offset   uint64
	Vaddr    uint64
	Paddr    uint64
	Filesz   uint64
	Memsz    uint64
	Hash     bool   // Qualcomm hash segment (segment-type nibble 2)
	QCNibble uint8  // Upper 4 bits of Flags ((Flags >> 24) & 0xf)
	Role     string // Semantic role: "Code", "Data", "Rodata", "BSS", "Hash / Certs", "PageTable", etc.
}

// ExecutionTopology describes the target memory location and execution environment.
type ExecutionTopology struct {
	Region     string // "SRAM (Internal On-Chip / Pre-DDR)", "DRAM (High Memory / Post-Training)", "EL3 Secure Monitor", "Hexagon DSP", etc.
	BaseAddr   uint64 // Lowest physical load address
	EndAddr    uint64 // Highest physical load address + memsz
	TotalMemKB uint64 // Total memory footprint in KB
	CodeBytes  uint64 // Executable code size (PF_X)
	DataBytes  uint64 // Initialized data size (non-executable with Filesz > 0)
	BSSBytes   uint64 // Zero-initialized runtime memory allocation (Memsz - Filesz)
}

// BuildProvenance carries parsed compiler/builder provenance from OEM strings.
type BuildProvenance struct {
	Builder   string // e.g. "hudsoncm", "crm-ubuntu96", "nobody"
	BuildDate string // e.g. "2021.08.04-07:36"
	CommitSHA string // e.g. "d68ca9415"
}

// Subsystems holds identified OEM and platform features discovered in the binary.
type Subsystems struct {
	MotorolaUTAGs bool     // MotUtagsDxe / MotUtagsDictDxe
	VerifiedBoot  bool     // VerifiedBootDxe / SecRSADxe / ASN1X509Dxe (AVB 2.0)
	BatteryCharge bool     // QcomChargerApp / QcomChargerDxeLA / BATTERY.PROVISION
	SharedMemory  bool     // SmemDxe (Qualcomm multi-core IPC)
	TME           bool     // Trust Management Engine
	FastbootUI    bool     // Fastboot / Android Bootloader UI
	Details       []string // Human readable tags
}

// Info holds decoded architecture, build, hardware, and security metadata from a boot ELF.
type Info struct {
	Class    int       // 32 or 64
	Endian   string    // "LSB" or "MSB"
	Machine  uint16    // Raw e_machine code
	Arch     string    // Human-readable architecture name ("ARM", "AArch64", "QDSP6 (Hexagon)", etc.)
	Type     uint16    // Raw e_type
	TypeName string    // "EXEC", "DYN", etc.
	Entry    uint64    // Entry point virtual address
	Segments []Segment // Program header segments

	// Execution topology & memory map
	Topology ExecutionTopology

	// Build provenance
	Provenance BuildProvenance

	// Identified firmware subsystems & features
	Subsystems Subsystems

	// Qualcomm build & image metadata (extracted from text/rodata strings)
	QCVersion    string // e.g. "BOOT.XF.3.2-00336-SM8250-1"
	Variant      string // e.g. "Soc8250LAA"
	TargetSoC    string // Normalized SoC name or commercial moniker (e.g. "Qualcomm SM8250 Snapdragon 865/870")
	OEMBuild     string // e.g. "android-build nobody 2023.09.07-05:18 e5db4d5b4"
	TMEVersion   string // e.g. "ssg.tmefw.1.0-01433-release"
	TMEBuildTime string // e.g. "September 06 2022 at 12:38:43"
	QCBuildTime  string // e.g. "2023.12.14-00:23:26", from the CRM build path of QCVersion

	// Storage capabilities detected from programmer code
	Storage []string // ["ufs"], ["emmc"], or ["ufs", "emmc"]

	// Peek reports the loader's peek/poke memory-command support — the
	// capability behind "signed but exploitable" repair loaders. Only
	// meaningful for a firehose programmer.
	Peek secboot.PeekSupport

	// Secboot signing identity (if signed)
	Identity *secboot.Identity

	// UEFI firmware module inventory (if carrying EFI firmware volumes, e.g. abl.elf)
	UEFIModules []string

	// Kernel boot parameters found in bootloader strings (e.g. androidboot.*)
	KernelParams []string
}

// IsELF reports whether b begins with the ELF magic header (\x7fELF).
func IsELF(b []byte) bool {
	return len(b) >= len(elf.ELFMAG) && bytes.HasPrefix(b, []byte(elf.ELFMAG))
}

var (
	reQCVersion    = regexp.MustCompile(`QC_IMAGE_VERSION_STRING=([^\x00\r\n]+)`)
	reVariant      = regexp.MustCompile(`IMAGE_VARIANT_STRING=([^\x00\r\n]+)`)
	reOEMBuild     = regexp.MustCompile(`OEM_IMAGE_VERSION_STRING=([^\x00\r\n]+)`)
	reTMEVersion   = regexp.MustCompile(`TME_FW_VERSION_STRING=([^\x00\r\n]+)`)
	reTMEBuildTime = regexp.MustCompile(`TME_FW_BUILD_TIME_STRING=([^\x00\r\n]+)`)
	// The OEM rebuild stamps its time into the image UUID: Q_SENTINEL_{…}_YYYYMMDD_HHMM.
	reOEMUUIDTime = regexp.MustCompile(`OEM_IMAGE_UUID_STRING=[^\x00\r\n]*_([0-9]{4})([0-9]{2})([0-9]{2})_([0-9]{2})([0-9]{2})\b`)
	reAndroidBoot = regexp.MustCompile(`\bandroidboot\.([a-zA-Z0-9_.-]+(?:=[^\s\x00"]+)?)`)

	variantMu  sync.RWMutex
	customVars map[string]string
)

// SetVariantMap explicitly sets the variant-to-SoC mapping used by bootelf.
// Pass nil to reset to the default catalog-driven resolution.
func SetVariantMap(m map[string]string) {
	variantMu.Lock()
	defer variantMu.Unlock()
	if m == nil {
		customVars = nil
		return
	}
	customVars = make(map[string]string, len(m))
	for k, v := range m {
		customVars[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
}

// LoadVariantYAML parses YAML data containing a top-level `variants:` map
// and sets it as the active variant map.
func LoadVariantYAML(b []byte) error {
	var file struct {
		Variants map[string]string `yaml:"variants"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return err
	}
	SetVariantMap(file.Variants)
	return nil
}

// LoadVariantFile loads a YAML file containing a top-level `variants:` map
// and sets it as the active variant map.
func LoadVariantFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return LoadVariantYAML(b)
}

// Analyze parses an ELF image and extracts architecture, segments, Qualcomm
// build metadata, storage capabilities, secboot credentials, and UEFI structures.
func Analyze(b []byte) (*Info, error) {
	ef, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("parsing ELF: %w", err)
	}
	defer ef.Close()

	info := &Info{}
	if ef.Class == elf.ELFCLASS32 {
		info.Class = 32
	} else {
		info.Class = 64
	}

	if ef.Data == elf.ELFDATA2MSB {
		info.Endian = "MSB"
	} else {
		info.Endian = "LSB"
	}

	info.Type = uint16(ef.Type)
	info.Machine = uint16(ef.Machine)
	info.Arch = machineString(info.Machine)
	info.TypeName = typeString(info.Type)
	info.Entry = ef.Entry

	// Parse Program Headers
	for i, p := range ef.Progs {
		hash := (uint32(p.Flags)>>24)&0xf == 2
		role, qcNibble := classifySegmentRole(p, hash)
		seg := Segment{
			Index:    i,
			Type:     uint32(p.Type),
			Flags:    uint32(p.Flags),
			Offset:   p.Off,
			Vaddr:    p.Vaddr,
			Paddr:    p.Paddr,
			Filesz:   p.Filesz,
			Memsz:    p.Memsz,
			Hash:     hash,
			QCNibble: qcNibble,
			Role:     role,
		}
		if seg.Offset <= uint64(len(b)) && seg.Offset+seg.Filesz <= uint64(len(b)) {
			info.Segments = append(info.Segments, seg)
		}
	}

	// Extract Qualcomm Build and Platform Metadata
	extractQCStrings(b, info)

	// Detect Storage Capabilities (UFS, eMMC)
	info.Storage = detectStorage(b, info)

	// Peek/poke support — the "signed but exploitable" capability.
	info.Peek = secboot.ScanPeek(b)

	// Parse SecBoot Identity (if signed image)
	if id, err := secboot.FromELF(b); err == nil {
		info.Identity = id
	}

	// Auto-resolve SoC via JTAG ID if variant string lookup was unresolved
	if info.TargetSoC == "" && info.Identity != nil && info.Identity.JTAGID != "" {
		if cat, err := catalog.Default(); err == nil && cat != nil {
			if soc, ok := cat.SoCByJTAG(info.Identity.JTAGID); ok && soc != "" {
				info.TargetSoC = soc
			}
		}
	}

	// Extract UEFI Firmware Modules and Kernel Boot Parameters (if present)
	if bytes.Contains(b, []byte("_FVH")) {
		if mods, err := efi.Extract(b); err == nil && len(mods) > 0 {
			modNames := make([]string, 0, len(mods))
			for _, m := range mods {
				name := m.Name
				if name == "" {
					if cat, err := catalog.Default(); err == nil && cat != nil {
						name = cat.EFIGUIDName(m.GUID)
					}
				}
				if name != "" {
					modNames = append(modNames, name)
				} else {
					modNames = append(modNames, m.GUID)
				}
				// Also inspect module data for androidboot.* parameters
				if len(m.Data) > 0 {
					findKernelParams(m.Data, info)
				}
			}
			info.UEFIModules = modNames
		}
	}

	// Compute Memory Topology
	info.Topology = computeTopology(info)

	// Parse Build Provenance
	info.Provenance = parseProvenance(info.OEMBuild)
	if info.Provenance.BuildDate == "" {
		if m := reOEMUUIDTime.FindSubmatch(b); m != nil {
			info.Provenance.BuildDate = fmt.Sprintf("%s.%s.%s-%s:%s", m[1], m[2], m[3], m[4], m[5])
		}
	}

	// Fingerprint Subsystems
	info.Subsystems = fingerprintSubsystems(b, info)

	return info, nil
}

func classifySegmentRole(p *elf.Prog, hash bool) (role string, qcNibble uint8) {
	qcNibble = uint8((uint32(p.Flags) >> 24) & 0xf)
	if hash || qcNibble == 2 {
		return "Hash / Certs", qcNibble
	}
	switch qcNibble {
	case 1:
		return "PageTable", qcNibble
	case 3:
		return "Phdr Table", qcNibble
	}

	switch p.Type {
	case elf.PT_LOAD:
		if p.Flags&elf.PF_X != 0 {
			return "Code", qcNibble
		}
		if p.Filesz == 0 && p.Memsz > 0 {
			return "BSS", qcNibble
		}
		if p.Flags&elf.PF_W != 0 {
			return "Data", qcNibble
		}
		if p.Flags&elf.PF_R != 0 {
			return "Rodata", qcNibble
		}
		return "Loadable", qcNibble
	case elf.PT_NOTE:
		return "Note / Build-ID", qcNibble
	case elf.PT_DYNAMIC:
		return "Dynamic Linking", qcNibble
	case elf.PT_NULL:
		if qcNibble == 7 {
			return "ELF Wrapper", qcNibble
		}
		return "Metadata", qcNibble
	default:
		return "Other", qcNibble
	}
}

func readablePayloads(b []byte, info *Info) []byte {
	var buf bytes.Buffer
	for _, s := range info.Segments {
		// Target PT_LOAD segments that have read permission, are not hash segments, and have non-zero file size
		if s.Type == uint32(elf.PT_LOAD) && s.Flags&uint32(elf.PF_R) != 0 && !s.Hash && s.Filesz > 0 {
			if s.Offset <= uint64(len(b)) && s.Offset+s.Filesz <= uint64(len(b)) {
				buf.Write(b[s.Offset : s.Offset+s.Filesz])
			}
		}
	}
	if buf.Len() == 0 {
		return b
	}
	return buf.Bytes()
}

func computeTopology(info *Info) ExecutionTopology {
	var top ExecutionTopology
	var minPaddr uint64 = ^uint64(0)
	var maxEnd uint64 = 0
	var totalMemsz uint64 = 0
	hasLoad := false

	for _, s := range info.Segments {
		if s.Type == uint32(elf.PT_LOAD) && (s.Memsz > 0 || s.Filesz > 0) { // PT_LOAD with non-zero memory or file size
			hasLoad = true
			totalMemsz += s.Memsz
			if s.Paddr < minPaddr {
				minPaddr = s.Paddr
			}
			end := s.Paddr + s.Memsz
			if end > maxEnd {
				maxEnd = end
			}

			// Breakdown by permissions and allocation
			if s.Flags&uint32(elf.PF_X) != 0 {
				top.CodeBytes += s.Filesz
			} else if s.Filesz > 0 {
				top.DataBytes += s.Filesz
			}
			if s.Memsz > s.Filesz {
				top.BSSBytes += (s.Memsz - s.Filesz)
			}
		}
	}

	if hasLoad && minPaddr <= maxEnd {
		top.BaseAddr = minPaddr
		top.EndAddr = maxEnd
		top.TotalMemKB = (totalMemsz + 1023) / 1024
	}

	// Classify execution region: prefer entry point if non-zero, otherwise base load address
	refAddr := top.BaseAddr
	if info.Entry != 0 {
		refAddr = info.Entry
	}

	switch {
	case info.Machine == MachineQDSP6:
		top.Region = "Hexagon DSP (Low-Power Core)"
	case strings.Contains(info.QCVersion, "TZ.") || info.Identity.SWType() == 7 || (refAddr >= 0x14680000 && refAddr < 0x14700000):
		top.Region = "EL3 Secure Monitor (TrustZone)"
	case refAddr >= 0x80000000:
		top.Region = "DRAM (High Memory / Post-Training)"
	case refAddr >= 0x08000000 && refAddr < 0x20000000:
		top.Region = "SRAM (Internal On-Chip / Pre-DDR)"
	case hasLoad:
		top.Region = "Direct Physical Memory"
	default:
		top.Region = "Relocatable / Non-Loaded"
	}

	return top
}

var reProvenance = regexp.MustCompile(`(?:android-build\s+)?([a-zA-Z0-9_.-]+)\s+([0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9]{2}:[0-9]{2})\s+([a-f0-9]{6,40})`)

func parseProvenance(oemBuild string) BuildProvenance {
	var prov BuildProvenance
	oemBuild = strings.TrimSpace(oemBuild)
	if oemBuild == "" {
		return prov
	}

	if m := reProvenance.FindStringSubmatch(oemBuild); len(m) == 4 {
		prov.Builder = m[1]
		prov.BuildDate = m[2]
		prov.CommitSHA = m[3]
		return prov
	}

	// Fallback for single-token strings like "crm-ubuntu96" or "android-build"
	tokens := strings.Fields(oemBuild)
	if len(tokens) == 1 {
		prov.Builder = tokens[0]
	} else if len(tokens) == 2 && tokens[0] == "android-build" {
		prov.Builder = tokens[1]
	}
	return prov
}

func fingerprintSubsystems(b []byte, info *Info) Subsystems {
	var sub Subsystems
	data := readablePayloads(b, info)

	// 1. Motorola UTAGs NV
	hasUTAGs := false
	for _, m := range info.UEFIModules {
		if strings.Contains(m, "MotUtags") {
			hasUTAGs = true
			break
		}
	}
	if !hasUTAGs {
		hasUTAGs = bytes.Contains(data, []byte("UTAGS")) || bytes.Contains(data, []byte("utags"))
		if !hasUTAGs && len(data) != len(b) {
			hasUTAGs = bytes.Contains(b, []byte("UTAGS")) || bytes.Contains(b, []byte("utags"))
		}
	}
	if hasUTAGs {
		sub.MotorolaUTAGs = true
		sub.Details = append(sub.Details, "Motorola UTAGs NV")
	}

	// 2. Pre-Kernel Verified Boot (AVB 2.0)
	hasAVB := false
	for _, m := range info.UEFIModules {
		if strings.Contains(m, "VerifiedBoot") {
			hasAVB = true
			break
		}
	}
	if !hasAVB {
		hasAVB = bytes.Contains(data, []byte("avb_slot_verify")) || bytes.Contains(data, []byte("avb_version"))
		if !hasAVB && len(data) != len(b) {
			hasAVB = bytes.Contains(b, []byte("avb_slot_verify")) || bytes.Contains(b, []byte("avb_version"))
		}
	}
	if hasAVB {
		sub.VerifiedBoot = true
		sub.Details = append(sub.Details, "AVB 2.0 Verified Boot")
	}

	// 3. UEFI Battery Charger
	hasCharger := false
	for _, m := range info.UEFIModules {
		if strings.Contains(m, "Charger") {
			hasCharger = true
			break
		}
	}
	if hasCharger {
		sub.BatteryCharge = true
		sub.Details = append(sub.Details, "UEFI Battery Charger")
	}

	// 4. Shared Memory Multi-Core IPC (SMEM)
	hasSMEM := false
	for _, m := range info.UEFIModules {
		if strings.Contains(m, "Smem") {
			hasSMEM = true
			break
		}
	}
	if !hasSMEM {
		hasSMEM = bytes.Contains(data, []byte("smem_alloc")) || bytes.Contains(data, []byte("SMEM"))
		if !hasSMEM && len(data) != len(b) {
			hasSMEM = bytes.Contains(b, []byte("smem_alloc")) || bytes.Contains(b, []byte("SMEM"))
		}
	}
	if hasSMEM {
		sub.SharedMemory = true
		sub.Details = append(sub.Details, "SMEM Multi-Core IPC")
	}

	// 5. Trust Management Engine (TME)
	if info.TMEVersion != "" || bytes.Contains(data, []byte("ssg.tmefw")) || bytes.Contains(b, []byte("ssg.tmefw")) {
		sub.TME = true
		sub.Details = append(sub.Details, "TME Security Enclave")
	}

	// 6. Fastboot / ABL UI
	if info.Identity.SWType() == 28 || bytes.Contains(data, []byte("fastboot_publish")) || bytes.Contains(b, []byte("fastboot_publish")) {
		sub.FastbootUI = true
		sub.Details = append(sub.Details, "Fastboot / ABL UI")
	}

	return sub
}

func extractQCStrings(b []byte, info *Info) {
	data := readablePayloads(b, info)
	scan := func(src []byte) {
		if info.QCVersion == "" {
			if m := reQCVersion.FindSubmatch(src); len(m) > 1 {
				info.QCVersion = cleanString(string(m[1]))
			}
		}
		if info.Variant == "" {
			if m := reVariant.FindSubmatch(src); len(m) > 1 {
				info.Variant = cleanString(string(m[1]))
			}
		}
		if info.OEMBuild == "" {
			if m := reOEMBuild.FindSubmatch(src); len(m) > 1 {
				info.OEMBuild = cleanString(string(m[1]))
			}
		}
		if info.TMEVersion == "" {
			if m := reTMEVersion.FindSubmatch(src); len(m) > 1 {
				info.TMEVersion = cleanString(string(m[1]))
			}
		}
		if info.TMEBuildTime == "" {
			if m := reTMEBuildTime.FindSubmatch(src); len(m) > 1 {
				info.TMEBuildTime = cleanString(string(m[1]))
			}
		}
	}

	scan(data)
	if (info.QCVersion == "" || info.Variant == "") && len(data) != len(b) {
		scan(b)
	}

	// Qualcomm's CRM build directory is named <QCVersion>_YYYYMMDD_HHMMSS and
	// survives in __FILE__ paths. Anchoring on this image's own version skips
	// paths from prebuilt libraries of other builds.
	if info.QCVersion != "" {
		re := regexp.MustCompile(`CRMBuilds/` + regexp.QuoteMeta(info.QCVersion) + `_([0-9]{4})([0-9]{2})([0-9]{2})_([0-9]{2})([0-9]{2})([0-9]{2})/`)
		if m := re.FindSubmatch(b); m != nil {
			info.QCBuildTime = fmt.Sprintf("%s.%s.%s-%s:%s:%s", m[1], m[2], m[3], m[4], m[5], m[6])
		}
	}

	// Resolve target SoC
	info.TargetSoC = resolveSoC(info.Variant, info.QCVersion)
}

func resolveSoC(variant, qcVersion string) string {
	variantMu.RLock()
	vars := customVars
	variantMu.RUnlock()

	if len(vars) > 0 {
		return matchVariantMap(vars, variant, qcVersion)
	}

	if cat, err := catalog.Default(); err == nil && cat != nil {
		if moniker := cat.ResolveVariant(variant, qcVersion); moniker != "" {
			return moniker
		}
	}

	return ""
}

func matchVariantMap(vars map[string]string, variant, qcVersion string) string {
	if len(vars) == 0 {
		return ""
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	vLower := strings.ToLower(variant)
	if vLower != "" {
		for _, k := range keys {
			if strings.HasPrefix(vLower, k) || strings.Contains(vLower, k) {
				return vars[k]
			}
		}
		for _, k := range keys {
			core := strings.TrimPrefix(k, "soc")
			if len(core) >= 4 && (strings.Contains(vLower, core) || strings.HasPrefix(vLower, core)) {
				return vars[k]
			}
		}
	}

	qUpper := strings.ToUpper(qcVersion)
	if qUpper != "" {
		for _, k := range keys {
			if strings.Contains(qUpper, strings.ToUpper(k)) {
				return vars[k]
			}
		}
		for _, k := range keys {
			core := strings.TrimPrefix(k, "soc")
			if len(core) >= 4 && strings.Contains(qUpper, strings.ToUpper(core)) {
				return vars[k]
			}
		}
	}

	return ""
}

func detectStorage(b []byte, info *Info) []string {
	data := readablePayloads(b, info)
	st := scanStorage(data)
	if len(st) == 0 && len(data) != len(b) {
		st = scanStorage(b)
	}
	return st
}

func scanStorage(b []byte) []string {
	hasUFS := bytes.Contains(b, []byte("devprg_storage_ufs")) ||
		bytes.Contains(b, []byte("UFS INQUIRY")) ||
		bytes.Contains(b, []byte("ufs_phy")) ||
		bytes.Contains(b, []byte("Device type ufs")) ||
		bytes.Contains(b, []byte("Setting UFS provisioning")) ||
		bytes.Contains(b, []byte("memoryname is ufs"))

	hasEMMC := bytes.Contains(b, []byte("devprg_storage_sdcc")) ||
		bytes.Contains(b, []byte("eMMC Extended CSD")) ||
		bytes.Contains(b, []byte("eMMC Firmware Version")) ||
		bytes.Contains(b, []byte("eMMC_RAW_DATA")) ||
		bytes.Contains(b, []byte("Error: eMMC read fail")) ||
		bytes.Contains(b, []byte("mem_type\":\"eMMC\"")) ||
		bytes.Contains(b, []byte("memoryname is emmc"))

	var out []string
	if hasUFS {
		out = append(out, "ufs")
	}
	if hasEMMC {
		out = append(out, "emmc")
	}
	return out
}

func findKernelParams(data []byte, info *Info) {
	matches := reAndroidBoot.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return
	}
	paramSet := map[string]bool{}
	for _, p := range info.KernelParams {
		paramSet[p] = true
	}
	for _, m := range matches {
		if len(m) > 1 {
			param := string(m[1])
			if !paramSet[param] && len(param) > 1 && len(param) < 40 {
				paramSet[param] = true
				info.KernelParams = append(info.KernelParams, param)
			}
		}
	}
	sort.Strings(info.KernelParams)
}

func machineString(m uint16) string {
	switch m {
	case MachineARM:
		return "ARM"
	case MachineAArch64:
		return "AArch64"
	case MachineQDSP6:
		return "QDSP6 (Hexagon)"
	case Machine386:
		return "x86"
	case MachineX86_64:
		return "x86_64"
	case MachineRISCV:
		return "RISC-V"
	default:
		return fmt.Sprintf("Machine-0x%04x", m)
	}
}

func typeString(t uint16) string {
	switch t {
	case TypeRel:
		return "REL (Relocatable)"
	case TypeExec:
		return "EXEC (Executable)"
	case TypeDyn:
		return "DYN (Shared object)"
	case TypeCore:
		return "CORE"
	default:
		return fmt.Sprintf("Type-%d", t)
	}
}

func cleanString(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.IndexAny(s, "\x00\r\n"); idx >= 0 {
		s = s[:idx]
	}
	return s
}
