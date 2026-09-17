package bootelf

import (
	"encoding/binary"
	"os"
	"testing"
)

func buildTestELF(class int, machine uint16, paddr uint64, extra []byte) []byte {
	var buf []byte
	if class == 32 {
		buf = make([]byte, 0x34+32)
		copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
		buf[4] = 1 // 32-bit
		buf[5] = 1 // little-endian
		buf[6] = 1 // version
		binary.LittleEndian.PutUint16(buf[0x10:], TypeExec)
		binary.LittleEndian.PutUint16(buf[0x12:], machine)
		binary.LittleEndian.PutUint32(buf[0x14:], 1)             // e_version
		binary.LittleEndian.PutUint32(buf[0x18:], uint32(paddr)) // entry
		binary.LittleEndian.PutUint32(buf[0x1c:], 0x34)          // phoff
		binary.LittleEndian.PutUint16(buf[0x28:], 52)            // ehsize
		binary.LittleEndian.PutUint16(buf[0x2a:], 32)            // phentsize
		binary.LittleEndian.PutUint16(buf[0x2c:], 1)             // phnum

		// Program header 0
		ph := buf[0x34:]
		binary.LittleEndian.PutUint32(ph[0:], 1)                   // PT_LOAD
		binary.LittleEndian.PutUint32(ph[4:], 0x34+32)             // offset
		binary.LittleEndian.PutUint32(ph[8:], uint32(paddr))       // vaddr
		binary.LittleEndian.PutUint32(ph[12:], uint32(paddr))      // paddr
		binary.LittleEndian.PutUint32(ph[16:], uint32(len(extra))) // filesz
		binary.LittleEndian.PutUint32(ph[20:], uint32(len(extra))) // memsz
		binary.LittleEndian.PutUint32(ph[24:], 7)                  // flags rwx
	} else {
		buf = make([]byte, 0x40+56)
		copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
		buf[4] = 2 // 64-bit
		buf[5] = 1 // little-endian
		buf[6] = 1 // version
		binary.LittleEndian.PutUint16(buf[0x10:], TypeExec)
		binary.LittleEndian.PutUint16(buf[0x12:], machine)
		binary.LittleEndian.PutUint32(buf[0x14:], 1)             // e_version
		binary.LittleEndian.PutUint64(buf[0x18:], paddr)         // entry
		binary.LittleEndian.PutUint64(buf[0x20:], 0x40)          // phoff
		binary.LittleEndian.PutUint16(buf[0x34:], 64)            // ehsize
		binary.LittleEndian.PutUint16(buf[0x36:], 56)            // phentsize
		binary.LittleEndian.PutUint16(buf[0x38:], 1)             // phnum

		// Program header 0
		ph := buf[0x40:]
		binary.LittleEndian.PutUint32(ph[0:], 1)                   // PT_LOAD
		binary.LittleEndian.PutUint32(ph[4:], 7)                   // flags rwx
		binary.LittleEndian.PutUint64(ph[8:], 0x40+56)             // offset
		binary.LittleEndian.PutUint64(ph[16:], paddr)              // vaddr
		binary.LittleEndian.PutUint64(ph[24:], paddr)              // paddr
		binary.LittleEndian.PutUint64(ph[32:], uint64(len(extra))) // filesz
		binary.LittleEndian.PutUint64(ph[40:], uint64(len(extra))) // memsz
	}
	return append(buf, extra...)
}

func TestAnalyze32(t *testing.T) {
	extra := []byte("QC_IMAGE_VERSION_STRING=BOOT.XF.3.2-00336-SM8250-1\x00IMAGE_VARIANT_STRING=Soc8250LAA\x00UFS INQUIRY\x00")
	elfBytes := buildTestELF(32, MachineARM, 0x80000000, extra)

	info, err := Analyze(elfBytes)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if info.Class != 32 {
		t.Errorf("class: got %d, want 32", info.Class)
	}
	if info.Arch != "ARM" {
		t.Errorf("arch: got %s, want ARM", info.Arch)
	}
	if info.QCVersion != "BOOT.XF.3.2-00336-SM8250-1" {
		t.Errorf("qc_version: got %q", info.QCVersion)
	}
	if info.Variant != "Soc8250LAA" {
		t.Errorf("variant: got %q", info.Variant)
	}
	if info.TargetSoC != "Qualcomm SM8250 Snapdragon 865/870" {
		t.Errorf("target_soc: got %q", info.TargetSoC)
	}
	if len(info.Storage) != 1 || info.Storage[0] != "ufs" {
		t.Errorf("storage: got %v, want [ufs]", info.Storage)
	}
}

func TestAnalyze64(t *testing.T) {
	extra := []byte("QC_IMAGE_VERSION_STRING=BOOT.MXF.2.1.1-00053-KAILUA-1.16789.3\x00IMAGE_VARIANT_STRING=SocKailuaLAA\x00devprg_storage_sdcc\x00ufs_phy\x00")
	elfBytes := buildTestELF(64, MachineAArch64, 0x90000000, extra)

	info, err := Analyze(elfBytes)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if info.Class != 64 {
		t.Errorf("class: got %d, want 64", info.Class)
	}
	if info.Arch != "AArch64" {
		t.Errorf("arch: got %s, want AArch64", info.Arch)
	}
	if info.Variant != "SocKailuaLAA" {
		t.Errorf("variant: got %q", info.Variant)
	}
	if info.TargetSoC != "Qualcomm SM8550 Snapdragon 8 Gen 2" {
		t.Errorf("target_soc: got %q", info.TargetSoC)
	}
	if len(info.Storage) != 2 || info.Storage[0] != "ufs" || info.Storage[1] != "emmc" {
		t.Errorf("storage: got %v, want [ufs, emmc]", info.Storage)
	}
}

func TestAnalyzeHexagonDSP(t *testing.T) {
	elfBytes := buildTestELF(32, MachineQDSP6, 0x10000000, []byte("dummy"))
	info, err := Analyze(elfBytes)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if info.Arch != "QDSP6 (Hexagon)" {
		t.Errorf("arch: got %s, want QDSP6 (Hexagon)", info.Arch)
	}
}

func TestAnalyzeRejectsNonELF(t *testing.T) {
	if _, err := Analyze([]byte("not an elf binary")); err == nil {
		t.Error("expected error on non-ELF")
	}
	if _, err := Analyze([]byte{0x7f, 'E', 'L', 'F'}); err == nil {
		t.Error("expected error on truncated ELF")
	}
}

func TestAnalyzeRealFiles(t *testing.T) {
	// Test on real pstar loader
	path := "../../library/loaders/motorola/000C30E1/pstar_RRA31.Q3-19-50/programmer.elf"
	if b, err := os.ReadFile(path); err == nil {
		info, err := Analyze(b)
		if err != nil {
			t.Fatalf("Analyze(%s): %v", path, err)
		}
		if info.Arch != "AArch64" {
			t.Errorf("expected AArch64, got %s", info.Arch)
		}
		if info.Variant != "Soc8250LAA" {
			t.Errorf("expected Soc8250LAA, got %s", info.Variant)
		}
		if info.TargetSoC != "Qualcomm SM8250 Snapdragon 865/870" {
			t.Errorf("expected SM8250, got %s", info.TargetSoC)
		}
		if info.Identity == nil || info.Identity.JTAGID != "000C30E1" {
			t.Errorf("expected JTAG 000C30E1, got %v", info.Identity)
		}
	}

	// Test on real ginna eMMC loader
	ginnaPath := "../../library/loaders/motorola/000BA0E1/ginna_10_QPGS30.82-141-15-7/programmer.elf"
	if b, err := os.ReadFile(ginnaPath); err == nil {
		info, err := Analyze(b)
		if err != nil {
			t.Fatalf("Analyze(%s): %v", ginnaPath, err)
		}
		if len(info.Storage) != 1 || info.Storage[0] != "emmc" {
			t.Errorf("ginna storage: got %v, want [emmc]", info.Storage)
		}
	}

	// Test on real rtwo Kailua loader
	rtwoPath := "../../library/loaders/motorola/SM_KAILUA/rtwo_retcn_T1TR33.4-30-10-2/programmer.elf"
	if b, err := os.ReadFile(rtwoPath); err == nil {
		info, err := Analyze(b)
		if err != nil {
			t.Fatalf("Analyze(%s): %v", rtwoPath, err)
		}
		if info.Variant != "SocKailuaLAA" {
			t.Errorf("expected SocKailuaLAA, got %s", info.Variant)
		}
		if info.TargetSoC != "Qualcomm SM8550 Snapdragon 8 Gen 2" {
			t.Errorf("expected SM8550, got %s", info.TargetSoC)
		}
	}
}

func TestFindKernelParams(t *testing.T) {
	data := []byte("console=ttyMSM0 androidboot.bootdevice=soc/1d84000.ufshc androidboot.verifiedbootstate=green androidboot.serialno=12345")
	info := &Info{}
	findKernelParams(data, info)

	expected := []string{"bootdevice=soc/1d84000.ufshc", "serialno=12345", "verifiedbootstate=green"}
	if len(info.KernelParams) != len(expected) {
		t.Fatalf("kernel params count: got %v, want %v", info.KernelParams, expected)
	}
	for i, want := range expected {
		if info.KernelParams[i] != want {
			t.Errorf("param %d: got %q, want %q", i, info.KernelParams[i], want)
		}
	}
}

func TestDynamicVariantMap(t *testing.T) {
	// Ensure reset at end of test
	defer SetVariantMap(nil)

	// 1. Test explicit SetVariantMap override
	SetVariantMap(map[string]string{
		"soctestchip": "Test Custom SoC",
	})
	got := resolveSoC("SocTestChipLAA", "")
	if got != "Test Custom SoC" {
		t.Errorf("expected 'Test Custom SoC', got %q", got)
	}

	// 2. Test LoadVariantYAML
	customYAML := []byte(`variants:
  soccustom: "Snapdragon Custom 999"
`)
	if err := LoadVariantYAML(customYAML); err != nil {
		t.Fatalf("LoadVariantYAML failed: %v", err)
	}
	got = resolveSoC("SocCustomLAA", "")
	if got != "Snapdragon Custom 999" {
		t.Errorf("expected 'Snapdragon Custom 999', got %q", got)
	}

	// 3. Reset to nil and verify fallback to catalog
	SetVariantMap(nil)
	got = resolveSoC("Soc8250LAA", "")
	if got != "Qualcomm SM8250 Snapdragon 865/870" {
		t.Errorf("expected catalog fallback to resolve Soc8250LAA, got %q", got)
	}
}

func TestTopologyProvenanceSubsystems(t *testing.T) {
	extra := []byte("OEM_IMAGE_VERSION_STRING=android-build hudsoncm 2021.08.04-07:36 d68ca9415\x00UTAGS\x00avb_version 1.2\x00")
	// Load address in SRAM range: 0x14800000
	elfBytes := buildTestELF(64, MachineAArch64, 0x14800000, extra)

	info, err := Analyze(elfBytes)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// 1. Check Provenance
	if info.Provenance.Builder != "hudsoncm" {
		t.Errorf("builder: got %q, want hudsoncm", info.Provenance.Builder)
	}
	if info.Provenance.BuildDate != "2021.08.04-07:36" {
		t.Errorf("build date: got %q, want 2021.08.04-07:36", info.Provenance.BuildDate)
	}
	if info.Provenance.CommitSHA != "d68ca9415" {
		t.Errorf("commit SHA: got %q, want d68ca9415", info.Provenance.CommitSHA)
	}

	// 2. Check Topology
	if info.Topology.BaseAddr != 0x14800000 {
		t.Errorf("base addr: got 0x%x, want 0x14800000", info.Topology.BaseAddr)
	}
	if info.Topology.Region != "SRAM (Internal On-Chip / Pre-DDR)" {
		t.Errorf("region: got %q, want SRAM (Internal On-Chip / Pre-DDR)", info.Topology.Region)
	}

	// 3. Check Subsystems
	if !info.Subsystems.MotorolaUTAGs {
		t.Error("expected Motorola UTAGs detected")
	}
	if !info.Subsystems.VerifiedBoot {
		t.Error("expected AVB VerifiedBoot detected")
	}
}

func TestMemoryFootprintAndRoles(t *testing.T) {
	const phnum = 5
	const phentsize = 56
	const phoff = 64
	hdr := make([]byte, phoff+phnum*phentsize)
	copy(hdr[0:4], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = 2 // 64-bit
	hdr[5] = 1 // little-endian
	hdr[6] = 1 // version
	binary.LittleEndian.PutUint16(hdr[0x10:], TypeExec)
	binary.LittleEndian.PutUint16(hdr[0x12:], MachineAArch64)
	binary.LittleEndian.PutUint32(hdr[0x14:], 1)          // e_version
	binary.LittleEndian.PutUint64(hdr[0x18:], 0x14000000) // entry
	binary.LittleEndian.PutUint64(hdr[0x20:], phoff)
	binary.LittleEndian.PutUint16(hdr[0x34:], 64)
	binary.LittleEndian.PutUint16(hdr[0x36:], phentsize)
	binary.LittleEndian.PutUint16(hdr[0x38:], phnum)

	rodata := []byte("QC_IMAGE_VERSION_STRING=TEST.BOOT.1.0\x00IMAGE_VARIANT_STRING=SocTest\x00devprg_storage_ufs\x00")
	code := make([]byte, 1000)
	pt := make([]byte, 100)

	baseOff := uint64(len(hdr))
	codeOff := baseOff
	rodataOff := codeOff + uint64(len(code))
	ptOff := rodataOff + uint64(len(rodata))

	// 0: PT_NULL, flags=0x7000000 (ELF Wrapper)
	p0 := hdr[phoff:]
	binary.LittleEndian.PutUint32(p0[0:], 0) // PT_NULL
	binary.LittleEndian.PutUint32(p0[4:], 0x7000000)

	// 1: PT_LOAD, flags=PF_X|PF_R (Code)
	p1 := hdr[phoff+phentsize:]
	binary.LittleEndian.PutUint32(p1[0:], 1) // PT_LOAD
	binary.LittleEndian.PutUint32(p1[4:], 5) // PF_X | PF_R
	binary.LittleEndian.PutUint64(p1[8:], codeOff)
	binary.LittleEndian.PutUint64(p1[16:], 0x14000000)
	binary.LittleEndian.PutUint64(p1[24:], 0x14000000)
	binary.LittleEndian.PutUint64(p1[32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(p1[40:], uint64(len(code)))

	// 2: PT_LOAD, flags=PF_R (Rodata)
	p2 := hdr[phoff+2*phentsize:]
	binary.LittleEndian.PutUint32(p2[0:], 1) // PT_LOAD
	binary.LittleEndian.PutUint32(p2[4:], 4) // PF_R
	binary.LittleEndian.PutUint64(p2[8:], rodataOff)
	binary.LittleEndian.PutUint64(p2[16:], 0x14001000)
	binary.LittleEndian.PutUint64(p2[24:], 0x14001000)
	binary.LittleEndian.PutUint64(p2[32:], uint64(len(rodata)))
	binary.LittleEndian.PutUint64(p2[40:], uint64(len(rodata)))

	// 3: PT_LOAD, flags=PF_W|PF_R (BSS, filesz=0, memsz=4000)
	p3 := hdr[phoff+3*phentsize:]
	binary.LittleEndian.PutUint32(p3[0:], 1) // PT_LOAD
	binary.LittleEndian.PutUint32(p3[4:], 6) // PF_W | PF_R
	binary.LittleEndian.PutUint64(p3[8:], ptOff)
	binary.LittleEndian.PutUint64(p3[16:], 0x14002000)
	binary.LittleEndian.PutUint64(p3[24:], 0x14002000)
	binary.LittleEndian.PutUint64(p3[32:], 0)    // filesz=0
	binary.LittleEndian.PutUint64(p3[40:], 4000) // memsz=4000

	// 4: PT_LOAD, flags=0x1000000|PF_X|PF_W|PF_R (PageTable)
	p4 := hdr[phoff+4*phentsize:]
	binary.LittleEndian.PutUint32(p4[0:], 1) // PT_LOAD
	binary.LittleEndian.PutUint32(p4[4:], 0x1000007)
	binary.LittleEndian.PutUint64(p4[8:], ptOff)
	binary.LittleEndian.PutUint64(p4[16:], 0x14003000)
	binary.LittleEndian.PutUint64(p4[24:], 0x14003000)
	binary.LittleEndian.PutUint64(p4[32:], uint64(len(pt)))
	binary.LittleEndian.PutUint64(p4[40:], uint64(len(pt)))

	payload := append(hdr, code...)
	payload = append(payload, rodata...)
	payload = append(payload, pt...)

	info, err := Analyze(payload)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(info.Segments) != 5 {
		t.Fatalf("expected 5 segments, got %d", len(info.Segments))
	}
	if info.Segments[0].Role != "ELF Wrapper" || info.Segments[0].QCNibble != 7 {
		t.Errorf("seg 0 role: got %q (qc 0x%x), want ELF Wrapper (qc 0x7)", info.Segments[0].Role, info.Segments[0].QCNibble)
	}
	if info.Segments[1].Role != "Code" {
		t.Errorf("seg 1 role: got %q, want Code", info.Segments[1].Role)
	}
	if info.Segments[2].Role != "Rodata" {
		t.Errorf("seg 2 role: got %q, want Rodata", info.Segments[2].Role)
	}
	if info.Segments[3].Role != "BSS" {
		t.Errorf("seg 3 role: got %q, want BSS", info.Segments[3].Role)
	}
	if info.Segments[4].Role != "PageTable" || info.Segments[4].QCNibble != 1 {
		t.Errorf("seg 4 role: got %q (qc 0x%x), want PageTable (qc 0x1)", info.Segments[4].Role, info.Segments[4].QCNibble)
	}

	if info.Topology.CodeBytes != uint64(len(code)+len(pt)) {
		t.Errorf("code bytes: got %d, want %d", info.Topology.CodeBytes, len(code)+len(pt))
	}
	if info.Topology.DataBytes != uint64(len(rodata)) {
		t.Errorf("data bytes: got %d, want %d", info.Topology.DataBytes, len(rodata))
	}
	if info.Topology.BSSBytes != 4000 {
		t.Errorf("bss bytes: got %d, want 4000", info.Topology.BSSBytes)
	}
	if info.QCVersion != "TEST.BOOT.1.0" {
		t.Errorf("qc version: got %q, want TEST.BOOT.1.0", info.QCVersion)
	}
	if len(info.Storage) != 1 || info.Storage[0] != "ufs" {
		t.Errorf("storage: got %v, want [ufs]", info.Storage)
	}
}



