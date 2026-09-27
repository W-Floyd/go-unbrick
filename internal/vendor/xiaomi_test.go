package vendor_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/W-Floyd/go-unbrick/internal/payload"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

func TestXiaomiDriverRegistration(t *testing.T) {
	d, ok := vendor.For("xiaomi")
	if !ok {
		t.Fatalf("xiaomi driver not found in registry")
	}
	if d.Platform() != vendor.PlatformQualcomm {
		t.Errorf("expected platform qualcomm, got %s", d.Platform())
	}
	oemIDs := d.OEMIDs()
	expectedOEMs := map[string]bool{"0072": false, "0000": false, "0001": false, "0003": false}
	for _, id := range oemIDs {
		expectedOEMs[id] = true
	}
	for oem, found := range expectedOEMs {
		if !found {
			t.Errorf("expected OEM ID %s in xiaomi driver", oem)
		}
	}
}

func TestXiaomiCanIngest(t *testing.T) {
	d, ok := vendor.For("xiaomi")
	if !ok {
		t.Fatal("xiaomi driver not found")
	}

	tmpDir := t.TempDir()

	// 1. Xiaomi codename in directory or file name
	miuiDir := filepath.Join(tmpDir, "miui_APOLLO_Global_V12")
	if err := os.MkdirAll(miuiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !d.CanIngest(miuiDir) {
		t.Errorf("CanIngest should accept directory with miui in name")
	}

	// 2. Fastboot .tgz
	tgzFile := filepath.Join(tmpDir, "firmware.tgz")
	if err := os.WriteFile(tgzFile, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !d.CanIngest(tgzFile) {
		t.Errorf("CanIngest should accept .tgz file")
	}

	// 3. payload.bin
	payloadFile := filepath.Join(tmpDir, "payload.bin")
	if err := os.WriteFile(payloadFile, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !d.CanIngest(payloadFile) {
		t.Errorf("CanIngest should accept payload.bin")
	}
}

func createTestTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func createTestZip(t *testing.T, files map[string][]byte, storeOnly bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for name, content := range files {
		method := zip.Deflate
		if storeOnly {
			method = zip.Store
		}
		hdr := &zip.FileHeader{
			Name:   name,
			Method: uint16(method),
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestXiaomiFastbootTarIngestion(t *testing.T) {
	d, ok := vendor.For("xiaomi")
	if !ok {
		t.Fatal("xiaomi driver not found")
	}
	tmpDir := t.TempDir()

	rawProg := `<data><program SECTOR_SIZE_IN_BYTES="4096" file_sector_offset="0" filename="xbl.elf" label="xbl_a" num_partition_sectors="1024" physical_partition_number="0" size_in_KB="4096" sparse="false" start_byte_hex="0x200000" start_sector="512"/></data>`
	firehoseProg := bytes.Repeat([]byte("FIREHOSE_PROGRAMMER_BINARY"), 100)
	xblData := bytes.Repeat([]byte("XBL_ELF_STAGE"), 200)
	gptData := make([]byte, 16384)
	copy(gptData[4096:], "EFI PART")

	archiveBytes := createTestTarGz(t, map[string][]byte{
		"images/prog_firehose_lite.elf": firehoseProg,
		"images/rawprogram0.xml":        []byte(rawProg),
		"images/xbl.elf":                xblData,
		"images/gpt_main0.bin":          gptData,
	})

	tarPath := filepath.Join(tmpDir, "apollo_fastboot.tgz")
	if err := os.WriteFile(tarPath, archiveBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. IngestDonor from tar
	donor, err := d.IngestDonor(tarPath)
	if err != nil {
		t.Fatalf("IngestDonor from tar failed: %v", err)
	}
	if !bytes.Equal(donor.Programmer, firehoseProg) {
		t.Fatalf("donor programmer mismatch")
	}
	if len(donor.Recipes) == 0 || donor.Recipes["rawprogram0.xml"] == nil {
		t.Fatalf("expected rawprogram0.xml in donor recipes")
	}

	// 2. HarvestStock from tar
	target, err := d.HarvestStock(vendor.TargetSource{
		Bootloader: tarPath,
		Slot:       "a",
	})
	if err != nil {
		t.Fatalf("HarvestStock from tar failed: %v", err)
	}
	if !bytes.Equal(target.GPT, gptData) {
		t.Fatalf("target GPT mismatch")
	}
	if target.Parts["xbl"] == nil && target.Parts["xbl.elf"] == nil {
		t.Fatalf("xbl partition not found in target")
	}
	if len(target.FlashOrder) == 0 || target.FlashOrder[0] != "xbl" {
		t.Fatalf("expected FlashOrder with xbl, got: %v", target.FlashOrder)
	}

	// 3. Assemble
	res, err := d.Assemble(donor, target, vendor.AssembleOptions{
		Slot:    "a",
		Storage: "ufs",
	})
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}
	if res.Aux == nil {
		t.Fatalf("expected Aux files map in ForgeResult")
	}
	if res.Aux["prog_firehose_lite.elf"] == nil {
		t.Errorf("missing programmer in forged bundle")
	}
	if res.Aux["rawprogram0.xml"] == nil {
		t.Errorf("missing rawprogram0.xml in forged bundle")
	}
	if res.Aux["flash.sh"] == nil {
		t.Errorf("missing flash.sh in forged bundle")
	}
}

func TestXiaomiRecoveryZipAliasTranslation(t *testing.T) {
	d, ok := vendor.For("xiaomi")
	if !ok {
		t.Fatal("xiaomi driver not found")
	}
	tmpDir := t.TempDir()

	qupfwData := []byte("QUP3_FIRMWARE_DATA")
	uefiData := []byte("UEFI_SECURITY_DATA")
	kmData := []byte("KEYMASTER_MBN_DATA")
	modemData := []byte("BASEBAND_MODEM_DATA")
	gptData := make([]byte, 16384)
	copy(gptData[4096:], "EFI PART")

	zipBytes := createTestZip(t, map[string][]byte{
		"firmware-update/qupv3fw.elf":   qupfwData,
		"firmware-update/uefi_sec.mbn":  uefiData,
		"firmware-update/km4.mbn":       kmData,
		"firmware-update/NON-HLOS.bin":  modemData,
		"firmware-update/gpt_main0.bin": gptData,
	}, false)

	zipPath := filepath.Join(tmpDir, "miui_recovery.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	target, err := d.HarvestStock(vendor.TargetSource{
		Bootloader: zipPath,
		Slot:       "a",
	})
	if err != nil {
		t.Fatalf("HarvestStock from recovery zip failed: %v", err)
	}

	// Verify alias resolutions
	if !bytes.Equal(target.Parts["qupfw"], qupfwData) {
		t.Errorf("qupv3fw.elf was not mapped to canonical 'qupfw'")
	}
	if !bytes.Equal(target.Parts["uefisecapp"], uefiData) {
		t.Errorf("uefi_sec.mbn was not mapped to canonical 'uefisecapp'")
	}
	if !bytes.Equal(target.Parts["keymaster"], kmData) {
		t.Errorf("km4.mbn was not mapped to canonical 'keymaster'")
	}
	if !bytes.Equal(target.Parts["modem"], modemData) {
		t.Errorf("NON-HLOS.bin was not mapped to canonical 'modem'")
	}
}

func TestXiaomiOTAPayloadIngestion(t *testing.T) {
	d, ok := vendor.For("xiaomi")
	if !ok {
		t.Fatal("xiaomi driver not found")
	}
	tmpDir := t.TempDir()

	xblContent := bytes.Repeat([]byte("XBL_DATA_"), 512) // 4608 bytes
	ablContent := bytes.Repeat([]byte("ABL_DATA_"), 512)

	manifest := &payload.DeltaArchiveManifest{
		BlockSize:    proto.Uint32(4096),
		MinorVersion: proto.Uint32(0),
		Partitions: []*payload.PartitionUpdate{
			{
				PartitionName: proto.String("xbl_a"),
				Operations: []*payload.InstallOperation{
					{
						Type:       payload.InstallOperation_REPLACE.Enum(),
						DataOffset: proto.Uint64(0),
						DataLength: proto.Uint64(uint64(len(xblContent))),
						DstExtents: []*payload.Extent{
							{StartBlock: proto.Uint64(0), NumBlocks: proto.Uint64(2)},
						},
					},
				},
				NewPartitionInfo: &payload.PartitionInfo{Size: proto.Uint64(uint64(len(xblContent)))},
			},
			{
				PartitionName: proto.String("abl_a"),
				Operations: []*payload.InstallOperation{
					{
						Type:       payload.InstallOperation_REPLACE.Enum(),
						DataOffset: proto.Uint64(uint64(len(xblContent))),
						DataLength: proto.Uint64(uint64(len(ablContent))),
						DstExtents: []*payload.Extent{
							{StartBlock: proto.Uint64(0), NumBlocks: proto.Uint64(2)},
						},
					},
				},
				NewPartitionInfo: &payload.PartitionInfo{Size: proto.Uint64(uint64(len(ablContent)))},
			},
		},
	}
	manifestBytes, err := proto.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	var pBuf bytes.Buffer
	pBuf.WriteString("CrAU")
	binary.Write(&pBuf, binary.BigEndian, uint64(2))
	binary.Write(&pBuf, binary.BigEndian, uint64(len(manifestBytes)))
	binary.Write(&pBuf, binary.BigEndian, uint32(0))
	pBuf.Write(manifestBytes)
	pBuf.Write(xblContent)
	pBuf.Write(ablContent)

	// Wrap in an OTA update zip
	otaZipBytes := createTestZip(t, map[string][]byte{
		"payload.bin": pBuf.Bytes(),
	}, true)

	otaZipPath := filepath.Join(tmpDir, "ota_update.zip")
	if err := os.WriteFile(otaZipPath, otaZipBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	target, err := d.HarvestStock(vendor.TargetSource{
		Bootloader: otaZipPath,
		Slot:       "a",
	})
	if err != nil {
		t.Fatalf("HarvestStock from OTA zip failed: %v", err)
	}

	if target.Parts["xbl"] == nil {
		t.Errorf("xbl partition not extracted from OTA payload")
	}
	if target.Parts["abl"] == nil {
		t.Errorf("abl partition not extracted from OTA payload")
	}
}
