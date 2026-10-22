package filetype

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDetect(t *testing.T) {
	ext4 := make([]byte, 0x440)
	binary.LittleEndian.PutUint16(ext4[0x438:], 0xEF53)
	gpt := make([]byte, 520)
	copy(gpt[512:], "EFI PART")
	gpt4k := make([]byte, 4104)
	copy(gpt4k[4096:], "EFI PART")
	sparse := make([]byte, 4)
	binary.LittleEndian.PutUint32(sparse, 0xed26ff3a)
	erofs := make([]byte, 1028)
	binary.LittleEndian.PutUint32(erofs[1024:], 0xe0f5e1e2)
	dtbo := []byte{0xd7, 0xb7, 0xab, 0x1e}
	fdt := []byte{0xd0, 0x0d, 0xfe, 0xed}

	cases := []struct {
		name string
		head []byte
		want Kind
	}{
		{"zip", []byte("PK\x03\x04rest"), Zip},
		{"arm64 image", func() []byte { b := make([]byte, 0x40); copy(b, "MZ"); copy(b[0x38:], "ARM\x64"); return b }(), ARM64Image},
		{"elf", []byte("\x7fELFrest"), ELF},
		{"snl", []byte("SINGLE_N_LONELY\x00more"), SingleNLonely},
		{"avb", []byte("AVB0xxxx"), VBMeta},
		{"sparse", sparse, SparseImage},
		{"gpt", gpt, GPT},
		{"gpt-4k", gpt4k, GPT},
		{"ext4", ext4, Ext4},
		{"erofs", erofs, EROFS},
		{"dtbo", dtbo, DTBOTable},
		{"fdt", fdt, DeviceTree},
		{"android-boot", []byte("ANDROID!xxxxxxxx"), AndroidBoot},
		{"vendor-boot", []byte("VNDRBOOTxxxxxxxx"), AndroidVendorBoot},
		{"qdb", []byte("\x7fQDBxxxx"), QDB},
		{"ubi", []byte("UBI#\x01\x00\x00\x00"), UBI},
		{"ogg", []byte("OggS\x00\x02"), Ogg},
		{"acdb", []byte("QCMSNDDBextra"), ACDB},
		{"unknown", []byte("hello world"), Unknown},
	}
	for _, c := range cases {
		if got := Detect(c.head); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	_ = bytes.MinRead
}

func TestBackupGPT(t *testing.T) {
	img := make([]byte, 5*4096)
	copy(img[4*4096:], "EFI PART")
	if !BackupGPT(img) || Detect(img) != Unknown {
		t.Error("backup GPT image: header in the last sector")
	}
	if BackupGPT(img[:4*4096]) || BackupGPT(make([]byte, 4096)) {
		t.Error("BackupGPT without a header in the last sector")
	}
}

func TestPEAndText(t *testing.T) {
	pe := make([]byte, 0x100)
	copy(pe, "MZ")
	pe[0x3c] = 0x80
	copy(pe[0x80:], "PE\x00\x00")
	if Detect(pe) != PE {
		t.Error("PE not detected")
	}
	pe[0x81] = 'X'
	if Detect(pe) == PE {
		t.Error("MZ without a PE signature taken as PE")
	}
	for in, want := range map[string][2]bool{
		"#!/usr/bin/env python\nprint(1)\n": {true, true},
		"fastboot $* flash abl_a x\r\n":     {true, false},
		"caf\xc3":                           {true, false}, // a rune cut at the head's end
		"\x00\x01binary":                    {false, false},
		"":                                  {false, false},
	} {
		if ok, script := Text([]byte(in)); ok != want[0] || script != want[1] {
			t.Errorf("Text(%q) = %v, %v", in, ok, script)
		}
	}
}

func TestDetectODEXAndQCDT(t *testing.T) {
	if Detect([]byte("dey\n036\x00rest")) != ODEX {
		t.Error("odex")
	}
	if Detect([]byte("QCDT\x03\x00\x00\x00")) != QCDT {
		t.Error("qcdt")
	}
}

func TestDetectLZ4Formats(t *testing.T) {
	if Detect([]byte{0x04, 0x22, 0x4d, 0x18, 0x64, 0x40}) != LZ4 {
		t.Error("lz4 frame")
	}
	if Detect([]byte{0x02, 0x21, 0x4c, 0x18, 0xb3, 0x41, 0x3f, 0x00}) != LZ4Legacy {
		t.Error("lz4 legacy")
	}
	// The magic with no block after it is not a stream.
	if Detect([]byte{0x02, 0x21, 0x4c, 0x18, 0, 0, 0, 0}) == LZ4Legacy {
		t.Error("lz4 legacy magic with a zero block size")
	}
}

func TestDetectTelechipsBoot(t *testing.T) {
	h := make([]byte, 0x180)
	copy(h, "CERT")
	copy(h[0x100:], "HDR\x00")
	if Detect(h) != TelechipsBoot {
		t.Error("telechips boot stage")
	}
	if Detect(h[:0x100]) == TelechipsBoot {
		t.Error("a head too short to show the HDR is not one")
	}
}

func TestGzipNeedsAHeader(t *testing.T) {
	if Detect([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0}) != Gzip {
		t.Error("a deflate gzip header is not gzip")
	}
	// What a wrong key can leave: the magic, then noise.
	if Detect([]byte{0x1f, 0x8b, 0x4e, 0xe4, 0x67, 0xeb}) == Gzip {
		t.Error("1f 8b with another method byte is not gzip")
	}
}
