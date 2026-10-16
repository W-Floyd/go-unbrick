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
		{"mbn", []byte{0xd1, 0xdc, 0x4b, 0x84, 0xff}, QcomMBN},
		{"qcom-partition", []byte{0x9a, 0x1b, 0x7d, 0xaa, 0x00}, QcomPartition},
		{"unknown",[]byte("hello world"), Unknown},
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
