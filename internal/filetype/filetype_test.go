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
		{"unknown", []byte("hello world"), Unknown},
	}
	for _, c := range cases {
		if got := Detect(c.head); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	_ = bytes.MinRead
}
