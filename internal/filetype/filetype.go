// Package filetype identifies a file by its container/format from magic bytes.
// It knows only neutral, industry formats (zip, ELF, Android sparse, ext4, GPT,
// AVB vbmeta, Motorola's SINGLE_N_LONELY container); anything vendor-specific
// beyond that — which OEM a zip is, what a partition means — is decided by the
// vendor seam and vendor parsers, not here.
package filetype

import (
	"bytes"
	"encoding/binary"
)

type Kind string

const (
	Zip               Kind = "zip"
	ELF               Kind = "elf"
	SparseImage       Kind = "android-sparse"
	Ext4              Kind = "ext4"
	EROFS             Kind = "erofs"
	GPT               Kind = "gpt"
	VBMeta            Kind = "avb-vbmeta"
	AndroidBoot       Kind = "android-boot"
	AndroidVendorBoot Kind = "android-vendor-boot"
	DTBOTable         Kind = "dtbo-table"
	DeviceTree        Kind = "device-tree"
	QDB               Kind = "qualcomm-qdb"
	SingleNLonely     Kind = "single_n_lonely"
	OTAPayload        Kind = "android-ota-payload"
	FAT               Kind = "fat"
	Unknown           Kind = "unknown"
)

// Detect classifies head (the first bytes of a file; a few KiB is plenty). It
// never reads the whole file, so a huge zip or image is cheap to identify. Only
// neutral, cross-vendor formats live here; vendor-specific magics (Motorola
// MotoLogo, CID, subsidy .nvm) are recognized by the caller/vendor seam.
func Detect(head []byte) Kind {
	be, le := binary.BigEndian, binary.LittleEndian
	switch {
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("PK\x03\x04")):
		return Zip
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("\x7fELF")):
		return ELF
	case len(head) >= 8 && bytes.Equal(head[:8], []byte("ANDROID!")):
		return AndroidBoot
	case len(head) >= 8 && bytes.Equal(head[:8], []byte("VNDRBOOT")):
		return AndroidVendorBoot
	case len(head) >= 16 && bytes.Equal(head[:16], []byte("SINGLE_N_LONELY\x00")):
		return SingleNLonely
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("AVB0")):
		return VBMeta
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("\x7fQDB")):
		return QDB
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("CrAU")):
		return OTAPayload
	case len(head) >= 4 && be.Uint32(head[:4]) == 0xd7b7ab1e:
		return DTBOTable
	case len(head) >= 4 && be.Uint32(head[:4]) == 0xd00dfeed:
		return DeviceTree
	case len(head) >= 4 && le.Uint32(head[:4]) == 0xed26ff3a:
		return SparseImage
	case len(head) >= 520 && bytes.Equal(head[512:520], []byte("EFI PART")): // 512-byte sectors
		return GPT
	case len(head) >= 4104 && bytes.Equal(head[4096:4104], []byte("EFI PART")): // 4K sectors (UFS)
		return GPT
	case len(head) >= 8 && bytes.Equal(head[:8], []byte("EFI PART")): // header with no protective MBR
		return GPT
	case len(head) >= 512 && head[510] == 0x55 && head[511] == 0xaa &&
		(bytes.Equal(head[0x36:0x39], []byte("FAT")) || bytes.Equal(head[0x52:0x57], []byte("FAT32"))):
		return FAT
	case len(head) >= 0x43a && le.Uint16(head[0x438:0x43a]) == 0xEF53:
		return Ext4
	case len(head) >= 1028 && le.Uint32(head[1024:1028]) == 0xe0f5e1e2:
		return EROFS
	default:
		return Unknown
	}
}
