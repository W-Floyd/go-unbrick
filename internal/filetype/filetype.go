// Package filetype identifies a file by its container/format from magic bytes.
// It knows only neutral, industry formats (zip, ELF, Android sparse, ext4, GPT,
// AVB vbmeta, Motorola's SINGLE_N_LONELY container); anything vendor-specific
// beyond that — which OEM a zip is, what a partition means — is decided by the
// vendor seam and vendor parsers, not here.
package filetype

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

type Kind string

const (
	Zip               Kind = "zip"
	SevenZip          Kind = "7z"
	ELF               Kind = "elf"
	ARM64Image        Kind = "arm64-image" // AArch64 Linux "Image": "ARM\x64" at 0x38 (it often has an EFI stub too, so before PE)
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
	Tar               Kind = "tar"
	Gzip              Kind = "gzip"
	LZ4               Kind = "lz4"
	LZ4Legacy         Kind = "lz4-legacy" // the older LZ4 stream format: blocks with no frame header or end
	PE                Kind = "pe"
	F2FS              Kind = "f2fs"
	JPEG              Kind = "jpeg"
	PNG               Kind = "png"
	WinHelp           Kind = "winhelp"     // .hlp, beside Windows flash tools
	TypeLib           Kind = "com-typelib" // .tlb, a COM type library
	SQLite            Kind = "sqlite"
	UBI               Kind = "ubi" // raw NAND UBI image (erase-block headers)
	UBIFS             Kind = "ubifs"
	QCDT              Kind = "qualcomm-dt-table"
	ODEX              Kind = "dalvik-odex" // optimized DEX, pre-ART ("dey\n036")
	DEX               Kind = "dalvik-dex"
	Ogg               Kind = "ogg"
	TelechipsBoot     Kind = "telechips-boot" // signed boot stage: "CERT" block, "HDR" at 0x100
	Unknown          Kind = "unknown"
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
	case len(head) >= 6 && bytes.Equal(head[:6], []byte("7z\xbc\xaf\x27\x1c")):
		return SevenZip
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("\x7fELF")):
		return ELF
	case len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar")):
		return Tar
	// Two bytes of magic alone match 1 in 65536 random blocks: a real header also has method 8
	// (deflate) and no reserved flag bits, and a key that turns noise into 1f 8b should not pass.
	case len(head) >= 4 && head[0] == 0x1f && head[1] == 0x8b && head[2] == 8 && head[3]&0xe0 == 0:
		return Gzip
	case len(head) >= 4 && le.Uint32(head[:4]) == 0x184d2204: // frame format
		return LZ4
	case len(head) >= 8 && le.Uint32(head[:4]) == 0x184c2102 && le.Uint32(head[4:8]) != 0: // legacy: magic, then a first block size
		return LZ4Legacy
	case len(head) >= 0x3c && le.Uint32(head[0x38:0x3c]) == 0x644d5241:
		return ARM64Image
	case isPE(head):
		return PE
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
	case len(head) >= 1028 && le.Uint32(head[1024:1028]) == 0xf2f52010:
		return F2FS
	case len(head) >= 3 && bytes.Equal(head[:3], []byte{0xff, 0xd8, 0xff}):
		return JPEG
	case len(head) >= 8 && bytes.Equal(head[:8], []byte("\x89PNG\r\n\x1a\n")):
		return PNG
	case len(head) >= 4 && bytes.Equal(head[:4], []byte{0x3f, 0x5f, 0x03, 0x00}):
		return WinHelp
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("MSFT")):
		return TypeLib
	case len(head) >= 16 && bytes.Equal(head[:16], []byte("SQLite format 3\x00")):
		return SQLite
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("UBI#")):
		return UBI
	case len(head) >= 4 && le.Uint32(head[:4]) == 0x06101831: // UBIFS node magic
		return UBIFS
	case len(head) >= 8 && bytes.Equal(head[:4], []byte("dex\n")):
		return DEX
	case len(head) >= 8 && bytes.Equal(head[:4], []byte("dey\n")):
		return ODEX
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("QCDT")):
		return QCDT
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("OggS")):
		return Ogg
	case len(head) >= 0x104 && bytes.Equal(head[:4], []byte("CERT")) && bytes.Equal(head[0x100:0x104], []byte("HDR\x00")):
		return TelechipsBoot
	default:
		return Unknown
	}
}

// BackupGPT reports an image of a backup GPT (gpt_backupN.bin): the entries
// first, the header in the last sector. Detect cannot see it, as it looks only
// at a head; this needs the whole image.
func BackupGPT(data []byte) bool {
	for _, s := range []int{512, 4096} {
		if len(data) >= 2*s && len(data)%s == 0 && bytes.HasPrefix(data[len(data)-s:], []byte("EFI PART")) {
			return true
		}
	}
	return false
}

// isPE reports a Windows PE executable or DLL: the MZ stub, pointing at a PE
// signature within the head.
func isPE(head []byte) bool {
	if len(head) < 0x40 || head[0] != 'M' || head[1] != 'Z' {
		return false
	}
	off := int(binary.LittleEndian.Uint32(head[0x3c:]))
	return off+4 <= len(head) && bytes.Equal(head[off:off+4], []byte("PE\x00\x00"))
}

// Text reports whether head reads as text (UTF-8, no control bytes but
// whitespace), and whether it is a script, opening with "#!". It is not part
// of Detect: callers that treat Unknown as "ask the vendor's content
// recognizers" would otherwise skip text formats those recognize.
func Text(head []byte) (ok, script bool) {
	if len(head) == 0 {
		return false, false
	}
	// A head can end mid-rune; only whole runes are judged.
	for i := 0; i < len(head); {
		r, n := utf8.DecodeRune(head[i:])
		if r == utf8.RuneError && n <= 1 && len(head)-i >= utf8.UTFMax {
			return false, false
		}
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' && r != '\f' {
			return false, false
		}
		i += max(n, 1)
	}
	return true, bytes.HasPrefix(head, []byte("#!"))
}
