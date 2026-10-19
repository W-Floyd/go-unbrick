package bootimg

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
)

// ZImageMagic sits at offset 0x24 of an ARM zImage.
const ZImageMagic = 0x016f2818

// IsZImage reports an ARM (32-bit, AArch32) zImage header.
func IsZImage(head []byte) bool {
	return len(head) >= 0x28 && binary.LittleEndian.Uint32(head[0x24:]) == ZImageMagic
}

// arm64ImageMagic ("ARM\x64", little-endian) sits at offset 0x38 of an
// AArch64 Linux "Image" (the booti/kernel.img format, kernel's own
// Documentation/arm64/booting.rst) — unrelated to, and not interchangeable
// with, the 32-bit zImage format above: a kernel is one or the other, never
// both, so this distinguishes a system's real kernel word size.
const arm64ImageMagic = 0x644d5241

// IsAArch64Image reports an AArch64 Linux "Image" header.
func IsAArch64Image(head []byte) bool {
	return len(head) >= 0x3c && binary.LittleEndian.Uint32(head[0x38:]) == arm64ImageMagic
}

// KernelConfig returns the .config a kernel was built with (CONFIG_IKCONFIG):
// a gzip stream between the IKCFG_ST and IKCFG_ED markers in the image. ok is
// false when the kernel carries none.
func KernelConfig(kernel []byte) ([]byte, bool) {
	_, after, found := bytes.Cut(kernel, []byte("IKCFG_ST"))
	if !found {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(after))
	if err != nil {
		return nil, false
	}
	cfg, _ := io.ReadAll(io.LimitReader(zr, 4<<20))
	if !bytes.Contains(cfg, []byte("CONFIG_")) {
		return nil, false
	}
	return cfg, true
}

// ZImagePayload returns the kernel an ARM zImage's decompressor stub carries,
// gzip-compressed after the stub. Trailing bytes after the stream are the
// stub's own and not an error.
func ZImagePayload(z []byte) ([]byte, error) {
	if !IsZImage(z) {
		return nil, errors.New("not an ARM zImage")
	}
	i := bytes.Index(z, []byte{0x1f, 0x8b, 0x08})
	if i < 0 {
		return nil, errors.New("zImage: no gzip payload (another compressor)")
	}
	zr, err := gzip.NewReader(bytes.NewReader(z[i:]))
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(zr, 128<<20))
	if len(plain) == 0 && err != nil {
		return nil, err
	}
	return plain, nil
}
