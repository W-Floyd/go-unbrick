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

// IsZImage reports an ARM zImage header.
func IsZImage(head []byte) bool {
	return len(head) >= 0x28 && binary.LittleEndian.Uint32(head[0x24:]) == ZImageMagic
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
