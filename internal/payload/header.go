package payload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	HeaderMagic        = "CrAU"
	MajorVersionBrillo = 2
	HeaderLen          = 24
)

var (
	ErrNotPayload        = errors.New("not an Android OTA payload (magic mismatch)")
	ErrUnsupportedVersion = errors.New("unsupported payload major version (only version 2 supported)")
)

// Header is the 24-byte CrAU payload file header.
type Header struct {
	Version              uint64
	ManifestLen          uint64
	MetadataSignatureLen uint32
}

// ReadHeader parses the 24-byte CrAU header from an io.Reader.
func ReadHeader(r io.Reader) (Header, error) {
	var h Header
	buf := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return h, fmt.Errorf("reading payload header: %w", err)
	}
	if string(buf[0:4]) != HeaderMagic {
		return h, ErrNotPayload
	}
	h.Version = binary.BigEndian.Uint64(buf[4:12])
	if h.Version != MajorVersionBrillo {
		return h, fmt.Errorf("%w: %d", ErrUnsupportedVersion, h.Version)
	}
	h.ManifestLen = binary.BigEndian.Uint64(buf[12:20])
	if h.ManifestLen == 0 {
		return h, fmt.Errorf("payload manifest length is zero")
	}
	h.MetadataSignatureLen = binary.BigEndian.Uint32(buf[20:24])
	return h, nil
}

