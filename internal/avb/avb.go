// Package avb parses the header of an Android Verified Boot (AVB) vbmeta image
// (magic "AVB0"). All multi-byte fields are big-endian. This reads the top-level
// header only — enough to report the libavb version, signing algorithm, rollback
// index, flags, and the tool release string.
package avb

import (
	"encoding/binary"
	"fmt"
)

// Header is the parsed AvbVBMetaImageHeader (first 256 bytes).
type Header struct {
	VersionMajor    uint32
	VersionMinor    uint32
	Algorithm       string
	RollbackIndex   uint64
	Flags           uint32
	Release         string // release_string, e.g. "avbtool 1.2.0"
	AuthBlockSize   uint64
	AuxBlockSize    uint64
	DescriptorsSize uint64
}

var algorithms = map[uint32]string{
	0: "NONE (unsigned)",
	1: "SHA256_RSA2048",
	2: "SHA256_RSA4096",
	3: "SHA256_RSA8192",
	4: "SHA512_RSA2048",
	5: "SHA512_RSA4096",
	6: "SHA512_RSA8192",
}

// Parse reads the vbmeta header. head must be at least 176 bytes (the fixed
// fields through release_string).
func Parse(head []byte) (*Header, error) {
	if len(head) < 176 || string(head[:4]) != "AVB0" {
		return nil, fmt.Errorf("avb: not a vbmeta image")
	}
	be := binary.BigEndian
	algo := be.Uint32(head[28:32])
	algoName := algorithms[algo]
	if algoName == "" {
		algoName = fmt.Sprintf("unknown (%d)", algo)
	}
	rel := string(head[128:176])
	if i := indexZero(rel); i >= 0 {
		rel = rel[:i]
	}
	return &Header{
		VersionMajor:    be.Uint32(head[4:8]),
		VersionMinor:    be.Uint32(head[8:12]),
		AuthBlockSize:   be.Uint64(head[12:20]),
		AuxBlockSize:    be.Uint64(head[20:28]),
		Algorithm:       algoName,
		DescriptorsSize: be.Uint64(head[104:112]),
		RollbackIndex:   be.Uint64(head[112:120]),
		Flags:           be.Uint32(head[120:124]),
		Release:         rel,
	}, nil
}

func indexZero(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return i
		}
	}
	return -1
}
