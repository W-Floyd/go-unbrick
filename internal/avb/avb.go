// Package avb parses the header of an Android Verified Boot (AVB) vbmeta image
// (magic "AVB0"). All multi-byte fields are big-endian. This reads the top-level
// header only — enough to report the libavb version, signing algorithm, rollback
// index, flags, and the tool release string.
package avb

import (
	"crypto/sha256"
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

// Descriptor kinds in the vbmeta auxiliary block.
const (
	tagProperty      = 0
	tagHashtree      = 1
	tagHash          = 2
	tagKernelCmdline = 3
	tagChain         = 4
)

// Descriptor is one parsed AVB descriptor. Only the fields meaningful for its
// Kind are set.
type Descriptor struct {
	Kind          string // "hash", "hashtree", "chain", "cmdline", "property"
	Partition     string // hash / hashtree / chain
	ImageSize     uint64 // hash / hashtree
	HashAlgorithm string // hash / hashtree
	Digest        []byte // hash root / hashtree root digest
	// Chain descriptor: the separate key a chained partition (e.g. vbmeta_system)
	// is verified against, and where its rollback index is stored.
	ChainKeySHA256   string
	ChainRollbackLoc uint32
	Cmdline          string // kernel_cmdline
	Key, Value       string // property
}

// Image is a fully parsed vbmeta: the header, the SHA-256 of the embedded AVB
// signing (root) public key, and every descriptor. The pubkey hash is what a
// device anchors verified boot to (the fused ROT), so it identifies the key
// domain the image was signed in.
type Image struct {
	Header
	RollbackIndexLocation uint32
	PublicKeySHA256       string
	Descriptors           []Descriptor
}

// ParseImage parses a whole vbmeta image: header, public key, and descriptors.
// It needs the full image bytes, not just the header.
func ParseImage(data []byte) (*Image, error) {
	h, err := Parse(data)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	img := &Image{Header: *h, RollbackIndexLocation: be.Uint32(data[124:128])}

	// hash/signature offsets are relative to the authentication block, public
	// key and descriptors to the auxiliary block, which follows it.
	auxStart := 256 + int(h.AuthBlockSize)
	pkOff := auxStart + int(be.Uint64(data[64:72]))
	pkSize := int(be.Uint64(data[72:80]))
	if pkSize > 0 && pkOff >= 0 && pkOff+pkSize <= len(data) {
		sum := sha256.Sum256(data[pkOff : pkOff+pkSize])
		img.PublicKeySHA256 = fmt.Sprintf("%x", sum)
	}

	descOff := auxStart + int(be.Uint64(data[96:104]))
	descEnd := descOff + int(h.DescriptorsSize)
	if descOff < 0 || descEnd > len(data) {
		return img, nil // header is still useful even if descriptors are truncated
	}
	for p := descOff; p+16 <= descEnd; {
		tag := be.Uint64(data[p : p+8])
		nb := int(be.Uint64(data[p+8 : p+16]))
		body := data[p+16:]
		if nb > len(body) {
			break
		}
		body = body[:nb]
		if d, ok := parseDescriptor(tag, body); ok {
			img.Descriptors = append(img.Descriptors, d)
		}
		p += 16 + nb
	}
	return img, nil
}

func parseDescriptor(tag uint64, b []byte) (Descriptor, bool) {
	be := binary.BigEndian
	str := func(s []byte) string {
		if i := indexZero(string(s)); i >= 0 {
			return string(s[:i])
		}
		return string(s)
	}
	switch tag {
	case tagHash: // AvbHashDescriptor: name at 116 after the fixed fields
		if len(b) < 116 {
			return Descriptor{}, false
		}
		pnl := int(be.Uint32(b[40:44]))
		sl := int(be.Uint32(b[44:48]))
		dl := int(be.Uint32(b[48:52]))
		d := Descriptor{Kind: "hash", ImageSize: be.Uint64(b[0:8]), HashAlgorithm: str(b[8:40])}
		off := 116
		if off+pnl <= len(b) {
			d.Partition = string(b[off : off+pnl])
		}
		if off+pnl+sl+dl <= len(b) {
			d.Digest = append([]byte(nil), b[off+pnl+sl:off+pnl+sl+dl]...)
		}
		return d, true
	case tagHashtree: // AvbHashtreeDescriptor: name at 164
		if len(b) < 164 {
			return Descriptor{}, false
		}
		pnl := int(be.Uint32(b[88:92]))
		d := Descriptor{Kind: "hashtree", ImageSize: be.Uint64(b[4:12]), HashAlgorithm: str(b[56:88])}
		if 164+pnl <= len(b) {
			d.Partition = string(b[164 : 164+pnl])
		}
		return d, true
	case tagChain: // AvbChainPartitionDescriptor: name at 76, then the public key
		if len(b) < 76 {
			return Descriptor{}, false
		}
		rbl := be.Uint32(b[0:4])
		pnl := int(be.Uint32(b[4:8]))
		pkl := int(be.Uint32(b[8:12]))
		d := Descriptor{Kind: "chain", ChainRollbackLoc: rbl}
		if 76+pnl <= len(b) {
			d.Partition = string(b[76 : 76+pnl])
		}
		if 76+pnl+pkl <= len(b) {
			sum := sha256.Sum256(b[76+pnl : 76+pnl+pkl])
			d.ChainKeySHA256 = fmt.Sprintf("%x", sum)
		}
		return d, true
	case tagKernelCmdline: // AvbKernelCmdlineDescriptor: cmdline at 8
		if len(b) < 8 {
			return Descriptor{}, false
		}
		l := int(be.Uint32(b[4:8]))
		if 8+l <= len(b) {
			return Descriptor{Kind: "cmdline", Cmdline: string(b[8 : 8+l])}, true
		}
		return Descriptor{}, false
	case tagProperty: // AvbPropertyDescriptor: key then value, each NUL-terminated
		if len(b) < 16 {
			return Descriptor{}, false
		}
		kl := int(be.Uint64(b[0:8]))
		vl := int(be.Uint64(b[8:16]))
		if 16+kl+1+vl <= len(b) {
			return Descriptor{Kind: "property", Key: string(b[16 : 16+kl]), Value: string(b[16+kl+1 : 16+kl+1+vl])}, true
		}
		return Descriptor{}, false
	}
	return Descriptor{}, false
}
