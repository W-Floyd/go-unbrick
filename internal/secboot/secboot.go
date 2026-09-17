// Package secboot reads the Qualcomm secure-boot identity out of a signed image
// (Firehose programmer.elf, xbl.elf, abl.elf, ...). That identity — OEM_ID,
// HW_ID, SW_ID and the signing root — is what the target's PBL enforces when it
// authenticates a loader, so it is the real key to whether a sibling's loader
// will run on a given device.
//
// The signed image is an ELF (program headers only) — aarch64, or the 32-bit ARM
// of older programmers — carrying a Qualcomm hash-table segment (program-header
// flags with segment-type nibble 2): a SHA
// table, an RSA signature, then an X.509 chain leaf -> attestation CA -> root.
// The leaf's Subject packs the enforced fields as OU strings of the form
// "NN <hexvalue> NAME" (e.g. "04 02E8 OEM_ID", "01 …0002 SW_ID").
package secboot

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Identity is the secboot-enforced signing identity of one image.
type Identity struct {
	OEMID   string // OEM key id, e.g. "02E8" (Motorola)
	HWID    string // full HW_ID: JTAG_ID<<32 | OEM_ID<<16 | MODEL_ID
	JTAGID  string // HW_ID[63:32], the SoC hardware id
	ModelID string
	SWID    uint64 // anti-rollback counter for this image type
	SWSize  string
	Debug   string
	Root    string // short signing-root label: a numeric tag (e.g. "724") or the raw CN
	RootCN  string // raw root cert common name (vendor-agnostic; e.g. "Samsung Root CA cert")
	LeafCN  string // leaf attestation cert CN
	KeyBits int    // signing key size (RSA modulus bits)
}

func IsELF(b []byte) bool {
	return len(b) >= len(elf.ELFMAG) && bytes.HasPrefix(b, []byte(elf.ELFMAG))
}

// Segment is one program-header entry of a Qualcomm signed image.
type Segment struct {
	Index                 int
	Offset, Filesz, Paddr uint64
	Flags                 uint64
	// Hash marks the Qualcomm hash-table segment: the SHA table, signature and
	// cert chain. It is re-generated on every build, so it differs between two
	// images even when their payload is identical.
	Hash bool
}

// Segments lists an image's program headers using debug/elf. Handles both ELFCLASS64
// (aarch64 loaders) and ELFCLASS32 (older 32-bit programmers).
func Segments(b []byte) ([]Segment, error) {
	ef, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer ef.Close()
	var out []Segment
	for i, p := range ef.Progs {
		if p.Off > uint64(len(b)) || p.Off+p.Filesz > uint64(len(b)) {
			continue
		}
		out = append(out, Segment{
			Index:  i,
			Offset: p.Off,
			Filesz: p.Filesz,
			Paddr:  p.Paddr,
			Flags:  uint64(p.Flags),
			Hash:   (uint32(p.Flags)>>24)&0xf == 2,
		})
	}
	return out, nil
}

// hashSegment returns the Qualcomm hash-table segment (program-header flags with
// segment-type nibble 2).
func hashSegment(b []byte) ([]byte, error) {
	segs, err := Segments(b)
	if err != nil {
		return nil, err
	}
	for _, s := range segs {
		if s.Hash {
			return b[s.Offset : s.Offset+s.Filesz], nil
		}
	}
	return nil, fmt.Errorf("no hash-table segment (unsigned or not a QC image?)")
}

// carveCerts finds the concatenated DER certificates in the hash segment.
func carveCerts(seg []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for i := 0; i+4 < len(seg); {
		if seg[i] == 0x30 && seg[i+1] == 0x82 {
			ln := int(binary.BigEndian.Uint16(seg[i+2:])) + 4
			if i+ln <= len(seg) && seg[i+4] == 0x30 && seg[i+5] == 0x82 {
				if c, err := x509.ParseCertificate(seg[i : i+ln]); err == nil {
					out = append(out, c)
					i += ln
					continue
				}
			}
		}
		i++
	}
	return out
}

var (
	reOU   = regexp.MustCompile(`^[0-9]{2} ([0-9A-Fa-f]+) ([A-Z0-9_]+)$`)
	reRoot = regexp.MustCompile(`(\d{3,})`)
)

// FromELF extracts the signing identity from a signed QC ELF.
func FromELF(b []byte) (*Identity, error) {
	id, err := fromELFDirect(b)
	if err == nil {
		return id, nil
	}
	if !IsELF(b) {
		return nil, err
	}
	// Multi-image ELF containers (e.g. MELF) package multiple images within an
	// outer ELF stub. Look for embedded signed ELFs using fast SIMD search.
	needle := []byte(elf.ELFMAG)
	for offset := 4; offset+4 < len(b); {
		idx := bytes.Index(b[offset:], needle)
		if idx < 0 {
			break
		}
		curr := offset + idx
		if emb, err2 := fromELFDirect(b[curr:]); err2 == nil {
			return emb, nil
		}
		offset = curr + 4
	}
	return nil, err
}

func fromELFDirect(b []byte) (*Identity, error) {
	seg, err := hashSegment(b)
	if err != nil {
		return nil, err
	}
	certs := carveCerts(seg)
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate chain in hash segment")
	}
	var leaf, root *x509.Certificate
	for _, c := range certs {
		for _, ou := range c.Subject.OrganizationalUnit {
			if strings.HasSuffix(ou, " HW_ID") { // leaf attestation carries the enforced fields
				leaf = c
			}
		}
		if bytes.Equal(c.RawSubject, c.RawIssuer) { // self-signed = root, vendor-agnostic
			root = c
		}
	}
	if leaf == nil {
		return nil, fmt.Errorf("no leaf attestation cert (no HW_ID OU found)")
	}
	id := &Identity{LeafCN: leaf.Subject.CommonName}
	for _, ou := range leaf.Subject.OrganizationalUnit {
		m := reOU.FindStringSubmatch(ou)
		if m == nil {
			continue
		}
		val, name := m[1], m[2]
		switch name {
		case "OEM_ID":
			id.OEMID = val
		case "HW_ID":
			id.HWID = val
		case "MODEL_ID":
			id.ModelID = val
		case "SW_ID":
			id.SWID, _ = strconv.ParseUint(val, 16, 64)
		case "SW_SIZE":
			id.SWSize = val
		case "DEBUG":
			id.Debug = val
		}
	}
	if len(id.HWID) == 16 {
		id.JTAGID = id.HWID[:8]
	}
	// Root identity: keep the raw CN (vendor-agnostic), and derive a short label —
	// a numeric tag when the CN carries one (Motorola "Root CA 724" -> "724"),
	// else the CN verbatim (Samsung "Samsung Root CA cert"). Vendor drivers can
	// interpret RootCN further.
	if root != nil {
		id.RootCN = root.Subject.CommonName
	}
	if m := reRoot.FindString(id.RootCN); m != "" {
		id.Root = m
	} else if id.RootCN != "" {
		id.Root = id.RootCN
	} else if m := reRoot.FindString(leaf.Subject.CommonName); m != "" {
		id.Root = m
	}
	if pk, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
		id.KeyBits = pk.N.BitLen()
	}
	return id, nil
}

// Compatible reports whether a loader with identity ld is likely to authenticate
// on a target whose own signed images have identity tg. OEM must match (hard
// binding); a differing JTAG/HW_ID or root is only advisory (the loader stage's
// acceptance is coarser, and the true mask is fused per SoC — provable only on
// device). reasons lists the advisory divergences.
func Compatible(ld, tg *Identity) (oemOK bool, reasons []string) {
	oemOK = ld.OEMID == tg.OEMID
	if !oemOK {
		reasons = append(reasons, fmt.Sprintf("OEM_ID differs (loader %s vs target %s) — will NOT authenticate", ld.OEMID, tg.OEMID))
	}
	if ld.JTAGID != tg.JTAGID {
		reasons = append(reasons, fmt.Sprintf("JTAG/HW_ID differs (loader %s vs target %s)", ld.JTAGID, tg.JTAGID))
	}
	if ld.Root != tg.Root {
		reasons = append(reasons, fmt.Sprintf("signing root differs (loader CA %s vs target CA %s)", ld.Root, tg.Root))
	}
	return oemOK, reasons
}
