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
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Identity is the secboot-enforced signing identity of one image.
type Identity struct {
	OEMID    string // OEM key id, e.g. "02E8" (Motorola)
	HWID     string // full HW_ID: JTAG_ID<<32 | OEM_ID<<16 | MODEL_ID
	JTAGID   string // HW_ID[63:32], the SoC hardware id
	ModelID  string
	SWID     uint64 // anti-rollback counter for this image type
	SWSize   string
	Debug    string
	Root     string // short signing-root label: a numeric tag (e.g. "724") or the raw CN
	RootCN   string // raw root cert common name (vendor-agnostic; e.g. "Samsung Root CA cert")
	RootHash string // SHA-256 hash prefix (16 hex) of root certificate DER
	LeafCN   string // leaf attestation cert CN
	KeyBits  int    // signing key size (RSA modulus bits)
	Format   string // "ELF", "QSB", "MELF"
}

func IsELF(b []byte) bool {
	return len(b) >= len(elf.ELFMAG) && bytes.HasPrefix(b, []byte(elf.ELFMAG))
}

// IsQSB reports whether the data begins with the Qualcomm 32-bit QSB/MBN magic (0x844BDCD1).
func IsQSB(b []byte) bool {
	return len(b) >= 4 && b[0] == 0xd1 && b[1] == 0xdc && b[2] == 0x4b && b[3] == 0x84
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

// carveCerts finds the concatenated DER certificates in the hash segment or image.
func carveCerts(seg []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for i := 0; i+4 < len(seg); {
		if seg[i] == 0x30 && seg[i+1] == 0x82 {
			ln := int(binary.BigEndian.Uint16(seg[i+2:])) + 4
			if i+ln <= len(seg) && seg[i+4] == 0x30 {
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

// IdentityFromCerts parses secboot Identity from a carved certificate chain.
// Handles both legacy Qualcomm leaf certs with HW_ID/OEM_ID OUs and modern
// SecTools / SRoT hierarchies (Samsung, Vivo, Oppo, ZTE, Xiaomi).
func IdentityFromCerts(certs []*x509.Certificate) (*Identity, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate chain in image")
	}
	var leaf, root *x509.Certificate
	for _, c := range certs {
		for _, ou := range c.Subject.OrganizationalUnit {
			if strings.HasSuffix(ou, " HW_ID") { // legacy leaf attestation carries enforced fields
				leaf = c
			}
		}
		if bytes.Equal(c.RawSubject, c.RawIssuer) { // self-signed root
			root = c
		}
	}

	// In modern SecTools/SRoT hierarchies, leaf certs lack explicit HW_ID OUs.
	// Use the first cert as leaf and last cert as root fallback.
	if leaf == nil {
		leaf = certs[0]
	}
	if root == nil && len(certs) > 0 {
		root = certs[len(certs)-1]
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
	if len(id.HWID) >= 8 {
		id.JTAGID = id.HWID[:8]
	}

	// Root identity & hash
	if root != nil {
		id.RootCN = root.Subject.CommonName
		h := sha256.Sum256(root.Raw)
		id.RootHash = hex.EncodeToString(h[:8])
	}
	if m := reRoot.FindString(id.RootCN); m != "" {
		id.Root = m
	} else if id.RootCN != "" {
		id.Root = id.RootCN
	} else if m := reRoot.FindString(leaf.Subject.CommonName); m != "" {
		id.Root = m
	}

	// Fallback OEM_ID derivation if no OEM_ID OU was present
	if id.OEMID == "" {
		id.OEMID = deriveOEMFromCerts(certs)
	}

	// Default JTAGID to generic if not constrained in leaf
	if id.JTAGID == "" {
		id.JTAGID = "00000000"
	}

	if pk, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
		id.KeyBits = pk.N.BitLen()
	}

	return id, nil
}

func deriveOEMFromCerts(certs []*x509.Certificate) string {
	for _, c := range certs {
		txt := strings.ToUpper(c.Subject.String() + " " + c.Issuer.String())
		switch {
		case strings.Contains(txt, "SAMSUNG"):
			return "0020"
		case strings.Contains(txt, "OPPO"), strings.Contains(txt, "OPLUS"), strings.Contains(txt, "ONEPLUS"):
			return "0051"
		case strings.Contains(txt, "XIAOMI"), strings.Contains(txt, "REDMI"), strings.Contains(txt, "POCO"):
			return "0072"
		case strings.Contains(txt, "MOTOROLA"), strings.Contains(txt, "LENOVO"):
			return "02E8"
		case strings.Contains(txt, "VIVO"), strings.Contains(txt, "BBK"):
			return "0073"
		case strings.Contains(txt, "ZTE"):
			return "0004"
		case strings.Contains(txt, "HUAWEI"), strings.Contains(txt, "HONOR"), strings.Contains(txt, "HIHONOR"):
			return "0000"
		case strings.Contains(txt, "ASUS"):
			return "1111"
		case strings.Contains(txt, "TCL"), strings.Contains(txt, "ALCATEL"):
			return "0042"
		case strings.Contains(txt, "QUALCOMM"), strings.Contains(txt, "QCT"), strings.Contains(txt, "LAB126"), strings.Contains(txt, "AMAZON"):
			return "0000"
		}
	}
	return "0000"
}

// FromImage extracts the signing identity from any supported Qualcomm image
// (ELF64, ELF32, MELF, or QSB32/MBN).
func FromImage(b []byte) (*Identity, error) {
	if IsELF(b) {
		return FromELF(b)
	}
	if IsQSB(b) {
		return FromQSB(b)
	}
	certs := carveCerts(b)
	if len(certs) > 0 {
		return IdentityFromCerts(certs)
	}
	return nil, fmt.Errorf("unrecognized image format (neither ELF nor QSB32/MBN)")
}

// FromQSB extracts the signing identity from a Qualcomm 32-bit QSB/MBN container.
func FromQSB(b []byte) (*Identity, error) {
	if !IsQSB(b) {
		return nil, fmt.Errorf("not a QSB32/MBN image (magic 0x844BDCD1 expected)")
	}
	certs := carveCerts(b)
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate chain in QSB32/MBN image")
	}
	id, err := IdentityFromCerts(certs)
	if err != nil {
		return nil, err
	}
	id.Format = "QSB"
	return id, nil
}

// FromELF extracts the signing identity from a signed QC ELF.
func FromELF(b []byte) (*Identity, error) {
	id, err := fromELFDirect(b)
	if err == nil {
		id.Format = "ELF"
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
			emb.Format = "MELF"
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
	return IdentityFromCerts(certs)
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

// SWType returns the Qualcomm software stage type (bits [31:0] of SW_ID).
func (id *Identity) SWType() uint32 {
	if id == nil {
		return 0
	}
	return uint32(id.SWID & 0xFFFFFFFF)
}

// AntiRollback returns the enforced anti-rollback version counter (bits [63:32] of SW_ID).
func (id *Identity) AntiRollback() uint32 {
	if id == nil {
		return 0
	}
	return uint32(id.SWID >> 32)
}

// RollbackStatus describes the anti-rollback compatibility status.
type RollbackStatus int

const (
	RollbackSafe RollbackStatus = iota
	RollbackWarning
	RollbackFatal
)

func (s RollbackStatus) String() string {
	switch s {
	case RollbackSafe:
		return "SAFE"
	case RollbackWarning:
		return "WARNING"
	case RollbackFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// RollbackReport provides detailed pre-flight rollback verification between donor and target.
type RollbackReport struct {
	Status       RollbackStatus
	DonorSWID    uint64
	TargetSWID   uint64
	DonorAR      uint32
	TargetAR     uint32
	DonorSWType  uint32
	TargetSWType uint32
	Reasons      []string
}

// ValidateRollback performs an anti-rollback pre-flight check between a donor loader
// and a target device's stock signing identity.
//
// In Qualcomm secboot architecture:
// 1. OEM_ID must match (hard binding; mismatch is fatal).
// 2. Anti-Rollback version (bits [63:32]) in the donor loader certificate must satisfy
//    the target device's fused counter. If donorAR < targetAR, target fuses may reject
//    the loader with Sahara authentication failure.
func ValidateRollback(ld, tg *Identity) *RollbackReport {
	if ld == nil || tg == nil {
		return &RollbackReport{Status: RollbackSafe}
	}
	rep := &RollbackReport{
		Status:       RollbackSafe,
		DonorSWID:    ld.SWID,
		TargetSWID:   tg.SWID,
		DonorAR:      ld.AntiRollback(),
		TargetAR:     tg.AntiRollback(),
		DonorSWType:  ld.SWType(),
		TargetSWType: tg.SWType(),
	}

	if ld.OEMID != tg.OEMID {
		rep.Status = RollbackFatal
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("OEM_ID differs (loader %s vs target %s) — will NOT authenticate", ld.OEMID, tg.OEMID))
		return rep
	}

	// Compare anti-rollback counter if either image has bits [63:32] set
	if rep.DonorAR < rep.TargetAR {
		rep.Status = RollbackWarning
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("loader anti-rollback version (%d) is lower than target stock image (%d); target fuses may reject loader with Sahara stall", rep.DonorAR, rep.TargetAR))
	} else if rep.DonorAR > rep.TargetAR {
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("loader anti-rollback version (%d) is newer than target stock image (%d)", rep.DonorAR, rep.TargetAR))
	}

	// Also check raw SWID if stage matches
	if rep.DonorSWType == rep.TargetSWType && rep.DonorSWID < rep.TargetSWID {
		rep.Status = RollbackWarning
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("loader SW_ID (%d) < target SW_ID (%d) for same stage type %d", rep.DonorSWID, rep.TargetSWID, rep.DonorSWType))
	}

	return rep
}

