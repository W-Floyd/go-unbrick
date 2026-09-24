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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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
	// RootSHA256 and RootSHA384 are the root certificate DER hashed both ways
	// the PBL may hash it for OEM_PK_HASH. Which one a chip uses is its own
	// (the fused hash's length says), not the chain's signature digest: SM6225
	// fuses SHA-384 over roots signed with SHA-256.
	RootSHA256 string
	RootSHA384 string
	LeafCN     string // leaf attestation cert CN
	KeyBits    int    // signing key size (RSA modulus bits)
	Format     string // "ELF", "QSB", "MELF"
	// Meta is the signed image metadata of an MBN v6+ hash segment, which is
	// what the PBL enforces there; nil for older formats. When present, SWID is
	// taken from it and CertSWID keeps the leaf cert's OU value, which on v6
	// is not per-image: Motorola signs a whole boot chain with one leaf.
	Meta     *Metadata
	Signers  []string // metadata signers, OEM first: ["oem"], or ["oem","qti"] when double-signed
	CertSWID uint64
	// MultiImage is the number of distinct SW_IDs found when the bytes are a
	// whole boot chain rather than one image; SWID is then 0 (unknown).
	MultiImage int
}

// Metadata is one signer's metadata block of an MBN v6+ hash segment. The
// image carries a QTI block, an OEM block, or both (double-signed).
type Metadata struct {
	Signer       string // "oem" or "qti"
	SWID         uint32 // image type: 0 SBL/XBL, 3 Firehose, 7 TZ, 0x15 hyp, 0x1c ABL, …
	HWID         uint32 // 0 when bound by SoC version instead
	OEMID        uint32
	ModelID      uint32
	AppID        uint32
	Flags        uint32
	SoCVersions  []uint32 // chip family/version ids the image is bound to
	Serials      []uint32 // chip serials the image is bound to; empty = any unit
	RootIndex    uint32
	AntiRollback uint32
}

// parseMetadataV7 reads an MBN v7 hash segment: a 40-byte header (image_id,
// version, common/qti/oem metadata sizes, hash table, qti sig+chain, oem
// sig+chain), then a 24-byte common block holding the image's sw_id, then the
// signers' blocks. Field positions are inferred from 25 Lenovo, OnePlus,
// Huawei and Qualcomm programmers: sw_id (3, or 26 on OnePlus) and the SoC
// versions at OEM word 4 are consistent across all of them; anti-rollback at
// OEM word 2 was non-zero in only one sample, so it is the least certain.
func parseMetadataV7(seg []byte) []Metadata {
	if len(seg) < 40 {
		return nil
	}
	w := func(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i*4:]) }
	commonSize, qtiSize, oemSize := int(w(seg, 2)), int(w(seg, 3)), int(w(seg, 4))
	if commonSize < 12 || 40+commonSize+qtiSize+oemSize > len(seg) {
		return nil
	}
	swid := w(seg[40:], 2)
	var out []Metadata
	pos := 40 + commonSize
	for _, blk := range []struct {
		signer string
		size   int
	}{{"qti", qtiSize}, {"oem", oemSize}} {
		if blk.size == 0 {
			continue
		}
		b := seg[pos : pos+blk.size]
		pos += blk.size
		m := Metadata{Signer: blk.signer, SWID: swid}
		if blk.size >= 64 {
			m.AntiRollback, m.RootIndex = w(b, 2), w(b, 3)
			for i := 4; i < 16; i++ {
				if v := w(b, i); v != 0 {
					m.SoCVersions = append(m.SoCVersions, v)
				}
			}
		}
		out = append([]Metadata{m}, out...)
	}
	if len(out) == 0 {
		out = []Metadata{{Signer: "common", SWID: swid}}
	}
	return out
}

// Metadata flag bits (sectools MBN v6).
const (
	MetaRoTEnabled       = 1 << 0
	MetaSoCHWVersion     = 1 << 1
	MetaSerialBound      = 1 << 2
	MetaOEMIDIndependent = 1 << 3
)

// mbnV6MetaSize is metadata v0.0: 30 little-endian words.
const mbnV6MetaSize = 120

// parseMetadata reads the metadata blocks that follow a v6+ hash-segment
// header (48 bytes: …, metadata_size_qti, metadata_size). The OEM block comes
// last and is what the OEM's fused root verifies, so it is returned first.
func parseMetadata(seg []byte) []Metadata {
	if len(seg) < 48 {
		return nil
	}
	w := func(i int) uint32 { return binary.LittleEndian.Uint32(seg[i*4:]) }
	switch {
	case w(1) == 7:
		return parseMetadataV7(seg)
	case w(1) < 6:
		return nil
	}
	qtiSize, oemSize := int(w(10)), int(w(11))
	var out []Metadata
	pos := 48
	for _, blk := range []struct {
		signer string
		size   int
	}{{"qti", qtiSize}, {"oem", oemSize}} {
		if blk.size == 0 {
			continue
		}
		if blk.size < mbnV6MetaSize || pos+blk.size > len(seg) {
			return nil
		}
		b := seg[pos : pos+blk.size]
		pos += blk.size
		mw := func(i int) uint32 { return binary.LittleEndian.Uint32(b[i*4:]) }
		if mw(0) != 0 { // only metadata v0.x's layout is known
			continue
		}
		m := Metadata{
			Signer: blk.signer, SWID: mw(2), HWID: mw(3), OEMID: mw(4), ModelID: mw(5),
			AppID: mw(6), Flags: mw(7), RootIndex: mw(28), AntiRollback: mw(29),
		}
		for i := 8; i < 20; i++ {
			if v := mw(i); v != 0 {
				m.SoCVersions = append(m.SoCVersions, v)
			}
		}
		for i := 20; i < 28; i++ {
			if v := mw(i); v != 0 {
				m.Serials = append(m.Serials, v)
			}
		}
		out = append([]Metadata{m}, out...)
	}
	return out
}

func IsELF(b []byte) bool {
	return len(b) >= len(elf.ELFMAG) && bytes.HasPrefix(b, []byte(elf.ELFMAG))
}

// Restriction is the read/write policy a Firehose programmer enforces, read
// statically from the marker strings its refusal paths log. It reports that a
// loader *can* refuse, not which partitions: the per-range decision is runtime
// code against the live GPT, and the allowlist is not a table in the binary
// (confirmed on Motorola SM6225 loaders — no partition labels appear), so the
// readable set is knowable only by probing the device.
type Restriction struct {
	RangeGated   bool // logs "range restricted: lun=…": reads/writes of protected ranges are refused
	HandlerGated bool // logs "handler %s is restricted!": whole Firehose verbs are gated
	PeekPokeOff  bool // peek/poke disabled on secure-boot devices
}

// Restricted reports whether any restriction machinery is compiled in.
func (r Restriction) Restricted() bool { return r.RangeGated || r.HandlerGated || r.PeekPokeOff }

// markers are the log format strings a restricted loader carries. An
// engineering/unrestricted loader either lacks the range/handler gate or keys
// it off a debug fuse; the peek/poke lines may still be present, so those alone
// are the weakest signal.
var restrictionMarkers = []struct {
	needle string
	set    func(*Restriction)
}{
	{"range restricted:", func(r *Restriction) { r.RangeGated = true }},
	{"is restricted!", func(r *Restriction) { r.HandlerGated = true }},
	{"Peek is disabled on secure boot", func(r *Restriction) { r.PeekPokeOff = true }},
	{"Poke is disabled on secure boot", func(r *Restriction) { r.PeekPokeOff = true }},
}

// ScanRestriction reads a programmer ELF's restriction policy from its bytes.
func ScanRestriction(b []byte) Restriction {
	var r Restriction
	for _, m := range restrictionMarkers {
		if bytes.Contains(b, []byte(m.needle)) {
			m.set(&r)
		}
	}
	return r
}

// PeekSupport is what a loader's firehose implementation allows for the
// peek/poke memory commands — the capability that turns a signed loader into a
// tool for dumping RAM or patching its own restrictions at runtime (see the
// "signed but exploitable" loaders). Read statically from the handler and gate
// strings the loader carries.
type PeekSupport int

const (
	// PeekUnknown: a firehose loader whose strings are not readable
	// (compressed code), so its peek support cannot be told statically.
	PeekUnknown PeekSupport = iota
	// PeekNA: not a firehose loader (a streaming/hostdl programmer, an older
	// protocol), so peek/poke does not apply.
	PeekNA
	// PeekNone: a firehose loader with no peek/poke handler — a minimal
	// programmer.
	PeekNone
	// PeekGated: the handler is present but refuses on a secure-boot device
	// ("Peek is disabled on secure boot"). Still works on a device whose
	// secure-boot fuse is not blown.
	PeekGated
	// PeekEnabled: handler present with no secure-boot gate — peek works
	// regardless. The engineering/repair ("_peek") loaders.
	PeekEnabled
)

func (p PeekSupport) String() string {
	switch p {
	case PeekNA:
		return "n/a (streaming loader)"
	case PeekNone:
		return "none"
	case PeekGated:
		return "gated (secure-boot devices refuse)"
	case PeekEnabled:
		return "enabled"
	}
	return "unknown (compressed)"
}

// peekHandlerMarkers are phrases from a loader's peek/poke handler. They are a
// definitive tell on their own; the broader signal (see hasPeekHandler) is the
// bare "peek"/"poke" dispatch tokens, which every loader implementing the
// commands carries — stock ones included, gated behind the secure-boot fuse.
var peekHandlerMarkers = []string{"<peek", "<poke", "nothing to peek/poke", "poke size %d is larger"}

// hasPeekHandler reports whether the loader implements the peek/poke firehose
// commands. The command dispatch registers both tag names as strings, and the
// pair together is specific enough to not fire on unrelated binaries (a boot
// image carries neither) — where a single "peek" substring would be too loose.
func hasPeekHandler(b []byte) bool {
	return (bytes.Contains(b, []byte("peek")) && bytes.Contains(b, []byte("poke"))) ||
		containsAny(b, peekHandlerMarkers)
}

// peekGateMarkers show the handler is compiled in but gated behind the
// secure-boot fuse.
var peekGateMarkers = []string{"Peek is disabled on secure boot", "Poke is disabled on secure boot"}

// firehoseVocab is plaintext a firehose loader carries when its strings are
// readable at all; its absence means the code is packed and a string scan
// cannot conclude anything.
var firehoseVocab = []string{"firehose", "Firehose", "MaxPayloadSizeToTarget", "NUM_DISK_SECTORS"}

// streamingVocab identifies the older streaming/hostdl programmer protocol,
// which predates firehose and has no peek command. Its presence (or a QSB/MBN
// container, which streaming loaders use) means peek is not applicable rather
// than merely unreadable.
var streamingVocab = []string{"hostdl", "ehostdl", "MPRG", "QCSBLHD", "Streaming Download", "FLASH_PARTITION"}

// ScanPeek reports a loader's peek/poke support.
//
// Static detection is inherently a heuristic — peek support is a runtime code
// property, and only disassembling the firehose command dispatch would be
// definitive. But the search is scoped to the loader's own code and data
// (loaderText below) rather than the raw file, so the cert chain, RSA
// signature and padding cannot produce a false match. The tokens are the
// command names the dispatch registers; the secure-boot gate string decides
// enabled vs gated.
func ScanPeek(b []byte) PeekSupport {
	text := loaderText(b)
	if hasPeekHandler(text) {
		if containsAny(text, peekGateMarkers) {
			return PeekGated // handler present but gated behind the secure-boot fuse
		}
		return PeekEnabled // handler present, no gate — works regardless
	}
	if containsAny(text, firehoseVocab) {
		return PeekNone // a firehose loader with peek compiled out
	}
	if IsQSB(b) || containsAny(text, streamingVocab) {
		return PeekNA // streaming/hostdl protocol — peek does not exist
	}
	return PeekUnknown // firehose code we cannot read (compressed)
}

// loaderText is the loader's bytes with only the Qualcomm hash segment (the
// hash table, RSA signature and X.509 cert chain) carved out — the one region
// that carries attacker-controllable text but no loader strings, so a "peek" in
// a certificate CN cannot cause a false match. Everything else is kept as-is,
// including program headers whose declared size overruns the file (common in
// Qualcomm MBNs), which is why the hash range is subtracted rather than the
// loadable segments being re-assembled. Returns the input unchanged when it is
// not a parseable ELF (QSB/MBN, raw images) or has no hash segment.
func loaderText(b []byte) []byte {
	segs, err := Segments(b)
	if err != nil {
		return b
	}
	for _, s := range segs {
		if s.Hash && s.Filesz > 0 && s.Offset+s.Filesz <= uint64(len(b)) {
			out := make([]byte, 0, len(b)-int(s.Filesz))
			out = append(out, b[:s.Offset]...)
			return append(out, b[s.Offset+s.Filesz:]...)
		}
	}
	return b
}

func containsAny(b []byte, needles []string) bool {
	for _, n := range needles {
		if bytes.Contains(b, []byte(n)) {
			return true
		}
	}
	return false
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
		h384 := sha512.Sum384(root.Raw)
		id.RootSHA256, id.RootSHA384 = hex.EncodeToString(h[:]), hex.EncodeToString(h384[:])
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
	if len(certs) == 0 {
		return nil, fmt.Errorf("unrecognized image format (neither ELF nor QSB32/MBN)")
	}
	id, err := IdentityFromCerts(certs)
	if err != nil {
		return nil, err
	}
	// A raw boot-chain image (msimage, singleimage) carries one signed image per
	// stage, each with its own SW_ID; the first chain carved is not the blob's.
	if n := len(certSWIDs(certs)); n > 1 {
		id.SWID, id.MultiImage = 0, n
	}
	return id, nil
}

// certSWIDs is the distinct SW_ID OU values across a set of certs.
func certSWIDs(certs []*x509.Certificate) map[string]bool {
	out := map[string]bool{}
	for _, c := range certs {
		for _, ou := range c.Subject.OrganizationalUnit {
			if m := reOU.FindStringSubmatch(ou); m != nil && m[2] == "SW_ID" {
				out[strings.ToUpper(m[1])] = true
			}
		}
	}
	return out
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
	id, err := IdentityFromCerts(certs)
	if err != nil {
		return nil, err
	}
	id.CertSWID = id.SWID
	if md := parseMetadata(seg); len(md) > 0 {
		id.Meta = &md[0]
		id.SWID = uint64(md[0].AntiRollback)<<32 | uint64(md[0].SWID)
		for _, m := range md {
			id.Signers = append(id.Signers, m.Signer)
		}
	}
	return id, nil
}

// Integrity is how an image's segments compare with the hash table it was
// signed over: one digest per program header, zero for the hash segment itself
// and for empty segments. A patched loader keeps the original signed table, so
// its edited segments stop matching — and the PBL refuses it on secure boot.
type Integrity struct {
	Checked  bool  // a hash table was found and its digest size recognized
	Matched  int   // segments whose digest matches
	CodeBad  []int // executable segments that do not match: patched code
	DataBad  []int // non-executable segments that do not match
	Embedded bool  // checked the image appended to a wrapper ELF
}

// Patched reports modified code. Data-only mismatches (seen on some v7 images)
// are left out: not enough is known about which data v7 hashes to call them.
func (in Integrity) Patched() bool { return len(in.CodeBad) > 0 }

// VerifySegments checks an ELF's segments against its signed hash table. It
// does not verify the signature over the table.
func VerifySegments(b []byte) Integrity {
	ef, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return Integrity{}
	}
	defer ef.Close()
	hashIdx := -1
	for i, p := range ef.Progs {
		if (uint32(p.Flags)>>24)&0xf == 2 {
			hashIdx = i
			break
		}
	}
	if hashIdx < 0 {
		// A wrapper ELF with the signed image appended after it.
		if i := bytes.Index(b[4:], []byte(elf.ELFMAG)); i >= 0 {
			in := VerifySegments(b[4+i:])
			in.Embedded = true
			return in
		}
		return Integrity{}
	}
	hp := ef.Progs[hashIdx]
	if hp.Off+48 > uint64(len(b)) {
		return Integrity{}
	}
	seg := b[hp.Off:]
	w := func(i int) int { return int(binary.LittleEndian.Uint32(seg[i*4:])) }
	var tab, size int
	switch w(1) {
	case 3, 5:
		tab, size = 40, w(5)
	case 6:
		tab, size = 48+w(10)+w(11), w(5)
	case 7:
		tab, size = 40+w(2)+w(3)+w(4), w(5)
	default:
		return Integrity{}
	}
	n := len(ef.Progs)
	if n == 0 || size%n != 0 || tab+size > len(seg) {
		return Integrity{}
	}
	var sum func([]byte) []byte
	switch size / n {
	case 20:
		sum = func(d []byte) []byte { h := sha1.Sum(d); return h[:] }
	case 32:
		sum = func(d []byte) []byte { h := sha256.Sum256(d); return h[:] }
	case 48:
		sum = func(d []byte) []byte { h := sha512.Sum384(d); return h[:] }
	default:
		return Integrity{}
	}
	dl := size / n
	in := Integrity{Checked: true}
	zero := make([]byte, dl)
	for i, p := range ef.Progs {
		want := seg[tab+i*dl : tab+(i+1)*dl]
		if i == hashIdx || p.Filesz == 0 || bytes.Equal(want, zero) || p.Off+p.Filesz > uint64(len(b)) {
			continue
		}
		switch {
		case bytes.Equal(want, sum(b[p.Off:p.Off+p.Filesz])):
			in.Matched++
		case p.Flags&elf.PF_X != 0:
			in.CodeBad = append(in.CodeBad, i)
		default:
			in.DataBad = append(in.DataBad, i)
		}
	}
	return in
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

// RootKeyHash is the root hash in the form a fused OEM_PK_HASH of the given
// hex length would take, or "" for a length no PBL uses.
func (id *Identity) RootKeyHash(hexLen int) string {
	switch hexLen {
	case 64:
		return id.RootSHA256
	case 96:
		return id.RootSHA384
	}
	return ""
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

