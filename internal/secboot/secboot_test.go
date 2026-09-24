package secboot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"
)

func makeCert(t *testing.T, subject pkix.Name, key *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// buildSignedELF wraps a cert chain in a minimal 64-bit ELF whose sole program
// header is a Qualcomm hash-table segment (flags type nibble 2).
func buildSignedELF(seg []byte) []byte {
	b := make([]byte, 128)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) // EI_MAG + 64-bit + EI_DATA (1) + EI_VERSION (1)
	binary.LittleEndian.PutUint32(b[0x14:], 1)      // e_version
	binary.LittleEndian.PutUint64(b[0x20:], 64)     // e_phoff
	binary.LittleEndian.PutUint16(b[0x34:], 64)     // e_ehsize
	binary.LittleEndian.PutUint16(b[0x36:], 56)     // e_phentsize
	binary.LittleEndian.PutUint16(b[0x38:], 1)      // e_phnum
	o := 64
	binary.LittleEndian.PutUint32(b[o+4:], 0x02000000)        // p_flags: type nibble 2
	binary.LittleEndian.PutUint64(b[o+8:], 128)               // p_offset
	binary.LittleEndian.PutUint64(b[o+32:], uint64(len(seg))) // p_filesz
	return append(b, seg...)
}

// buildSignedELF32 is the ELFCLASS32 counterpart: p_offset@4, p_filesz@16,
// p_flags@24 in the 32-byte program header.
func buildSignedELF32(seg []byte) []byte {
	b := make([]byte, 128)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1}) // EI_MAG + 32-bit + EI_DATA (1) + EI_VERSION (1)
	binary.LittleEndian.PutUint32(b[0x14:], 1)      // e_version
	binary.LittleEndian.PutUint32(b[0x1c:], 52)     // e_phoff
	binary.LittleEndian.PutUint16(b[0x28:], 52)     // e_ehsize
	binary.LittleEndian.PutUint16(b[0x2a:], 32)     // e_phentsize
	binary.LittleEndian.PutUint16(b[0x2c:], 1)      // e_phnum
	o := 52
	binary.LittleEndian.PutUint32(b[o+4:], 128)               // p_offset
	binary.LittleEndian.PutUint32(b[o+16:], uint32(len(seg))) // p_filesz
	binary.LittleEndian.PutUint32(b[o+24:], 0x02000000)       // p_flags: type nibble 2
	return append(b, seg...)
}

// A 32-bit signed programmer must parse identically to a 64-bit one — older QC
// SoCs ship ELFCLASS32 loaders (e.g. bkerler's 000ba0e1 fhprg).
func TestFromELF32(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeCert(t, pkix.Name{
		CommonName: "Motorola Attestation 719-1-3",
		OrganizationalUnit: []string{
			"04 02E8 OEM_ID",
			"02 000BA0E102E80000 HW_ID",
			"01 0000000000000000 SW_ID",
		},
	}, key)
	root := makeCert(t, pkix.Name{CommonName: "Root CA 719"}, key)
	elf := buildSignedELF32(append(make([]byte, 64), append(leaf, root...)...))

	id, err := FromELF(elf)
	if err != nil {
		t.Fatal(err)
	}
	if id.HWID != "000BA0E102E80000" || id.JTAGID != "000BA0E1" || id.OEMID != "02E8" {
		t.Errorf("32-bit identity: HW_ID=%q JTAG=%q OEM=%q", id.HWID, id.JTAGID, id.OEMID)
	}
}

func TestFromELF(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeCert(t, pkix.Name{
		Organization: []string{"Motorola Inc"},
		CommonName:   "Motorola Attestation 724-1-3",
		OrganizationalUnit: []string{
			"04 02E8 OEM_ID",
			"02 001B80E102E80000 HW_ID",
			"01 0000000000000002 SW_ID",
			"06 0000 MODEL_ID",
			"05 00004000 SW_SIZE",
		},
	}, key)
	root := makeCert(t, pkix.Name{
		Organization: []string{"Motorola Inc"},
		CommonName:   "Root CA 724",
	}, key)

	// A dummy SHA table before the certs, to prove the carver scans past it.
	seg := append(make([]byte, 64), append(leaf, root...)...)
	elf := buildSignedELF(seg)

	id, err := FromELF(elf)
	if err != nil {
		t.Fatal(err)
	}
	if id.OEMID != "02E8" {
		t.Errorf("OEM_ID: got %q", id.OEMID)
	}
	if id.HWID != "001B80E102E80000" || id.JTAGID != "001B80E1" {
		t.Errorf("HW_ID/JTAG: got %q / %q", id.HWID, id.JTAGID)
	}
	if id.SWID != 2 {
		t.Errorf("SW_ID: got %d", id.SWID)
	}
	if id.Root != "724" {
		t.Errorf("root: got %q", id.Root)
	}
	if id.KeyBits != 2048 {
		t.Errorf("key bits: got %d", id.KeyBits)
	}
}

func TestFromELFRejectsUnsigned(t *testing.T) {
	if _, err := FromELF([]byte("not an elf")); err == nil {
		t.Error("expected error on non-ELF")
	}
	// A valid ELF header with no hash segment and no embedded ELF.
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint32(b[0x14:], 1)  // e_version
	binary.LittleEndian.PutUint16(b[0x34:], 64) // e_ehsize
	if _, err := FromELF(b); err == nil {
		t.Error("expected error on ELF without hash segment")
	}
}

func TestFromELFEmbedded(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := makeCert(t, pkix.Name{
		Organization: []string{"Motorola Inc"},
		CommonName:   "Attestation CA",
		OrganizationalUnit: []string{
			"04 02E8 OEM_ID",
			"02 001870E102E80000 HW_ID",
		},
	}, key)
	seg := append(make([]byte, 64), leaf...)
	inner := buildSignedELF(seg)

	// Wrap in an outer ELF that has no hash segment
	outer := make([]byte, 128)
	copy(outer, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	binary.LittleEndian.PutUint32(outer[0x14:], 1)  // e_version
	binary.LittleEndian.PutUint16(outer[0x28:], 52) // e_ehsize
	wrapped := append(outer, inner...)

	id, err := FromELF(wrapped)
	if err != nil {
		t.Fatalf("FromELF wrapped: %v", err)
	}
	if id.OEMID != "02E8" || id.JTAGID != "001870E1" {
		t.Errorf("got %q / %q, want 02E8 / 001870E1", id.OEMID, id.JTAGID)
	}
}

func TestCompatible(t *testing.T) {
	tg := &Identity{OEMID: "02E8", JTAGID: "001B80E1", Root: "724"}
	same := &Identity{OEMID: "02E8", JTAGID: "001B80E1", Root: "724"}
	if ok, reasons := Compatible(same, tg); !ok || len(reasons) != 0 {
		t.Errorf("identical should be clean: ok=%v reasons=%v", ok, reasons)
	}
	cross := &Identity{OEMID: "02E8", JTAGID: "0016F0E1", Root: "722"}
	if ok, reasons := Compatible(cross, tg); !ok || len(reasons) != 2 {
		t.Errorf("cross-family: want ok=true with 2 advisories, got ok=%v reasons=%v", ok, reasons)
	}
	otherOEM := &Identity{OEMID: "0100", JTAGID: "001B80E1", Root: "724"}
	if ok, _ := Compatible(otherOEM, tg); ok {
		t.Error("different OEM must be incompatible")
	}
}

func TestValidateRollback(t *testing.T) {
	// 1. Safe: matching OEM, donor AR >= target AR
	// Donor: AR=2, stage 3 (Emergency Firehose Programmer) -> 0x0000000200000003
	// Target: AR=1, stage 28 (ABL) -> 0x000000010000001C
	donorSafe := &Identity{OEMID: "02E8", SWID: 0x0000000200000003}
	target := &Identity{OEMID: "02E8", SWID: 0x000000010000001C}

	rep := ValidateRollback(donorSafe, target)
	if rep.Status != RollbackSafe {
		t.Errorf("expected RollbackSafe, got %v (%v)", rep.Status, rep.Reasons)
	}
	if rep.DonorAR != 2 || rep.TargetAR != 1 {
		t.Errorf("AR counts: got donor=%d, target=%d", rep.DonorAR, rep.TargetAR)
	}

	// 2. Warning: donor AR < target AR
	// Donor: AR=0, stage 3 -> 0x0000000000000003
	donorOlder := &Identity{OEMID: "02E8", SWID: 0x0000000000000003}
	repWarn := ValidateRollback(donorOlder, target)
	if repWarn.Status != RollbackWarning {
		t.Errorf("expected RollbackWarning, got %v", repWarn.Status)
	}
	if len(repWarn.Reasons) == 0 || !strings.Contains(repWarn.Reasons[0], "lower than target") {
		t.Errorf("expected warning reason, got %v", repWarn.Reasons)
	}

	// 3. Fatal: differing OEM_ID
	donorWrongOEM := &Identity{OEMID: "0100", SWID: 0x0000000200000003}
	repFatal := ValidateRollback(donorWrongOEM, target)
	if repFatal.Status != RollbackFatal {
		t.Errorf("expected RollbackFatal, got %v", repFatal.Status)
	}
}

func TestFromQSB32(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeCert(t, pkix.Name{
		CommonName: "Amazon Attestation",
		OrganizationalUnit: []string{
			"04 0000 OEM_ID",
			"02 007B30E100000000 HW_ID",
			"01 0000000000000003 SW_ID",
		},
	}, key)
	root := makeCert(t, pkix.Name{
		Organization: []string{"Amazon"},
		CommonName:   "Lab126 Tablet Root CA 1",
	}, key)

	// Build a synthetic 40-byte QSB header (0x844BDCD1 magic)
	hdr := make([]byte, 40)
	copy(hdr, []byte{0xd1, 0xdc, 0x4b, 0x84})
	qsb := append(hdr, append(leaf, root...)...)

	if !IsQSB(qsb) {
		t.Error("IsQSB should be true")
	}

	id, err := FromQSB(qsb)
	if err != nil {
		t.Fatalf("FromQSB failed: %v", err)
	}
	if id.Format != "QSB" {
		t.Errorf("expected format QSB, got %q", id.Format)
	}
	if id.JTAGID != "007B30E1" {
		t.Errorf("expected JTAGID 007B30E1, got %q", id.JTAGID)
	}
	if id.SWID != 3 {
		t.Errorf("expected SWID 3, got %d", id.SWID)
	}

	// Also verify FromImage handles it
	idImg, err := FromImage(qsb)
	if err != nil {
		t.Fatalf("FromImage on QSB failed: %v", err)
	}
	if idImg.Format != "QSB" || idImg.JTAGID != "007B30E1" {
		t.Errorf("FromImage mismatch: got %v", idImg)
	}
}

func TestFromELF_ModernSRoT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Leaf has no HW_ID OU (modern SecTools SRoT style)
	leaf := makeCert(t, pkix.Name{
		Organization: []string{"Samsung Corporation"},
		CommonName:   "SecTools Test User",
	}, key)
	root := makeCert(t, pkix.Name{
		Organization: []string{"Samsung Corporation"},
		CommonName:   "Samsung Root CA cert",
	}, key)

	seg := append(make([]byte, 64), append(leaf, root...)...)
	elf := buildSignedELF(seg)

	id, err := FromELF(elf)
	if err != nil {
		t.Fatalf("FromELF modern SRoT failed: %v", err)
	}
	if id.Format != "ELF" {
		t.Errorf("expected format ELF, got %q", id.Format)
	}
	if id.OEMID != "0020" {
		t.Errorf("expected OEMID 0020 for Samsung, got %q", id.OEMID)
	}
	if id.RootCN != "Samsung Root CA cert" {
		t.Errorf("expected RootCN Samsung Root CA cert, got %q", id.RootCN)
	}
	if len(id.RootHash) == 0 {
		t.Error("expected non-empty RootHash")
	}
}

func TestFromELF_MELF(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeCert(t, pkix.Name{
		Organization: []string{"vivo"},
		CommonName:   "vivo kalama attest CA",
	}, key)
	root := makeCert(t, pkix.Name{
		Organization: []string{"vivo"},
		CommonName:   "vivo kalama Root CA",
	}, key)

	innerSeg := append(make([]byte, 64), append(leaf, root...)...)
	innerELF := buildSignedELF(innerSeg)

	// Wrap in an outer 32-bit ELF container without hash segment (MELF stub)
	outer := make([]byte, 128)
	copy(outer, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	binary.LittleEndian.PutUint32(outer[0x14:], 1)
	binary.LittleEndian.PutUint16(outer[0x28:], 52)
	melf := append(outer, innerELF...)

	id, err := FromELF(melf)
	if err != nil {
		t.Fatalf("FromELF on MELF failed: %v", err)
	}
	if id.Format != "MELF" {
		t.Errorf("expected format MELF, got %q", id.Format)
	}
	if id.OEMID != "0073" {
		t.Errorf("expected OEMID 0073 for vivo, got %q", id.OEMID)
	}
	if id.RootCN != "vivo kalama Root CA" {
		t.Errorf("expected RootCN vivo kalama Root CA, got %q", id.RootCN)
	}
}



func TestScanRestriction(t *testing.T) {
	restricted := []byte("...\x00range restricted: lun=%lld...\x00handler %s is restricted!\x00Peek is disabled on secure boot devices%c\x00")
	r := ScanRestriction(restricted)
	if !r.Restricted() || !r.RangeGated || !r.HandlerGated || !r.PeekPokeOff {
		t.Fatalf("restricted loader: %+v", r)
	}
	open := ScanRestriction([]byte("a plain firehose loader with no gate strings"))
	if open.Restricted() {
		t.Fatalf("unrestricted loader flagged: %+v", open)
	}
}

// mbnV6Seg builds a v6 hash-segment prefix: the 48-byte header and one
// metadata block per (signer, words) pair, QTI first as on disk.
func mbnV6Seg(qti, oem []uint32) []byte {
	le := binary.LittleEndian
	hdr := make([]byte, 48)
	le.PutUint32(hdr[4:], 6)
	block := func(w []uint32) []byte {
		b := make([]byte, mbnV6MetaSize)
		for i, v := range w {
			le.PutUint32(b[i*4:], v)
		}
		return b
	}
	var body []byte
	if qti != nil {
		le.PutUint32(hdr[40:], mbnV6MetaSize)
		body = append(body, block(qti)...)
	}
	if oem != nil {
		le.PutUint32(hdr[44:], mbnV6MetaSize)
		body = append(body, block(oem)...)
	}
	return append(hdr, body...)
}

func TestParseMetadata(t *testing.T) {
	// major, minor, sw_id, hw_id, oem_id, model_id, app_id, flags, soc_vers[12], serials[8], root, arb
	words := func(sw, oem, flags, arb uint32, serial uint32) []uint32 {
		w := make([]uint32, 30)
		w[2], w[4], w[7], w[8], w[20], w[29] = sw, oem, flags, 0x9007, serial, arb
		return w
	}
	md := parseMetadata(mbnV6Seg(words(7, 1, 0xa, 0, 0), words(7, 0x2e8, 0x2, 3, 0xdeadbeef)))
	if len(md) != 2 || md[0].Signer != "oem" || md[1].Signer != "qti" {
		t.Fatalf("signers: %+v", md)
	}
	m := md[0]
	if m.SWID != 7 || m.OEMID != 0x2e8 || m.AntiRollback != 3 || m.Flags&MetaSoCHWVersion == 0 ||
		len(m.SoCVersions) != 1 || m.SoCVersions[0] != 0x9007 || len(m.Serials) != 1 {
		t.Fatalf("oem block: %+v", m)
	}
	if got := parseMetadata(mbnV6Seg(nil, words(28, 0x2e8, 2, 0, 0))); len(got) != 1 || got[0].SWID != 28 {
		t.Fatalf("oem-only: %+v", got)
	}
	v5 := make([]byte, 48)
	binary.LittleEndian.PutUint32(v5[4:], 5)
	if got := parseMetadata(v5); got != nil {
		t.Fatalf("v5 header has no metadata, got %+v", got)
	}
}

func TestParseMetadataV7(t *testing.T) {
	le := binary.LittleEndian
	// 40-byte header, 24-byte common block, 224-byte OEM block — the layout
	// every v7 programmer in the library shares.
	seg := make([]byte, 40+24+224)
	le.PutUint32(seg[4:], 7)
	le.PutUint32(seg[8:], 24)   // common
	le.PutUint32(seg[16:], 224) // oem
	le.PutUint32(seg[40+8:], 3) // common sw_id
	oem := seg[64:]
	le.PutUint32(oem[0:], 2)
	le.PutUint32(oem[8:], 2) // anti-rollback
	le.PutUint32(oem[16:], 0xa008)
	md := parseMetadata(seg)
	if len(md) != 1 || md[0].Signer != "oem" || md[0].SWID != 3 || md[0].AntiRollback != 2 ||
		len(md[0].SoCVersions) != 1 || md[0].SoCVersions[0] != 0xa008 {
		t.Fatalf("v7: %+v", md)
	}
}

func TestScanPeek(t *testing.T) {
	fh := "firehose MaxPayloadSizeToTarget"
	cases := []struct {
		name string
		data string
		want PeekSupport
	}{
		{"packed", "\x7fELF random binary with no vocabulary", PeekUnknown},
		{"none", fh + " read program configure", PeekNone},
		{"gated", fh + " <peek> handler; Peek is disabled on secure boot devices", PeekGated},
		{"enabled", fh + " <peek> <poke> handlers present, no gate", PeekEnabled},
		{"enabled-fmt", fh + " size in bytes is %d, nothing to peek/poke", PeekEnabled},
		{"streaming-hostdl", "ehostdl streaming download protocol", PeekNA},
		{"raw-unreadable", "\x08\x00\x00\xea bare ARM image, no vocabulary", PeekUnknown},
	}
	for _, c := range cases {
		if got := ScanPeek([]byte(c.data)); got != c.want {
			t.Errorf("%s: got %v (%s), want %v", c.name, got, got, c.want)
		}
	}
	// A QSB/MBN container is a streaming loader: peek is not applicable.
	if got := ScanPeek([]byte{0xd1, 0xdc, 0x4b, 0x84, 0, 0, 0, 0}); got != PeekNA {
		t.Errorf("QSB: got %v, want PeekNA", got)
	}
}

// buildTwoSegELF makes a 64-bit ELF with a loadable (code/data) segment and a
// separate Qualcomm hash segment, so loaderText's carve-out can be exercised.
func buildTwoSegELF(code, hash []byte) []byte {
	const ehsize, phentsize = 64, 56
	hdr := make([]byte, ehsize+2*phentsize)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint32(hdr[0x14:], 1)
	binary.LittleEndian.PutUint64(hdr[0x20:], ehsize)
	binary.LittleEndian.PutUint16(hdr[0x34:], ehsize)
	binary.LittleEndian.PutUint16(hdr[0x36:], phentsize)
	binary.LittleEndian.PutUint16(hdr[0x38:], 2)
	codeOff := uint64(len(hdr))
	hashOff := codeOff + uint64(len(code))
	// ph0: loadable code (flags type nibble 0)
	o := ehsize
	binary.LittleEndian.PutUint64(hdr[o+8:], codeOff)
	binary.LittleEndian.PutUint64(hdr[o+32:], uint64(len(code)))
	// ph1: hash segment (flags type nibble 2)
	o = ehsize + phentsize
	binary.LittleEndian.PutUint32(hdr[o+4:], 0x02000000)
	binary.LittleEndian.PutUint64(hdr[o+8:], hashOff)
	binary.LittleEndian.PutUint64(hdr[o+32:], uint64(len(hash)))
	return append(append(hdr, code...), hash...)
}

// A "peek"/"poke" appearing only in a certificate CN (the hash segment) must
// NOT read as peek support — loaderText carves the hash segment out.
func TestScanPeekIgnoresCertText(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certs := makeCert(t, pkix.Name{
		CommonName:         "peek poke firehose attacker CN",
		OrganizationalUnit: []string{"04 02E8 OEM_ID"},
	}, key)
	// Code segment without firehose vocab; the peek/poke/firehose text lives
	// only in the cert CN.
	if got := ScanPeek(buildTwoSegELF([]byte("boot code only"), certs)); got == PeekEnabled || got == PeekGated {
		t.Fatalf("cert-CN text leaked into peek detection: got %v", got)
	}
	// Same certs, but the code segment now carries real firehose + peek text.
	if got := ScanPeek(buildTwoSegELF([]byte("firehose peek poke handler"), certs)); got != PeekEnabled {
		t.Fatalf("loadable peek text: got %v, want enabled", got)
	}
}
