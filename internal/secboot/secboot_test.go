package secboot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
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
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2})     // EI_MAG + 64-bit
	binary.LittleEndian.PutUint64(b[0x20:], 64) // e_phoff
	binary.LittleEndian.PutUint16(b[0x36:], 56) // e_phentsize
	binary.LittleEndian.PutUint16(b[0x38:], 1)  // e_phnum
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
	copy(b, []byte{0x7f, 'E', 'L', 'F', 1})     // EI_MAG + 32-bit
	binary.LittleEndian.PutUint32(b[0x1c:], 52) // e_phoff
	binary.LittleEndian.PutUint16(b[0x2a:], 32) // e_phentsize
	binary.LittleEndian.PutUint16(b[0x2c:], 1)  // e_phnum
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
	// A valid ELF header with no hash segment.
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2})
	if _, err := FromELF(b); err == nil {
		t.Error("expected error on ELF without hash segment")
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
