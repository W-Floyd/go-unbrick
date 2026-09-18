package rsakey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// realDiagModulus is the diagnostic-blob RSA-2048 public key modulus recovered
// from a real MotoBootModule.efi (fogona-abl-notes dec/rsa_pubkey_diag.txt, the
// key at file offset 0xe7ad0).
const realDiagModulus = "b2e5da9b15aff0487e6037a595c477f71cb4c3b710b13ba61e06ea97153120b8" +
	"361d3b710a3b0c3fd594dc12796ff5df62735748bc0e872cb3ba49bb43ce8e82" +
	"39f169f7514fbb15cade6dd2c8c347009266b56d130c11200229b0c54cec80c5" +
	"fe41c29120916eb6d77dd475415f8a9ead672eab2548185fe705ad0a0046d79a" +
	"cec1ca5588a84f62a76d7e86e8989cbe840e918df83ec14e346dcf5ca7eb21dc" +
	"3c7e2766f4d6026560ed4953dfaf7c7989422b5f5c92781533a569c8d2e9b1e3" +
	"a702fe520c86fbccdc9e29bfc48d275563c5d8fa618458bd1b708c8a41087c45" +
	"17fef9275f7e130628998f4b17b930b745d78dc32fe39b9c28a41f06839c8ebd"

// buildKeyBlob lays out flags(4) | pad(4) | modulus | exponent-record, so the
// modulus lands at offset 8 (parseAt needs ≥8 bytes before it for the header).
func buildKeyBlob(modulus []byte, flags uint32) []byte {
	rec := exponentRecord(65537)
	b := make([]byte, 8+len(modulus)+len(rec))
	b[4] = byte(flags)
	b[5] = byte(flags >> 8)
	b[6] = byte(flags >> 16)
	b[7] = byte(flags >> 24)
	copy(b[8:], modulus)
	copy(b[8+len(modulus):], rec)
	return b
}

func TestExponentRecordEncoding(t *testing.T) {
	// 65537 -> value 01 00 01 00, minimal byte-length 3.
	if got := exponentRecord(65537); hex.EncodeToString(got) != "0100010003000000" {
		t.Errorf("exponentRecord(65537) = %x", got)
	}
}

func TestScanFindsRealDiagKey(t *testing.T) {
	mod, err := hex.DecodeString(realDiagModulus)
	if err != nil {
		t.Fatal(err)
	}
	if len(mod) != 256 {
		t.Fatalf("modulus is %d bytes, want 256", len(mod))
	}
	blob := buildKeyBlob(mod, 0x01)

	res := Scan(blob)
	if len(res.Keys) != 1 {
		t.Fatalf("found %d keys, want 1", len(res.Keys))
	}
	k := res.Keys[0]
	if k.Bits() != 2048 {
		t.Errorf("bits = %d, want 2048", k.Bits())
	}
	if k.Public.E != 65537 {
		t.Errorf("exponent = %d, want 65537", k.Public.E)
	}
	if k.Public.N.Cmp(new(big.Int).SetBytes(mod)) != 0 {
		t.Error("reconstructed modulus does not match input")
	}
	if k.ModulusOffset != 8 || k.ExponentOffset != 8+256 {
		t.Errorf("offsets = mod %d / exp %d, want 8 / 264", k.ModulusOffset, k.ExponentOffset)
	}
	if k.HeaderFlags != 0x01 {
		t.Errorf("header flags = %#x, want 0x1", k.HeaderFlags)
	}
	// Ground truth from fogona-abl-notes FACTORY.md: the Root OEM Public Key's
	// documented modulus fingerprints. This pins the extractor to the real key.
	if k.ModulusSHA256 != "199d452fd464cacafb38febfa0306e8eb5d3e7efcae3f60da7148a4e45ce505f" {
		t.Errorf("modulus sha256 = %s, want the FACTORY.md root-key digest", k.ModulusSHA256)
	}
	if k.ModulusSHA1 != "50ea22cbe85b27e034c5c8f48155ae2523dda67d" {
		t.Errorf("modulus sha1 = %s, want the FACTORY.md root-key digest", k.ModulusSHA1)
	}
	if len(k.Fingerprint) != 64 {
		t.Errorf("SPKI fingerprint should be 64 hex chars, got %q", k.Fingerprint)
	}
	if !strings.Contains(k.PEM(), "BEGIN PUBLIC KEY") {
		t.Errorf("PEM export malformed: %q", k.PEM())
	}
}

func TestScanPrefers2048Over4096(t *testing.T) {
	// A 4096-bit window (512 bytes) whose trailing 256 bytes are also a valid
	// modulus must be read as 2048-bit — the ABL's keys are 2048-bit.
	mod := make([]byte, 512)
	for i := range mod {
		mod[i] = 0xAB // every 256-byte window has its MSB set
	}
	blob := buildKeyBlob(mod, 0)
	res := Scan(blob)
	if len(res.Keys) != 1 || res.Keys[0].Bits() != 2048 {
		t.Fatalf("expected one 2048-bit key, got %+v", res.Keys)
	}
}

func TestScanRejectsLowMSB(t *testing.T) {
	// A 256-byte window whose MSB is < 0x80 is not a full-width modulus. The next
	// window back (4096) is out of range here, so nothing is reported.
	mod := make([]byte, 256)
	mod[0] = 0x7f
	blob := buildKeyBlob(mod, 0)
	if res := Scan(blob); len(res.Keys) != 0 {
		t.Errorf("expected no keys for low-MSB window, got %d", len(res.Keys))
	}
}

func TestScanFindsOIDOffsets(t *testing.T) {
	blob := append([]byte{0xaa, 0xbb}, sha256ASN1OID...)
	blob = append(blob, 0xcc)
	res := Scan(blob)
	if len(res.OIDOffsets) != 1 || res.OIDOffsets[0] != 2 {
		t.Errorf("OID offsets = %v, want [2]", res.OIDOffsets)
	}
}

// A DER cert embedded in surrounding bytes is carved, its RSA key exposed, and
// its SPKI fingerprint matches the raw-key fingerprint of the same key — the
// property that lets a cert-stored key match a raw-stored one across binaries.
func TestScanCarvesCertAndFingerprintMatches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root CA"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	blob := append([]byte{0xde, 0xad, 0xbe, 0xef}, der...)
	blob = append(blob, 0x00, 0x01, 0x02)

	res := Scan(blob)
	if len(res.Certs) != 1 {
		t.Fatalf("carved %d certs, want 1", len(res.Certs))
	}
	c := res.Certs[0]
	if c.Offset != 4 || c.Public == nil || c.Subject != "CN=Test Root CA" {
		t.Errorf("cert = off %d subj %q public=%v", c.Offset, c.Subject, c.Public != nil)
	}
	// Fingerprint identity: the carved cert and the raw key agree.
	if c.Fingerprint != spkiFingerprint(&key.PublicKey) {
		t.Errorf("cert fingerprint %s != key fingerprint", c.Fingerprint)
	}
	ids := res.Identities()
	if len(ids) != 1 || ids[0].Kind != "cert" || ids[0].Bits != 2048 {
		t.Errorf("identities = %+v", ids)
	}
}
