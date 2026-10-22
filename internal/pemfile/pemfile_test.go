package pemfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func enc(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestParseKeysAndCert(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	blocks, ok := Parse(enc("PUBLIC KEY", spki))
	if !ok || len(blocks) != 1 || !strings.HasPrefix(blocks[0].Detail, "public key: RSA-2048 e=65537 sha256:") {
		t.Fatalf("public key: %+v", blocks)
	}
	if !strings.HasPrefix(blocks[0].Lines[0], "SPKI sha256 ") {
		t.Errorf("lines %v", blocks[0].Lines)
	}

	// A private key is named and matched to its public half, and none of it is printed.
	blocks, ok = Parse(enc("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k)))
	if !ok || !strings.HasPrefix(blocks[0].Detail, "private key: RSA-2048") {
		t.Fatalf("private key: %+v", blocks)
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA", Organization: []string{"Acme"}},
		NotBefore: time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 3, 4, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ec.PublicKey, ec)
	if err != nil {
		t.Fatal(err)
	}
	both := append(enc("CERTIFICATE", der), enc("PUBLIC KEY", spki)...)
	blocks, ok = Parse(both)
	if !ok || len(blocks) != 2 {
		t.Fatalf("two blocks: %+v", blocks)
	}
	if !strings.Contains(blocks[0].Detail, "certificate for Test CA — ECDSA P-256") {
		t.Errorf("cert: %q", blocks[0].Detail)
	}
	joined := strings.Join(blocks[0].Lines, "\n")
	for _, want := range []string{"valid:   2020-01-02 to 2040-03-04", "self-signed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("cert lines lack %q:\n%s", want, joined)
		}
	}
}

func TestParseRefusesOtherText(t *testing.T) {
	for _, s := range []string{"", "hello", "-----BEGIN", "x\n-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"} {
		if _, ok := Parse([]byte(s)); ok {
			t.Errorf("%q parsed", s)
		}
	}
}
