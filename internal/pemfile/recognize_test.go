package pemfile

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/pkg/analysis/recognize"
)

var _ recognize.Recognizer = Recognizer{}

func TestRecognizer(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	h := enc("PUBLIC KEY", spki)

	r := Recognizer{}
	if !r.Claims("key.pem", h) {
		t.Fatal("should claim a real PEM block")
	}
	if r.Claims("x", []byte("not pem")) {
		t.Error("should not claim plain text")
	}
	if got := r.Label("key.pem", h); got != "PEM public key" {
		t.Errorf("label %q", got)
	}
	if s := r.Summary("key.pem", h, nil); !strings.HasPrefix(s, " — public key: RSA-2048") {
		t.Errorf("summary %q", s)
	}
	lines := r.Report("x", "key.pem", h, nil)
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "public key: RSA-2048") {
		t.Errorf("report %+v", lines)
	}
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "  SPKI sha256 ") {
		t.Errorf("report nested line %+v", lines)
	}
}

func TestRecognizerBundle(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	both := append(enc("PUBLIC KEY", spki), enc("PUBLIC KEY", spki)...)

	r := Recognizer{}
	if got := r.Label("bundle.pem", both); got != "PEM bundle (2 blocks)" {
		t.Errorf("label %q", got)
	}
	if s := r.Summary("bundle.pem", both, nil); s != "" {
		t.Errorf("summary for a multi-block bundle should be empty, got %q", s)
	}
}
