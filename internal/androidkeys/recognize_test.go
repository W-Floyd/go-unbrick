package androidkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/pkg/analysis/recognize"
)

var _ recognize.Recognizer = Recognizer{}

func TestRecognizer(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	h := []byte(format(&k.PublicKey, false)) // format() is androidkeys_test.go's own fixture builder

	r := Recognizer{}
	if !r.Claims("keys", h) {
		t.Fatal("should claim a real res/keys header")
	}
	if r.Claims("keys", []byte("not a key file")) {
		t.Error("should not claim plain text")
	}
	if got := r.Label("keys", h); got != "Android recovery keys" {
		t.Errorf("label %q", got)
	}
	if s := r.Summary("keys", h, nil); !strings.Contains(s, "key") {
		t.Errorf("summary %q", s)
	}
	lines := r.Report("x", "keys", h, nil)
	if len(lines) == 0 || !strings.Contains(lines[0], "RSA") {
		t.Errorf("report %+v", lines)
	}
}
