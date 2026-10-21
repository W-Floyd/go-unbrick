package analysis

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// A key loaded through LoadSecrets opens an encrypted image the plain engine leaves opaque.
func TestLoadSecretsOpensEncryptedImages(t *testing.T) {
	UseVendors()
	if carve.ZipPasswords == nil {
		t.Error("UseVendors set no zip passwords")
	}
	UseVendors() // twice is the same as once

	// An Android boot image's magic and header, then something plainly not noise.
	plain := append([]byte("ANDROID!"), bytes.Repeat([]byte{0x00, 0x10, 0x20, 0x30}, 4096)...)
	key, iv := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 16)
	blk, _ := aes.NewCipher(key)
	ct := make([]byte, len(plain)-len(plain)%aes.BlockSize)
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, plain[:len(ct)])

	dir, secrets := t.TempDir(), t.TempDir()
	img := filepath.Join(dir, "enc_boot.img")
	if err := os.WriteFile(img, ct, 0o644); err != nil {
		t.Fatal(err)
	}
	// Without a key it is just noise.
	root, err := OpenRoot(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, kids, _ := root.Children(); len(kids) != 0 {
		t.Fatalf("opened without a key: %d children", len(kids))
	}

	for name, b := range map[string][]byte{"build_key.hex": key, "build_iv.hex": iv} {
		if err := os.WriteFile(filepath.Join(secrets, name), []byte(hex.EncodeToString(b)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	n, err := LoadSecrets(secrets)
	if err != nil || n == 0 {
		t.Fatalf("LoadSecrets: %d %v", n, err)
	}
	if _, err := LoadSecrets(filepath.Join(dir, "nope")); err == nil {
		t.Error("a missing directory loaded")
	}

	// A new input, as the key is loaded: the first was looked at without it.
	img2 := filepath.Join(dir, "second", "enc_boot.img")
	if err := os.MkdirAll(filepath.Dir(img2), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(img2, ct, 0o644); err != nil {
		t.Fatal(err)
	}
	root, err = OpenRoot(img2)
	if err != nil {
		t.Fatal(err)
	}
	_, kids, err := root.Children()
	if err != nil || len(kids) != 1 || kids[0].Name != "boot.img" || !bytes.HasPrefix(kids[0].Head(), []byte("ANDROID!")) {
		t.Fatalf("with the key: %v %d children", err, len(kids))
	}
}
