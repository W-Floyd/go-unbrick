package analysis

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
)

func TestFindKeyFiles(t *testing.T) {
	known := bytes.Repeat([]byte{0xAB}, 16)
	fresh := bytes.Repeat([]byte{0xCD}, 16)
	old := aeskeys.Secrets()
	aeskeys.Set([]aeskeys.Secret{{Name: "ev6-image", Key: known}})
	t.Cleanup(func() { aeskeys.Set(old) })

	dir := t.TempDir()
	put := func(name string, data []byte) {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("sys/etc/image.dat", []byte(hex.EncodeToString(known)+"\n"))
	put("other/iv.dat", fresh) // raw bytes, not text
	put("notes.txt", []byte("not a key"))
	put("deep/notiv.dat", []byte("x")) // name must be exactly iv.dat / image.dat
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte(hex.EncodeToString(fresh))
	tw.WriteHeader(&tar.Header{Name: "enc/etc/iv.dat", Mode: 0o644, Size: int64(len(body))})
	tw.Write(body)
	tw.Close()
	put("pkg.tar", buf.Bytes())

	var opened int
	var last string
	got, err := FindKeyFiles(context.Background(), dir, 3, func(o, f int, at string) { opened, last = o, at })
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]KeyFile{}
	for _, k := range got {
		byPath[k.Path] = k
	}
	if len(got) != 3 {
		t.Fatalf("found %d files, want 3: %+v", len(got), got)
	}
	if k := byPath["sys/etc/image.dat"]; k.Known != "ev6-image" || k.Value != hex.EncodeToString(known) {
		t.Errorf("a loaded key: %+v", k)
	}
	if k := byPath["other/iv.dat"]; k.Known != "" || k.Size != 16 {
		t.Errorf("a new raw IV: %+v", k)
	}
	if k := byPath["pkg.tar/enc/etc/iv.dat"]; k.Known != "" || k.Value != hex.EncodeToString(fresh) {
		t.Errorf("one inside a container: %+v", k)
	}
	if opened != 1 || last != "pkg.tar" {
		t.Errorf("progress said %d containers opened, last %q", opened, last)
	}
	// Depth 0 does not open containers.
	got, _ = FindKeyFiles(context.Background(), dir, 0, nil)
	for _, k := range got {
		if k.Path == "pkg.tar/enc/etc/iv.dat" {
			t.Error("depth 0 opened a container")
		}
	}
	// A cancelled search says so.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FindKeyFiles(ctx, dir, 3, nil); err == nil {
		t.Error("a cancelled search did not say so")
	}
}

func TestScanKeysSaysWhichSecretOpensWhichMember(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{0x3c, 0xa1, 0x07, 0xd5}, 4)
	ivBytes := bytes.Repeat([]byte{0x91, 0x2e, 0xb8, 0x44}, 4)
	secrets := t.TempDir()
	os.WriteFile(filepath.Join(secrets, "ev6_image_key.hex"), []byte(hex.EncodeToString(keyBytes)+"\n"), 0o600)
	os.WriteFile(filepath.Join(secrets, "ev6_iv.hex"), []byte(hex.EncodeToString(ivBytes)+"\n"), 0o600)
	old := aeskeys.Secrets()
	t.Cleanup(func() { aeskeys.Set(old) })
	if n, err := LoadSecrets(secrets); err != nil || n == 0 {
		t.Fatalf("LoadSecrets = %d, %v", n, err)
	}

	// A tar of text, encrypted under the secret (PKCS#7 padded), and noise nothing opens.
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	body := bytes.Repeat([]byte("firmware text\n"), 200)
	tw.WriteHeader(&tar.Header{Name: "etc/iv.dat", Mode: 0o644, Size: int64(len(body))})
	tw.Write(body)
	tw.Close()
	pad := 16 - plain.Len()%16
	data := append(plain.Bytes(), bytes.Repeat([]byte{byte(pad)}, pad)...)
	blk, _ := aes.NewCipher(keyBytes)
	cipher.NewCBCEncrypter(blk, ivBytes).CryptBlocks(data, data)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "enc_inner.tar"), data, 0o644)
	noise := make([]byte, 4096)
	rand.New(rand.NewSource(1)).Read(noise)
	os.WriteFile(filepath.Join(dir, "enc_noise.bin"), noise, 0o644)

	got, err := ScanKeys(context.Background(), dir, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Uses) != 1 || got.Uses[0].Path != "enc_inner.tar" || !strings.Contains(got.Uses[0].Secret, "ev6") {
		t.Errorf("uses = %+v", got.Uses)
	}
	// The key and the IV that opened it, together.
	if u := got.Uses[0]; u.Key != hex.EncodeToString(keyBytes) || u.IV != hex.EncodeToString(ivBytes) || !strings.Contains(u.IVFile, "iv") || !strings.Contains(u.KeyFile, "key") {
		t.Errorf("the pair: %+v", u)
	}
	if len(got.Unopened) != 1 || got.Unopened[0] != "enc_noise.bin" {
		t.Errorf("unopened = %v", got.Unopened)
	}
}

// An IV that more than one loaded file holds is named for the one that goes with the key beside it, and an IV
// is named for its own file, not the key's.
func TestKeyFilesNameTheIVFileThatGoesWithTheKeyBeside(t *testing.T) {
	keyA := bytes.Repeat([]byte{0x3c, 0xa1, 0x07, 0xd5}, 4)
	keyB := bytes.Repeat([]byte{0x6b, 0xc2, 0x19, 0xf0}, 4)
	iv := bytes.Repeat([]byte{0x91, 0x2e, 0xb8, 0x44}, 4) // the same bytes in two IV files
	secrets := t.TempDir()
	put := func(name string, b []byte) { os.WriteFile(filepath.Join(secrets, name), []byte(hex.EncodeToString(b)+"\n"), 0o600) }
	put("ev6-v1_image_dat_key.hex", keyA)
	put("kona-v2_image_dat_key.hex", keyB)
	put("ev6-v1_iv.hex", iv)
	put("kona-v2_iv.hex", iv)
	old := aeskeys.Secrets()
	t.Cleanup(func() { aeskeys.Set(old) })
	if _, err := LoadSecrets(secrets); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for sys, key := range map[string][]byte{"a": keyA, "b": keyB} {
		os.MkdirAll(filepath.Join(dir, sys, "etc"), 0o755)
		os.WriteFile(filepath.Join(dir, sys, "etc", "image.dat"), []byte(hex.EncodeToString(key)+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, sys, "etc", "iv.dat"), []byte(hex.EncodeToString(iv)+"\n"), 0o644)
	}
	got, err := ScanKeys(context.Background(), dir, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]string{}
	for _, f := range got.Files {
		known[f.Path] = f.Known
	}
	if !strings.Contains(known["a/etc/image.dat"], "ev6-v1") || !strings.Contains(known["b/etc/image.dat"], "kona-v2") {
		t.Errorf("the keys: %v", known)
	}
	if !strings.Contains(known["a/etc/iv.dat"], "ev6-v1_iv") || strings.Contains(known["a/etc/iv.dat"], "key") {
		t.Errorf("the IV beside the first key: %q", known["a/etc/iv.dat"])
	}
	if !strings.Contains(known["b/etc/iv.dat"], "kona-v2_iv") || strings.Contains(known["b/etc/iv.dat"], "key") {
		t.Errorf("the IV beside the second key: %q", known["b/etc/iv.dat"])
	}
}
