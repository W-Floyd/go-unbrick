package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
)

func TestNameAffinity(t *testing.T) {
	for _, c := range []struct {
		key, iv string
		want    int // the shared words, in characters
	}{
		{"2022_2024-usa-ev6_image_dat_key", "2022_2024-usa-ev6_iv", len("2022_2024-usa-ev6_")},
		{"2022-can-ioniq5-v011.007_image_dat_key", "2022-can-ioniq5-v011.007_iv", len("2022-can-ioniq5-v011.007_")},
		{"2022_2024-usa-ev6_image_dat_key", "2022-can-ioniq5-v011.007_iv", 0}, // "2022" is not a word of both
		{"2022-can-ioniq5-v011.007_image_dat_key", "2022-can-ioniq5-v015.011_iv", len("2022-can-ioniq5-")},
		{"Build_Key", "build_iv", len("build_")}, // case is not a difference
		{"", "x_iv", 0},
	} {
		if got := nameAffinity(c.key, c.iv); got != c.want {
			t.Errorf("nameAffinity(%q, %q) = %d, want %d", c.key, c.iv, got, c.want)
		}
	}
}

// encrypted is plain under key and iv, as AES-CBC, with a secrets directory
// holding the files named: name -> hex.
func encrypted(t *testing.T, plain, key, iv []byte, files map[string][]byte) []byte {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(hex.EncodeToString(b)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := aeskeys.Secrets()
	t.Cleanup(func() { aeskeys.Set(old) })
	if err := loadSecrets(dir); err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(key)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, plain)
	return ct
}

func iv16(seed int64) []byte {
	b := make([]byte, 16)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// bootImage is the start of an Android boot image: its magic and header, then
// something that is plainly not noise.
func bootImage() []byte {
	b := make([]byte, 16<<10)
	copy(b, "ANDROID!")
	b[8], b[9], b[10] = 0x38, 0xfa, 0x68 // kernel size
	b[14], b[15] = 0x00, 0x80            // kernel address 0x80008000
	b[12], b[13] = 0x00, 0x80
	copy(b[64:], "console=null androidboot.selinux=disabled")
	for i := 640; i < len(b); i++ {
		b[i] = byte(i % 7)
	}
	return b
}

func TestTheIVThatMakesTheFirstBlockRightIsChosen(t *testing.T) {
	key := iv16(1) // any 16 bytes
	good, bad := iv16(2), iv16(3)
	plain := bootImage()
	// Names with nothing in common, the wrong IV's sorting first: the order alone
	// would pick it.
	ct := encrypted(t, plain, key, good, map[string][]byte{
		"build_image_dat_key.hex": key,
		"aaa_iv.hex":              bad,
		"zzz_iv.hex":              good,
	})
	dec, _, ok := decryptedReaderAt(bytes.NewReader(ct), int64(len(ct)), ct[:8192])
	if !ok {
		t.Fatal("not opened")
	}
	first := make([]byte, 16)
	if _, err := dec.ReadAt(first, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, plain[:16]) {
		t.Errorf("the first block is %q (%x), want the boot image's %q: the wrong IV was used", first, first, plain[:16])
	}
	// Everything after it was never in doubt.
	rest := make([]byte, 4096)
	dec.ReadAt(rest, 4096)
	if !bytes.Equal(rest, plain[4096:8192]) {
		t.Error("the middle of the image is wrong")
	}
}

func TestTheNamedIVComesFirst(t *testing.T) {
	key := iv16(11)
	own, other := iv16(12), iv16(13)
	encrypted(t, bootImage(), key, own, map[string][]byte{
		"2022_usa-ev6_image_dat_key.hex": key,
		"2022-can-x_iv.hex":              other, // sorts before the key's own
		"2022_usa-ev6_iv.hex":            own,
	})
	var firstIV []byte
	for _, s := range aeskeys.Secrets() {
		if s.Mode == "" && s.Name == "2022_usa-ev6_image_dat_key" {
			firstIV = s.IV
			break
		}
	}
	if !bytes.Equal(firstIV, own) {
		t.Errorf("the first IV tried for the key is %x, want its own, %x", firstIV, own)
	}
}

// With no magic to go by, an image of a filesystem begins with zeros, and the IV
// that gives them is the right one.
func TestAnImageBeginningWithZerosPicksTheIVThatGivesZeros(t *testing.T) {
	key := iv16(21)
	good, bad := iv16(22), iv16(23)
	plain := make([]byte, 8<<10) // 16 zero bytes, then a pattern that is not noise
	for i := 16; i < len(plain); i++ {
		plain[i] = byte("abcdefgh"[i%8])
	}
	ct := encrypted(t, plain, key, good, map[string][]byte{
		"k_image_dat_key.hex": key,
		"aaa_iv.hex":          bad,
		"zzz_iv.hex":          good,
	})
	dec, _, ok := decryptedReaderAt(bytes.NewReader(ct), int64(len(ct)), ct[:8192])
	if !ok {
		t.Fatal("not opened")
	}
	first := make([]byte, 16)
	dec.ReadAt(first, 0)
	if !bytes.Equal(first, make([]byte, 16)) {
		t.Errorf("first block %x, want zeros", first)
	}
}

// One key and one IV still work, as before.
func TestASinglePairStillOpens(t *testing.T) {
	key, iv := iv16(31), iv16(32)
	plain := bootImage()
	ct := encrypted(t, plain, key, iv, map[string][]byte{"only_key.hex": key, "only_iv.hex": iv})
	dec, name, ok := decryptedReaderAt(bytes.NewReader(ct), int64(len(ct)), ct[:8192])
	if !ok || name != "only_key" {
		t.Fatalf("ok=%v name=%q", ok, name)
	}
	got := make([]byte, 8)
	dec.ReadAt(got, 0)
	if string(got) != "ANDROID!" {
		t.Errorf("first bytes %q", got)
	}
}
