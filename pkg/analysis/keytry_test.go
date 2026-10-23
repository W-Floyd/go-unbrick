package analysis

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// A key sent in is checked by decrypting the heads of a package's encrypted members: the right key opens them
// (whether or not it is loaded), a wrong one opens none, and a member nothing opens is still counted.
func TestTryCandidatesFindsTheKeyThatOpensAMember(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 16)
	iv := bytes.Repeat([]byte{9}, 16)
	plain := bytes.Repeat([]byte("a filesystem full of readable text. "), 200)
	plain = plain[:len(plain)/16*16]
	enc := make([]byte, len(plain))
	blk, _ := aes.NewCipher(key)
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(enc, plain)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "sub", "enc_system.ext4"), enc, 0o644)
	noise := make([]byte, 4096)
	rand.New(rand.NewSource(1)).Read(noise) // what a member no candidate opens looks like: no structure to repeat
	os.WriteFile(filepath.Join(dir, "enc_other.img"), noise, 0o644)
	os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("not encrypted"), 0o644)

	ctx := context.Background()
	n, opened, err := TryCandidates(ctx, dir, 2, nil, []Candidate{{Key: key, IV: iv}}, nil)
	if err != nil || n != 2 || len(opened) != 1 || filepath.Base(opened[0]) != "enc_system.ext4" {
		t.Errorf("the right key: %d members, opened %v, %v", n, opened, err)
	}
	wrong := bytes.Repeat([]byte{1}, 16)
	if n, opened, _ := TryCandidates(ctx, dir, 2, nil, []Candidate{{Key: wrong, IV: iv}, {Key: wrong, Mode: "ecb"}, {Key: wrong, IV: make([]byte, 16)}}, nil); n != 2 || len(opened) != 0 {
		t.Errorf("a wrong key: %d members, opened %v", n, opened)
	}
	if _, opened, _ := TryCandidates(ctx, dir, 2, nil, []Candidate{{Key: wrong, IV: iv}, {Key: key, IV: iv}}, nil); len(opened) != 1 {
		t.Errorf("a wrong and a right key: opened %v", opened)
	}
	// CBC: a wrong IV spoils only the first block, so the key still opens it. A key is proven whatever the IV;
	// an IV alone cannot be checked this way.
	if _, opened, _ := TryCandidates(ctx, dir, 2, nil, []Candidate{{Key: key, IV: bytes.Repeat([]byte{3}, 16)}}, nil); len(opened) != 1 {
		t.Errorf("the right key with another IV opened %v, want the one it opens", opened)
	}
}
