package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// A secrets directory holds hex files: *key* (AES key) and *iv* (16-byte IV),
// found by the underscore/dash/dot-separated words in the file name. A member
// that is neither a known format nor readable text is tried against every
// key and IV pair, as continuous AES-CBC over its head, and labelled only if
// the plaintext is a format typeLabel recognises.
type aesSecret struct {
	name string
	key  []byte
	iv   []byte
	mode string // "" CBC under iv, "ecb", or "prefix" (CBC, the first block is the IV)
}

// decryptHead decrypts the whole blocks of head under s.
func (s aesSecret) decryptHead(blk cipher.Block, head []byte) []byte {
	n := len(head) - len(head)%aes.BlockSize
	switch s.mode {
	case "ecb":
		out := make([]byte, n)
		for i := 0; i < n; i += aes.BlockSize {
			blk.Decrypt(out[i:], head[i:])
		}
		return out
	case "prefix":
		if n < 2*aes.BlockSize {
			return nil
		}
		out := make([]byte, n-aes.BlockSize)
		cipher.NewCBCDecrypter(blk, head[:aes.BlockSize]).CryptBlocks(out, head[aes.BlockSize:n])
		return out
	}
	out := make([]byte, n)
	cipher.NewCBCDecrypter(blk, s.iv).CryptBlocks(out, head[:n])
	return out
}

// proven reports whether plain, decrypted under a candidate secret, is
// plaintext rather than the uniform noise a wrong key leaves: a known format,
// a Telechips LK or splash header, or structure (low entropy over enough bytes
// to tell).
func proven(plain []byte) bool {
	return filetype.Detect(plain) != filetype.Unknown ||
		bytes.HasPrefix(plain, []byte("ANDROID@")) ||
		bytes.HasPrefix(plain, []byte("splash\x00")) ||
		len(plain) >= 1024 && !highEntropy(plain)
}

var (
	reconSecrets []aesSecret
	inDecrypt    bool
	nameWords    = regexp.MustCompile(`[_.\-]+`)
)

func loadSecrets(dir string) error {
	es, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var keys, ivs []aesSecret
	for _, e := range es {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(b) != aes.BlockSize && len(b) != 24 && len(b) != 32 {
			continue
		}
		stem := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		s := aesSecret{name: stem}
		isIV := false
		for _, w := range nameWords.Split(strings.ToLower(stem), -1) {
			if w == "iv" {
				isIV = true
			}
		}
		if isIV && len(b) == aes.BlockSize {
			s.iv = b
			ivs = append(ivs, s)
		} else if !isIV {
			s.key = b
			keys = append(keys, s)
		}
	}
	reconSecrets = nil
	for _, k := range keys {
		// A key is tried first with the IV that is named like it: the same build's
		// key and IV share the start of their file names. (Which IV is right shows
		// only in the first block of what is decrypted; see bestSecret.)
		byName := append([]aesSecret(nil), ivs...)
		sort.SliceStable(byName, func(i, j int) bool {
			return nameAffinity(k.name, byName[i].name) > nameAffinity(k.name, byName[j].name)
		})
		for _, iv := range byName {
			reconSecrets = append(reconSecrets, aesSecret{name: k.name, key: k.key, iv: iv.iv})
		}
	}
	// Less likely framings of the same keys, tried after every key/IV pair.
	for _, k := range keys {
		reconSecrets = append(reconSecrets,
			aesSecret{name: k.name + " (zero IV)", key: k.key, iv: make([]byte, aes.BlockSize)},
			aesSecret{name: k.name + " (ecb)", key: k.key, mode: "ecb"},
			aesSecret{name: k.name + " (prefixed IV)", key: k.key, mode: "prefix"})
	}
	return nil
}

// nameAffinity is how much of a key's file name and an IV's file name they have
// in common, up to a word boundary: "2022_2024-usa-ev6_image_dat_key" and
// "2022_2024-usa-ev6_iv" share "2022_2024-usa-ev6_", but neither shares more than
// "2022" with "2022-can-ioniq5-v011.007_iv", which is not a word.
func nameAffinity(a, b string) int {
	a, b = strings.ToLower(a), strings.ToLower(b)
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	for n > 0 && !strings.ContainsRune("_-.", rune(a[n-1])) {
		n--
	}
	return n
}

// bestSecret picks, for the key s proved, the IV that decrypts the first block
// properly. Only that block depends on the IV in CBC, so the structure that
// proved the key says nothing about it, and with several IVs loaded the first
// would otherwise win whether it is right or not. The first block is right when
// it is a known format's magic, or the zeros an image of a filesystem begins
// with; of IVs that do equally well, the earlier (the better-named) stays.
func bestSecret(s aesSecret, blk cipher.Block, head []byte) aesSecret {
	if s.mode != "" {
		return s
	}
	best, bestScore := s, -1
	for _, c := range reconSecrets {
		if c.mode != "" || !bytes.Equal(c.key, s.key) {
			continue
		}
		plain := c.decryptHead(blk, head)
		if len(plain) < aes.BlockSize {
			continue
		}
		score := 0
		if filetype.Detect(plain) != filetype.Unknown || bytes.HasPrefix(plain, []byte("ANDROID@")) || bytes.HasPrefix(plain, []byte("splash\x00")) {
			score++
		}
		if bytes.Equal(plain[:aes.BlockSize], make([]byte, aes.BlockSize)) {
			score++
		}
		if score > bestScore {
			best, bestScore = c, score
		}
	}
	return best
}

// findSecrets returns a secrets directory beside a collection: <dir>/secrets
// or <dir>/../secrets.
func findSecrets(dir string) string {
	for _, c := range []string{filepath.Join(dir, "secrets"), filepath.Join(dir, "..", "secrets")} {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return ""
}

// decryptLabel decrypts head under each loaded secret and returns the label
// of the first plaintext typeLabel can name.
func decryptLabel(head []byte) (string, bool) {
	if len(reconSecrets) == 0 || inDecrypt || len(head) < 2*aes.BlockSize {
		return "", false
	}
	inDecrypt = true
	defer func() { inDecrypt = false }()
	for _, s := range reconSecrets {
		blk, err := aes.NewCipher(s.key)
		if err != nil {
			continue
		}
		plain := s.decryptHead(blk, head)
		if plain == nil {
			continue
		}
		l := typeLabel("", plain)
		switch {
		case bytes.HasPrefix(plain, []byte("ANDROID@")):
			l = "LK bootloader"
		case bytes.HasPrefix(plain, []byte("splash\x00")):
			l = "splash image"
		case l == "unknown" && !highEntropy(plain):
			// A wrong key leaves uniform noise; structure after decrypting is the
			// key's proof even where the format has no signature here.
			l = "data"
		}
		if l != "unknown" && l != "encrypted or compressed" && l != "text" {
			return "encrypted " + l, true
		}
	}
	return "", false
}

// cbcReaderAt exposes the plaintext of an AES-CBC ciphertext by range: block i
// decrypts from ciphertext blocks i-1 and i alone, so a filesystem inside a
// multi-GiB image can be walked without decrypting the rest.
type cbcReaderAt struct {
	ra   io.ReaderAt
	blk  cipher.Block
	iv   []byte
	size int64
	ecb  bool  // blocks decrypt independently
	base int64 // ciphertext offset of plaintext offset 0 (16 when the IV leads)
}

// padLen is the PKCS#7 pad on the final plaintext block, 0 if the block does
// not end in a valid pad.
func (c *cbcReaderAt) padLen() int64 {
	if c.size < aes.BlockSize {
		return 0
	}
	last := make([]byte, aes.BlockSize)
	if _, err := c.ReadAt(last, c.size-aes.BlockSize); err != nil && err != io.EOF {
		return 0
	}
	n := int(last[aes.BlockSize-1])
	if n < 1 || n > aes.BlockSize {
		return 0
	}
	for _, b := range last[aes.BlockSize-n:] {
		if int(b) != n {
			return 0
		}
	}
	return int64(n)
}

func (c *cbcReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= c.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	eof := false
	if off+want > c.size {
		want, eof = c.size-off, true
	}
	start := off &^ (aes.BlockSize - 1)
	end := (off + want + aes.BlockSize - 1) &^ (aes.BlockSize - 1)
	// The block before start is the IV of CBC; the stored IV serves only the
	// first block of a stream that has none in front of it.
	lead := int64(aes.BlockSize)
	if c.ecb || start == 0 && c.base == 0 {
		lead = 0
	}
	buf := make([]byte, end-start+lead)
	if _, err := c.ra.ReadAt(buf, c.base+start-lead); err != nil && err != io.EOF {
		return 0, err
	}
	plain := make([]byte, end-start)
	if c.ecb {
		for i := 0; i < len(plain); i += aes.BlockSize {
			c.blk.Decrypt(plain[i:], buf[i:])
		}
	} else {
		iv := c.iv
		if lead > 0 {
			iv = buf[:aes.BlockSize]
		}
		cipher.NewCBCDecrypter(c.blk, iv).CryptBlocks(plain, buf[lead:])
	}
	n := copy(p, plain[off-start:off-start+want])
	if eof {
		return n, io.EOF
	}
	return n, nil
}

// decryptedReaderAt returns the plaintext view of ciphertext under the first
// loaded secret whose plaintext head is a filesystem.
//
// The images are PKCS#7-padded (1–16 bytes of the pad length), so the reader's
// size excludes the pad.
func decryptedReaderAt(ra io.ReaderAt, size int64, head []byte) (*cbcReaderAt, string, bool) {
	if len(head) < 2*aes.BlockSize {
		return nil, "", false
	}
	for _, s := range reconSecrets {
		blk, err := aes.NewCipher(s.key)
		if err != nil {
			continue
		}
		if plain := s.decryptHead(blk, head); plain != nil && proven(plain) {
			s = bestSecret(s, blk, head)
			c := &cbcReaderAt{ra: ra, blk: blk, iv: s.iv, size: size &^ (aes.BlockSize - 1), ecb: s.mode == "ecb"}
			if s.mode == "prefix" {
				c.base, c.size = aes.BlockSize, c.size-aes.BlockSize
			}
			c.size -= c.padLen()
			return c, s.name, true
		}
	}
	return nil, "", false
}

// encryptedExpander lets ls/extract see through an AES-encrypted member (an
// enc_*.ext4 or enc_boot.img) whose plaintext head is a known format: its one
// child is the decrypted image, read by range, named without the enc_ prefix.
func encryptedExpander() carve.Expander {
	open := func(n *carve.Node, head []byte) (*carve.Node, bool) {
		if len(reconSecrets) == 0 || !n.RandomAccess() {
			return nil, false
		}
		ra, err := n.ReaderAt()
		if err != nil {
			return nil, false
		}
		dec, _, ok := decryptedReaderAt(ra, n.Size, head)
		if !ok {
			return nil, false
		}
		return carve.FromReaderAt(strings.TrimPrefix(path.Base(n.Name), "enc_"), dec, dec.size), true
	}
	return carve.Expander{
		Kind: "encrypted",
		Match: func(n *carve.Node, head []byte) bool {
			if filetype.Detect(head) != filetype.Unknown || !highEntropy(head) {
				return false
			}
			_, ok := open(n, head)
			return ok
		},
		Expand: func(n *carve.Node) ([]*carve.Node, error) {
			head := make([]byte, 8192)
			ra, err := n.ReaderAt()
			if err != nil {
				return nil, err
			}
			k, _ := ra.ReadAt(head, 0)
			child, ok := open(n, head[:k])
			if !ok {
				return nil, errors.New("no loaded key opens it")
			}
			return []*carve.Node{child}, nil
		},
	}
}

// printEncryptedFS walks a filesystem inside an encrypted member through a
// range-decrypting reader: the build's identity from its build.prop, then the
// top-level directory counts. False when no secret opens it or it is not
// seekable.
// openEncryptedFS opens an encrypted tar member as a filesystem, trying every
// loaded secret (see decryptedReaderAt) and letting carve pick ext4 vs erofs
// from the decrypted content. Shared by the display path (printEncryptedFS)
// and the fact-extraction path (encryptedSystemProps), so a key loaded once
// serves both.
func openEncryptedFS(path string, m srcfile.Member) (fs.FS, string, bool) {
	if len(reconSecrets) == 0 {
		return nil, "", false
	}
	n, err := carvePath(path, m.Name)
	if err != nil || !n.RandomAccess() {
		return nil, "", false
	}
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, "", false
	}
	dec, key, ok := decryptedReaderAt(ra, int64(m.Size), m.Head)
	if !ok {
		return nil, "", false
	}
	fsys, err := carve.FromReaderAt("", dec, dec.size).FS()
	if err != nil {
		return nil, "", false
	}
	return fsys, key, true
}

func printEncryptedFS(path string, m srcfile.Member, indent string, clear func()) bool {
	fsys, key, ok := openEncryptedFS(path, m)
	if !ok {
		return false
	}
	clear()
	// Its identity already printed up top (learnSystemProps feeds the same
	// build.prop into the bag before the member loop reaches here) — this is
	// just the layout.
	fmt.Printf("%s%-26s [encrypted filesystem, opened with %s]  %s\n", indent, filepath.Base(m.Name), key, humanBytes(int64(m.Size)))
	count := map[string]int{}
	var dirs []string
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		top, _, found := strings.Cut(p, "/")
		if !found {
			top = "."
		}
		if count[top] == 0 {
			dirs = append(dirs, top)
		}
		count[top]++
		return nil
	})
	sort.Strings(dirs)
	for _, d := range dirs {
		fmt.Printf("%s  %-24s %d files\n", indent, d+"/", count[d])
	}
	return true
}
