// Package aeskeys is the AES keys and IVs a user keeps in a secrets directory, and what they
// open: members of a package that are AES-CBC encrypted images (enc_*.ext4, enc_boot.img), read
// by range without decrypting the rest.
//
// A secrets directory holds hex files: *key* (AES key) and *iv* (16-byte IV), found by the
// underscore/dash/dot-separated words in the file name. A member that is neither a known format
// nor readable text is tried against every key and IV pair, as continuous AES-CBC over its head,
// and taken to be encrypted only if the plaintext is a format the caller recognises.
package aeskeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
)

// Secret is a key, with the IV that goes with it and how the data is framed.
type Secret struct {
	Name string
	Key  []byte
	IV   []byte
	Mode string // "" CBC under IV, "ecb", or "prefix" (CBC, the first block is the IV)
}

// DecryptHead decrypts the whole blocks of head under s.
func (s Secret) DecryptHead(blk cipher.Block, head []byte) []byte {
	n := len(head) - len(head)%aes.BlockSize
	switch s.Mode {
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
	cipher.NewCBCDecrypter(blk, s.IV).CryptBlocks(out, head[:n])
	return out
}

// HighEntropy reports bytes as close to uniform as ciphertext or compressed data, and enough of
// them to tell: what is left once no format is seen.
func HighEntropy(b []byte) bool {
	if len(b) < 1024 {
		return false
	}
	var count [256]int
	for _, c := range b {
		count[c]++
	}
	h := 0.0
	for _, n := range count {
		if n > 0 {
			p := float64(n) / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	// A sample of n bytes from a uniform source falls short of 8 bits by about 255/(2n ln 2);
	// allow a little more.
	return h > 8-255/(float64(len(b))*math.Ln2)-0.05
}

// Proven reports whether plain, decrypted under a candidate secret, is plaintext rather than the
// uniform noise a wrong key leaves: a known format, a Telechips LK or splash header, or structure
// (low entropy over enough bytes to tell).
func Proven(plain []byte) bool {
	return filetype.Detect(plain) != filetype.Unknown ||
		bytes.HasPrefix(plain, []byte("ANDROID@")) ||
		bytes.HasPrefix(plain, []byte("splash\x00")) ||
		len(plain) >= 1024 && !HighEntropy(plain)
}

var (
	mu        sync.RWMutex
	loaded    []Secret
	nameWords = regexp.MustCompile(`[_.\-]+`)
)

// Secrets are the key/IV candidates loaded, in the order they are tried.
func Secrets() []Secret {
	mu.RLock()
	defer mu.RUnlock()
	return loaded
}

// Count is how many candidates are loaded.
func Count() int { return len(Secrets()) }

// Set replaces the loaded candidates (a test puts back what it found).
func Set(s []Secret) {
	mu.Lock()
	loaded = s
	mu.Unlock()
}

// Load reads the keys and IVs in dir, replacing what was loaded.
func Load(dir string) error {
	es, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var keys, ivs []Secret
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
		s := Secret{Name: stem}
		isIV := false
		for _, w := range nameWords.Split(strings.ToLower(stem), -1) {
			if w == "iv" {
				isIV = true
			}
		}
		if isIV && len(b) == aes.BlockSize {
			s.IV = b
			ivs = append(ivs, s)
		} else if !isIV {
			s.Key = b
			keys = append(keys, s)
		}
	}
	var out []Secret
	for _, k := range keys {
		// A key is tried first with the IV that is named like it: the same build's key and IV
		// share the start of their file names. (Which IV is right shows only in the first block
		// of what is decrypted; see bestSecret.)
		byName := append([]Secret(nil), ivs...)
		sort.SliceStable(byName, func(i, j int) bool {
			return NameAffinity(k.Name, byName[i].Name) > NameAffinity(k.Name, byName[j].Name)
		})
		for _, iv := range byName {
			out = append(out, Secret{Name: k.Name, Key: k.Key, IV: iv.IV})
		}
	}
	// Less likely framings of the same keys, tried after every key/IV pair.
	for _, k := range keys {
		out = append(out,
			Secret{Name: k.Name + " (zero IV)", Key: k.Key, IV: make([]byte, aes.BlockSize)},
			Secret{Name: k.Name + " (ecb)", Key: k.Key, Mode: "ecb"},
			Secret{Name: k.Name + " (prefixed IV)", Key: k.Key, Mode: "prefix"})
	}
	Set(out)
	return nil
}

// NameAffinity is how much of a key's file name and an IV's file name they have in common, up to a
// word boundary: "2022_2024-usa-ev6_image_dat_key" and "2022_2024-usa-ev6_iv" share
// "2022_2024-usa-ev6_", but neither shares more than "2022" with "2022-can-ioniq5-v011.007_iv",
// which is not a word.
func NameAffinity(a, b string) int {
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

// bestSecret picks, for the key s proved, the IV that decrypts the first block properly. Only that
// block depends on the IV in CBC, so the structure that proved the key says nothing about it, and
// with several IVs loaded the first would otherwise win whether it is right or not. The first
// block is right when it is a known format's magic, or the zeros an image of a filesystem begins
// with; of IVs that do equally well, the earlier (the better-named) stays.
func bestSecret(s Secret, blk cipher.Block, head []byte) Secret {
	if s.Mode != "" {
		return s
	}
	best, bestScore := s, -1
	for _, c := range Secrets() {
		if c.Mode != "" || !bytes.Equal(c.Key, s.Key) {
			continue
		}
		plain := c.DecryptHead(blk, head)
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

// Find returns a secrets directory beside a collection: <dir>/secrets or <dir>/../secrets.
func Find(dir string) string {
	for _, c := range []string{filepath.Join(dir, "secrets"), filepath.Join(dir, "..", "secrets")} {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return ""
}

// Reader exposes the plaintext of an AES-CBC ciphertext by range: block i decrypts from ciphertext
// blocks i-1 and i alone, so a filesystem inside a multi-GiB image can be walked without
// decrypting the rest.
type Reader struct {
	ra   io.ReaderAt
	blk  cipher.Block
	iv   []byte
	size int64
	ecb  bool  // blocks decrypt independently
	base int64 // ciphertext offset of plaintext offset 0 (16 when the IV leads)
}

// Size is the plaintext's length, without its padding.
func (c *Reader) Size() int64 { return c.size }

// padLen is the PKCS#7 pad on the final plaintext block, 0 if the block does not end in a valid
// pad.
func (c *Reader) padLen() int64 {
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

func (c *Reader) ReadAt(p []byte, off int64) (int, error) {
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
	// The block before start is the IV of CBC; the stored IV serves only the first block of a
	// stream that has none in front of it.
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

// DecryptedReaderAt returns the plaintext view of ciphertext under the first loaded secret whose
// plaintext head is a filesystem or other structure, and the name of that secret.
//
// The images are PKCS#7-padded (1–16 bytes of the pad length), so the reader's size excludes the
// pad.
func DecryptedReaderAt(ra io.ReaderAt, size int64, head []byte) (*Reader, string, bool) {
	if len(head) < 2*aes.BlockSize {
		return nil, "", false
	}
	for _, s := range Secrets() {
		blk, err := aes.NewCipher(s.Key)
		if err != nil {
			continue
		}
		if plain := s.DecryptHead(blk, head); plain != nil && Proven(plain) {
			s = bestSecret(s, blk, head)
			c := &Reader{ra: ra, blk: blk, iv: s.IV, size: size &^ (aes.BlockSize - 1), ecb: s.Mode == "ecb"}
			if s.Mode == "prefix" {
				c.base, c.size = aes.BlockSize, c.size-aes.BlockSize
			}
			c.size -= c.padLen()
			return c, s.Name, true
		}
	}
	return nil, "", false
}

// Expander lets a listing see through an AES-encrypted member (an enc_*.ext4 or enc_boot.img)
// whose plaintext head is a known format: its one child is the decrypted image, read by range,
// named without the enc_ prefix.
func Expander() carve.Expander {
	open := func(n *carve.Node, head []byte) (*carve.Node, bool) {
		if Count() == 0 || !n.RandomAccess() {
			return nil, false
		}
		ra, err := n.ReaderAt()
		if err != nil {
			return nil, false
		}
		dec, _, ok := DecryptedReaderAt(ra, n.Size, head)
		if !ok {
			return nil, false
		}
		return carve.FromReaderAt(strings.TrimPrefix(path.Base(n.Name), "enc_"), dec, dec.size), true
	}
	return carve.Expander{
		Kind: "encrypted",
		Match: func(n *carve.Node, head []byte) bool {
			if filetype.Detect(head) != filetype.Unknown || !HighEntropy(head) {
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
