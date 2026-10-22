// Package androidkeys reads Android recovery's res/keys: the public keys it trusts
// for update packages, written as C initialisers of the old mincrypt
// RSAPublicKey struct (word count, -n^-1 mod 2^32, the modulus and R^2 mod n as
// little-endian 32-bit words), one per key, with the exponent added after a key
// that does not use 65537.
package androidkeys

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/rsakey"
)

// Key is one key of a res/keys file.
type Key struct {
	Public      *rsa.PublicKey
	Bits        int
	Fingerprint string // SHA-256 of the DER SubjectPublicKeyInfo, as rsakey names keys
	// Consistent says the stored n0inv and R^2 are the ones this modulus gives: a
	// file edited by hand, or cut short, is not.
	Consistent bool
}

// keyRe is one key's initialiser. Words are written signed or unsigned.
var keyRe = regexp.MustCompile(`\{\s*(\d+)\s*,\s*(0[xX][0-9a-fA-F]+)\s*,\s*\{([-\d,\s]+)\}\s*,\s*\{([-\d,\s]+)\}\s*\}(?:\s*,\s*(\d+))?`)

// startRe is how the file begins, checked first so that ordinary text is not parsed.
var startRe = regexp.MustCompile(`^\s*\{\s*\d+\s*,\s*0[xX][0-9a-fA-F]+\s*,\s*\{\s*-?\d+\s*,`)

// Is reports whether head starts like a res/keys file.
func Is(head []byte) bool {
	return startRe.Match(head[:min(len(head), 256)])
}

// Parse reads the keys in data. ok is false when data is not a res/keys file or
// holds no key that parses.
func Parse(data []byte) (keys []Key, ok bool) {
	if !Is(data) {
		return nil, false
	}
	for _, m := range keyRe.FindAllStringSubmatch(string(data), -1) {
		if k, ok := parseKey(m); ok {
			keys = append(keys, k)
		}
	}
	return keys, len(keys) > 0
}

func parseKey(m []string) (Key, bool) {
	words, err := strconv.Atoi(m[1])
	if err != nil || words <= 0 || words > 1024 {
		return Key{}, false
	}
	n0inv, err := strconv.ParseUint(m[2][2:], 16, 32)
	if err != nil {
		return Key{}, false
	}
	n, ok := fromWords(m[3], words)
	if !ok {
		return Key{}, false
	}
	rr, rrOK := fromWords(m[4], words)
	e := 65537
	if m[5] != "" {
		if e, err = strconv.Atoi(m[5]); err != nil || e < 3 {
			return Key{}, false
		}
	}
	if n.BitLen() < 512 || n.Bit(0) == 0 { // an RSA modulus is odd, and not tiny
		return Key{}, false
	}
	pub := &rsa.PublicKey{N: n, E: e}
	// n0inv = -n^-1 mod 2^32; R^2 mod n, with R = 2^(32 words).
	two32 := new(big.Int).Lsh(big.NewInt(1), 32)
	inv := new(big.Int).ModInverse(new(big.Int).Mod(n, two32), two32)
	consistent := rrOK && inv != nil && new(big.Int).Sub(two32, inv).Uint64()&0xffffffff == n0inv
	if consistent {
		want := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(2*32*words)), n)
		consistent = rr.Cmp(want) == 0
	}
	return Key{Public: pub, Bits: n.BitLen(), Fingerprint: rsakey.Fingerprint(pub), Consistent: consistent}, true
}

// fromWords is little-endian 32-bit words, signed or not, as a number. ok is false
// unless there are exactly want of them.
func fromWords(list string, want int) (*big.Int, bool) {
	parts := strings.Split(strings.TrimSpace(list), ",")
	n := new(big.Int)
	if len(parts) != want {
		return n, false
	}
	for i, p := range parts {
		v, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
		if err != nil || v < -1<<31 || v >= 1<<32 {
			return n, false
		}
		n.Or(n, new(big.Int).Lsh(big.NewInt(v&0xffffffff), uint(32*i)))
	}
	return n, true
}

// Summary is a one-line description of keys: how many, and each one's size and
// short fingerprint.
func Summary(keys []Key) string {
	var parts []string
	for i, k := range keys {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("… %d more", len(keys)-3))
			break
		}
		parts = append(parts, fmt.Sprintf("RSA-%d sha256:%s…", k.Bits, k.Fingerprint[:12]))
	}
	noun := "keys"
	if len(keys) == 1 {
		noun = "key"
	}
	return fmt.Sprintf("%d %s: %s", len(keys), noun, strings.Join(parts, ", "))
}

// Lines describes each key in full, for a report.
func Lines(keys []Key) []string {
	var out []string
	for i, k := range keys {
		s := fmt.Sprintf("key %d: RSA-%d, e=%d, SPKI sha256 %s, modulus %x…", i+1, k.Bits, k.Public.E, k.Fingerprint, k.Public.N.Bytes()[:8])
		if !k.Consistent {
			s += " (stored n0inv or R² does not match the modulus)"
		}
		out = append(out, s)
	}
	return out
}
