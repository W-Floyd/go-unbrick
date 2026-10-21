package vendor

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/rsakey"
)

// Facts of Mobis's update-image verification, read from the driver source
// (u-boot/drivers/mobis/verify_update_image.c) a source release ships.
var (
	// SourceUpdateVerify is the scheme: what is hashed, the signature algorithm and
	// where the signature is read from.
	SourceUpdateVerify = facts.Key[string]("source_update_verify")
	// SourceUpdateKey is the public key the driver embeds, as the SPKI SHA-256
	// fingerprint rsakey.Scan reports, so it can be matched against keys found in
	// firmware.
	SourceUpdateKey = facts.Key[string]("source_update_key")
)

var (
	verifySigFile = regexp.MustCompile(`#define\s+UPDATE_SIGNATURE_FILE_NAME\s+"([^"]+)"`)
	verifySigSize = regexp.MustCompile(`#define\s+SIG_FILE_SIZE\s+(\d+)`)
	verifyBits    = regexp.MustCompile(`_rsa_bits\s*=\s*(\d+)`)
	verifyExp     = regexp.MustCompile(`(?s)_e\s*\[\s*\]\s*=\s*\{(.*?)\}`)
	verifyMod     = regexp.MustCompile(`(?s)_modulus\s*\[\s*\]\s*=\s*\{(.*?)\}`)
	hexByte       = regexp.MustCompile(`0[xX]([0-9a-fA-F]{1,2})`)
)

// UpdateVerify is an update-image verification driver's scheme.
type UpdateVerify struct {
	SigFile     string // the signature file read beside the update
	SigSize     int    // its length, bytes
	Hash        string
	Padding     string
	Bits        int
	Exponent    uint64
	Fingerprint string // SPKI SHA-256 of the embedded key; "" if it is not a well-formed key
}

// hexBytes reads the bytes of a C array initialiser written as 0xNN literals.
func hexBytes(s string) []byte {
	var out []byte
	for _, m := range hexByte.FindAllStringSubmatch(s, -1) {
		v, _ := strconv.ParseUint(m[1], 16, 8)
		out = append(out, byte(v))
	}
	return out
}

// ParseUpdateVerify reads a verify_update_image.c. ok is false if it does not
// embed an RSA public key and check a signature over a hash.
func ParseUpdateVerify(src []byte) (UpdateVerify, bool) {
	var v UpdateVerify
	s := string(src)
	mod := verifyMod.FindStringSubmatch(s)
	exp := verifyExp.FindStringSubmatch(s)
	if mod == nil || exp == nil {
		return v, false
	}
	if m := verifySigFile.FindStringSubmatch(s); m != nil {
		v.SigFile = m[1]
	}
	if m := verifySigSize.FindStringSubmatch(s); m != nil {
		v.SigSize, _ = strconv.Atoi(m[1])
	}
	if m := verifyBits.FindStringSubmatch(s); m != nil {
		v.Bits, _ = strconv.Atoi(m[1])
	}
	switch {
	case strings.Contains(s, "sha256_starts"):
		v.Hash = "SHA-256"
	case strings.Contains(s, "sha1_starts"):
		v.Hash = "SHA-1"
	}
	if strings.Contains(strings.ToLower(s), "pkcs1_5") {
		v.Padding = "PKCS#1 v1.5"
	}
	for _, b := range hexBytes(exp[1]) {
		v.Exponent = v.Exponent<<8 | uint64(b)
	}
	modulus := hexBytes(mod[1])
	// Only a modulus that is the declared size, with its top bit set, is a key
	// worth fingerprinting; anything else is a parse of something else.
	if v.Bits > 0 && len(modulus)*8 == v.Bits && modulus[0]&0x80 != 0 && v.Exponent > 1 && v.Exponent < 1<<31 {
		v.Fingerprint = rsakey.Fingerprint(&rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(v.Exponent)})
	}
	return v, v.Hash != "" || v.Fingerprint != ""
}

// Describe is the scheme in a line.
func (v UpdateVerify) Describe() string {
	out := "USB update"
	if v.Hash != "" {
		out += ": " + v.Hash + " over the update file"
	}
	sig := "RSA"
	if v.Bits > 0 {
		sig = fmt.Sprintf("RSA-%d", v.Bits)
	}
	if v.Padding != "" {
		sig += " " + v.Padding
	}
	out += ", " + sig + " signature"
	if v.SigFile != "" {
		out += " in " + v.SigFile
		if v.SigSize > 0 {
			out += fmt.Sprintf(" (%d bytes)", v.SigSize)
		}
	}
	if v.Exponent != 0 {
		out += fmt.Sprintf(", exponent %d", v.Exponent)
	}
	return out
}

// learnUpdateVerify reads each verification driver a source release ships.
func learnUpdateVerify(pkg PackageAccess, bag *facts.Bag) {
	var drivers []string
	for n := range pkg.Names {
		if strings.HasSuffix(n, "/drivers/mobis/verify_update_image.c") {
			drivers = append(drivers, n)
		}
	}
	sort.Strings(drivers)
	for _, n := range drivers {
		v, ok := ParseUpdateVerify(pkg.Read(n))
		if !ok {
			continue
		}
		prov := facts.Provenance{Source: n, Authority: facts.Attested}
		facts.Set(bag, SourceUpdateVerify, v.Describe(), prov)
		if v.Fingerprint != "" {
			facts.Set(bag, SourceUpdateKey, v.Fingerprint, prov)
		}
		return
	}
}
