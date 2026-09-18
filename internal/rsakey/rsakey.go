// Package rsakey extracts the RSA public keys embedded in a boot binary, as
// Motorola's ABL (MotoBootModule.efi) carries them for diagnostic-mode,
// CID/unlock-token, and boot-chain verification. It finds keys in both forms the
// ABL uses:
//
//   - Raw modulus+exponent (the factory root key): a big-endian modulus followed
//     by a fixed little-endian exponent record — value 0x00010001 (65537) with
//     byte-length 3, i.e. 01 00 01 00 03 00 00 00 — with the modulus in the 256
//     (RSA-2048) or 512 (RSA-4096) bytes before it, validated by the top bit of
//     its most-significant byte. (Ported from extract_moto_keys.py.)
//   - X.509 certificates (e.g. the Motorola Security Engineering Root CA and the
//     DBVAL/unlock verify keys), carved by scanning for DER SEQUENCEs.
//
// Both forms reduce to a crypto/rsa.PublicKey with a canonical SPKI fingerprint,
// so a key found as a cert in one binary matches the same key found raw (or in
// another model) by fingerprint. These are PUBLIC keys — extractable and
// fingerprintable, never forgeable.
package rsakey

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
)

// knownExponents are the RSA public exponents the scan anchors on. The ABL
// stores a key's exponent as a fixed record — a little-endian value word then a
// little-endian minimal byte-length word — and we search for that exact record
// because it is precise enough to locate a key with almost no false positives.
// 65537 (F4) is the exponent every embedded key in the RE notes uses; extend this
// list (and nothing else) if a binary is found to use another. The exponent is
// then read back from the matched record, not assumed.
var knownExponents = []uint32{65537}

// exponentRecord builds the 8-byte on-disk exponent record for e: the value as a
// little-endian u32, then its minimal byte length as a little-endian u32.
func exponentRecord(e uint32) []byte {
	rec := make([]byte, 8)
	binary.LittleEndian.PutUint32(rec[0:4], e)
	n := 4
	for n > 1 && rec[n-1] == 0 {
		n--
	}
	binary.LittleEndian.PutUint32(rec[4:8], uint32(n))
	return rec
}

// sha256ASN1OID is the ASN.1 DER DigestInfo prefix for SHA-256 (RFC 8017), the
// constant the ABL's RSA-verify routine (FUN_00056010) compares a recovered EM
// against. We scan for it only to corroborate that the binary does SHA-256 RSA
// PKCS#1 v1.5 verification — it does not locate or validate keys. It is hardcoded
// because Go's crypto keeps its DigestInfo prefixes unexported.
var sha256ASN1OID = []byte{
	0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
}

// Key is one embedded RSA public key located in the binary.
type Key struct {
	ModulusOffset  int            // file offset of the big-endian modulus
	ExponentOffset int            // file offset of the exponent record
	Public         *rsa.PublicKey // the reconstructed key (E is always 65537)
	// Fingerprint is the SHA-256 of the DER SubjectPublicKeyInfo — the canonical,
	// openssl-style key fingerprint, and the identity used to match a key across
	// binaries/models.
	Fingerprint string
	// ModulusSHA256 and ModulusSHA1 are hashes of the raw big-endian modulus, the
	// form Motorola's fused root-key hash and the RE notes (FACTORY.md) use; kept
	// alongside the SPKI fingerprint for cross-referencing.
	ModulusSHA256 string
	ModulusSHA1   string
	HeaderFlags   uint32 // the u32 at modulus-4, a key-metadata flag word
}

// Bits is the modulus size in bits.
func (k Key) Bits() int { return k.Public.N.BitLen() }

// PEM encodes the key as a PKIX PEM block.
func (k Key) PEM() string { return pemPublic(k.Public) }

// pemPublic encodes an RSA public key as a PKIX PEM block, or "" on error/nil.
func pemPublic(pub *rsa.PublicKey) string {
	if pub == nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// Cert is one embedded X.509 certificate located in the binary.
type Cert struct {
	Offset      int
	Certificate *x509.Certificate
	Public      *rsa.PublicKey // nil when the cert's key is not RSA
	// Fingerprint is the SHA-256 of the key's DER SubjectPublicKeyInfo — the same
	// identity a raw Key carries, so the two match across forms and binaries.
	Fingerprint string
	Subject     string
}

// Result is a scan of one binary.
type Result struct {
	Size       int   // input length
	OIDOffsets []int // offsets of the SHA-256 ASN.1 DigestInfo prefix
	Keys       []Key // raw modulus+exponent keys
	Certs      []Cert
}

// Identity is the common currency for matching keys across binaries and models:
// a canonical fingerprint plus how it was found and the key itself.
type Identity struct {
	Fingerprint string // SPKI SHA-256 of the RSA public key
	Bits        int
	Kind        string // "raw" or "cert"
	Label       string // "raw RSA key", or the cert subject
	Offset      int
	Public      *rsa.PublicKey
}

// PEM encodes the key as a PKIX PEM block.
func (id Identity) PEM() string { return pemPublic(id.Public) }

// Identities flattens the raw keys and RSA certs into one comparable list.
func (r Result) Identities() []Identity {
	out := make([]Identity, 0, len(r.Keys)+len(r.Certs))
	for _, k := range r.Keys {
		out = append(out, Identity{
			Fingerprint: k.Fingerprint,
			Bits:        k.Bits(),
			Kind:        "raw",
			Label:       "raw RSA key",
			Offset:      k.ModulusOffset,
			Public:      k.Public,
		})
	}
	for _, c := range r.Certs {
		if c.Public == nil {
			continue
		}
		out = append(out, Identity{
			Fingerprint: c.Fingerprint,
			Bits:        c.Public.N.BitLen(),
			Kind:        "cert",
			Label:       c.Subject,
			Offset:      c.Offset,
			Public:      c.Public,
		})
	}
	return out
}

// spkiFingerprint is the SHA-256 of a key's DER SubjectPublicKeyInfo.
func spkiFingerprint(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// parseAt validates an RSA key whose exponent record sits at expOff, preferring a
// 2048-bit modulus over 4096-bit (the ABL's keys are 2048-bit; a 4096-bit root
// falls through only when the 2048 window is not a valid modulus). Returns nil if
// neither window is a plausible big-endian modulus.
func parseAt(data []byte, expOff int) *Key {
	for _, bits := range []int{2048, 4096} {
		byteLen := bits / 8
		modOff := expOff - byteLen
		if modOff < 8 {
			continue
		}
		mod := data[modOff:expOff]
		// A big-endian RSA modulus is odd and uses its full width, so the
		// most-significant byte has its top bit set.
		if mod[0] < 0x80 {
			continue
		}
		// Read the exponent back from the matched record rather than assuming it.
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(mod),
			E: int(binary.LittleEndian.Uint32(data[expOff : expOff+4])),
		}
		modSum := sha256.Sum256(mod)
		modSum1 := sha1.Sum(mod)
		k := &Key{
			ModulusOffset:  modOff,
			ExponentOffset: expOff,
			Public:         pub,
			ModulusSHA256:  hex.EncodeToString(modSum[:]),
			ModulusSHA1:    hex.EncodeToString(modSum1[:]),
			HeaderFlags:    binary.LittleEndian.Uint32(data[modOff-4 : modOff]),
			Fingerprint:    spkiFingerprint(pub),
		}
		return k
	}
	return nil
}

// Scan finds every embedded RSA public key and SHA-256 OID reference in data.
func Scan(data []byte) Result {
	res := Result{Size: len(data)}

	for pos := 0; pos < len(data); {
		i := bytes.Index(data[pos:], sha256ASN1OID)
		if i < 0 {
			break
		}
		res.OIDOffsets = append(res.OIDOffsets, pos+i)
		pos += i + len(sha256ASN1OID)
	}

	seen := map[int]bool{}
	for _, e := range knownExponents {
		rec := exponentRecord(e)
		for pos := 0; pos < len(data); {
			i := bytes.Index(data[pos:], rec)
			if i < 0 {
				break
			}
			off := pos + i
			if k := parseAt(data, off); k != nil && !seen[k.ModulusOffset] {
				seen[k.ModulusOffset] = true
				res.Keys = append(res.Keys, *k)
			}
			pos = off + 1
		}
	}

	res.Certs = scanCerts(data)
	return res
}

// scanCerts carves embedded X.509 certificates by looking for DER SEQUENCE
// headers (0x30 0x82 <u16 length>) and parsing the span. Certificates are the
// hundreds-of-bytes range, so the 2-byte-length form covers them.
func scanCerts(data []byte) []Cert {
	var out []Cert
	for i := 0; i+4 < len(data); i++ {
		if data[i] != 0x30 || data[i+1] != 0x82 {
			continue
		}
		ln := int(data[i+2])<<8 | int(data[i+3]) + 4
		if ln < 64 || i+ln > len(data) {
			continue
		}
		c, err := x509.ParseCertificate(data[i : i+ln])
		if err != nil {
			continue
		}
		cert := Cert{Offset: i, Certificate: c, Subject: c.Subject.String()}
		if pub, ok := c.PublicKey.(*rsa.PublicKey); ok {
			cert.Public = pub
			cert.Fingerprint = spkiFingerprint(pub)
		}
		out = append(out, cert)
		i += ln - 1 // advance past the parsed certificate
	}
	return out
}
