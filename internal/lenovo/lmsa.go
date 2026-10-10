// Package lenovo decrypts the ROM files that Lenovo Motorola Smart Assistant
// (LMSA, shipped as "Software Fix") hides inside a firmware package: a flasher
// input renamed foo.t / foo.x, which LMSA decrypts to foo.txt / foo.xml (the SP
// Flash Tool scatter, the QFIL rawprogram/patch XML) in place, feeds to the
// bundled flasher, then deletes. The bundle's own flash_tool.exe never sees a
// .t because LMSA decrypts first.
//
// The scheme is the generic .NET "EncryptFile/DecryptFile" sample
// (lenovo.mbg.service.common.utilities.dll, DecryptRomFileHelper): a 16-byte IV
// and 16-byte salt header, then AES-256-CBC/PKCS7 over a framed plaintext. The
// AES key is PBKDF1 (SHA-256, 1000 iterations) from salt + a password.
//
// The password is not in the binary: LMSA fetches it at runtime from an
// authenticated endpoint (POST {service}/common/getEncryptionData.jhtml with
// body "DefaultDecryptPassword") and RSA-unwraps it. But the value it returns is
// the sample's own built-in default, "OSD" (EncryptFile's default parameter in
// the same class) — recovered by testing it against the magic header and
// confirmed end-to-end on real firmware (TB125FU_S101018_250416_ROW:
// version.t, MT6768_Android_scatter.t). So DefaultPassword works without a
// session; a caller can still pass a different one should Lenovo ever rotate it.
package lenovo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// DefaultPassword is Configurations.DefaultKey as the LMSA endpoint returns it —
// a static "OSD" across packages (see the package doc). Decryption needs no
// captured session unless this is ever rotated.
const DefaultPassword = "OSD"

// fcTag is the magic the framed plaintext carries after the length, written and
// checked as a little-endian uint64 (the decompiled code compares it as the
// signed -287946689199405361). A mismatch means the wrong password (the header
// decrypted to garbage) or a corrupt file.
const fcTag uint64 = 18158797384510146255

const (
	headerLen  = 32 // 16-byte IV followed by 16-byte salt
	iterations = 1000
	keyLen     = 32 // AES-256
)

// ErrWrongPassword is returned when the framed plaintext's magic does not match,
// which almost always means the supplied password is wrong.
var ErrWrongPassword = errors.New("lenovo: LMSA ROM magic mismatch (wrong password or corrupt file)")

// DecryptROM decrypts one LMSA ROM file (.t/.x) and returns the original file
// bytes (the .txt/.xml), after verifying the embedded SHA-256. password is
// Configurations.DefaultKey from a live LMSA session; see the package doc.
func DecryptROM(src []byte, password string) ([]byte, error) {
	if len(src) < headerLen {
		return nil, fmt.Errorf("lenovo: file is %d bytes, shorter than the %d-byte header", len(src), headerLen)
	}
	iv := src[:16]
	salt := src[16:headerLen]
	ct := src[headerLen:]
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("lenovo: ciphertext is %d bytes, not a whole number of AES blocks", len(ct))
	}

	block, err := aes.NewCipher(deriveKey(password, salt))
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)

	// Framed plaintext: int64 length, uint64 magic, length data bytes, SHA-256
	// of the data. PKCS7 padding follows and is ignored (length delimits).
	if len(pt) < 16 {
		return nil, ErrWrongPassword
	}
	n := int64(binary.LittleEndian.Uint64(pt[:8]))
	if binary.LittleEndian.Uint64(pt[8:16]) != fcTag {
		return nil, ErrWrongPassword
	}
	if n < 0 || 16+n+sha256.Size > int64(len(pt)) {
		return nil, fmt.Errorf("lenovo: framed length %d overruns the %d-byte plaintext", n, len(pt))
	}
	data := pt[16 : 16+n]
	want := pt[16+n : 16+n+sha256.Size]
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return nil, errors.New("lenovo: SHA-256 of decrypted data does not match (corrupt file)")
	}
	return bytes.Clone(data), nil
}

// EncryptROM is the inverse of DecryptROM, producing an LMSA ROM file from plain
// data. LMSA itself never consumes what this tool writes; it exists so the
// format round-trips under test and so a package could be re-wrapped if needed.
func EncryptROM(data []byte, password string) ([]byte, error) {
	iv := make([]byte, 16)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	sum := sha256.Sum256(data)
	plain := make([]byte, 0, 16+len(data)+sha256.Size)
	var hdr [16]byte
	binary.LittleEndian.PutUint64(hdr[:8], uint64(len(data)))
	binary.LittleEndian.PutUint64(hdr[8:16], fcTag)
	plain = append(plain, hdr[:]...)
	plain = append(plain, data...)
	plain = append(plain, sum[:]...)
	plain = pkcs7Pad(plain, aes.BlockSize)

	block, err := aes.NewCipher(deriveKey(password, salt))
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)

	out := make([]byte, 0, headerLen+len(ct))
	out = append(out, iv...)
	out = append(out, salt...)
	out = append(out, ct...)
	return out, nil
}

// deriveKey reproduces .NET System.Security.Cryptography.PasswordDeriveBytes
// (PBKDF1) for a key no longer than the hash, which is LMSA's case (32-byte key,
// SHA-256). The base value is SHA-256 of the UTF-8 password concatenated with
// the salt, iterated: one hash for the base, then iterations-2 more over it, so
// 999 for iterations=1000; GetBytes then emits one further hash of the base,
// making the key the 1000th SHA-256. The '1'-prefix extension PasswordDeriveBytes
// uses for output beyond one hash never triggers here (keyLen == hash size).
func deriveKey(password string, salt []byte) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write(salt)
	base := h.Sum(nil)
	for i := 1; i < iterations-1; i++ {
		s := sha256.Sum256(base)
		base = s[:]
	}
	key := sha256.Sum256(base)
	return key[:keyLen]
}

func pkcs7Pad(b []byte, block int) []byte {
	n := block - len(b)%block
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}
