package vendor

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// DecodeTarList reverses NEW_TarList.txt_encrypted's "encryption": XOR every
// byte with 0x11, per HKG_Gen5W_ReverseEngineer's README ("despite the name
// this is just a plaintext file encoded with a lame XOR cryptography").
// Not real encryption, so this round-trips.
func DecodeTarList(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ 0x11
	}
	return out
}

// hyundaiHashBlockSize/hyundaiHashBufSize must match gen5w-utils'
// sha224_gen.py exactly (SHA_BUF_SIZE = 16MiB - SHA_BLOCK_SIZE*2); changing
// the chunk size changes the result.
const (
	hyundaiHashBlockSize = 64
	hyundaiHashBufSize   = 16*1024*1024 - hyundaiHashBlockSize*2
)

// HyundaiSHA224 is Hyundai's customized two-level SHA-224, used both for
// each @FILE entry's hash in NEW_TarList.txt_encrypted and for each file's
// hash in update.info. It is NOT plain SHA-224 of the file — confirmed by
// direct comparison against this repo's own firmware package (both
// manifests), where plain SHA-224 does not match any listed hash. Per
// gen5w-utils' sha224_gen.py ("Hyundai's specialized SHA224"): SHA-224 each
// hyundaiHashBufSize chunk of the file, concatenate the digests, then
// SHA-224 the concatenation once more.
func HyundaiSHA224(r io.Reader) (string, error) {
	var first []byte
	buf := make([]byte, hyundaiHashBufSize)
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			sum := sha256.Sum224(buf[:n])
			first = append(first, sum[:]...)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	sum := sha256.Sum224(first)
	return hex.EncodeToString(sum[:]), nil
}
