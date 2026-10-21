package vendor

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/rsakey"
)

// cArray is a byte slice as a C initialiser, the way the driver writes its key.
func cArray(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("0x%02x", x)
	}
	return strings.Join(parts, ",")
}

func TestParseUpdateVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	src := fmt.Sprintf(`#include <u-boot/sha256.h>
#define UPDATE_SIGNATURE_FILE_NAME "update.sig"
#define SIG_FILE_SIZE		256
static void f(void){ sha256_starts(ctx); _encode_digest_pkcs1_5(&d);
	const int _rsa_bits = 2048;
	const uint8_t _e[]={0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01};
	const uint8_t _modulus[]={%s};
	const uint8_t _rr[]={0x0f};
}`, cArray(key.N.Bytes()))
	v, ok := ParseUpdateVerify([]byte(src))
	if !ok {
		t.Fatal("not parsed")
	}
	if v.SigFile != "update.sig" || v.SigSize != 256 || v.Hash != "SHA-256" || v.Padding != "PKCS#1 v1.5" || v.Bits != 2048 || v.Exponent != 65537 {
		t.Errorf("%+v", v)
	}
	if want := rsakey.Fingerprint(&key.PublicKey); v.Fingerprint != want {
		t.Errorf("fingerprint %q want %q", v.Fingerprint, want)
	}
	if got := v.Describe(); got != "USB update: SHA-256 over the update file, RSA-2048 PKCS#1 v1.5 signature in update.sig (256 bytes), exponent 65537" {
		t.Errorf("describe %q", got)
	}
}

func TestParseUpdateVerifyRejects(t *testing.T) {
	if _, ok := ParseUpdateVerify([]byte("int main(void){return 0;}")); ok {
		t.Error("parsed a file with no key")
	}
	// A modulus that is not the declared size is not fingerprinted.
	v, _ := ParseUpdateVerify([]byte("const int _rsa_bits = 2048;\nconst uint8_t _e[]={0x01,0x00,0x01};\nconst uint8_t _modulus[]={0xb8,0x28};\nsha256_starts"))
	if v.Fingerprint != "" {
		t.Errorf("short modulus fingerprinted: %+v", v)
	}
}
