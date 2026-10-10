package lenovo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// goldenVersionT is the real TB125FU_S101018_250416_ROW/image/version.t (176 B),
// pinning the derivation and DefaultPassword against genuine LMSA firmware.
const goldenVersionT = "5329d1816d6cdf7b943702be56bac3819076a2b5d25ab5f88a00ef9a81a32dcd" +
	"df5935a1d7e100cbe5965897907f56d800d2049cd0d351108a68cbbd33c79f58" +
	"e6d7bc9331d9671614432443acfaa71c7ec29c2454d67517f6c4bc187a082358" +
	"f6af7baf948d9d68c72f39da109b3df00890f778fec9d3ad762acefc94f27a13" +
	"f1796833d6babb77d8f950326b209c89b598b7dbc039e173895b1a0b3f44b78b" +
	"1703600749bbf6824b49f775ba8cb993"

func TestGoldenVersionT(t *testing.T) {
	src, err := hex.DecodeString(goldenVersionT)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptROM(src, DefaultPassword)
	if err != nil {
		t.Fatalf("DecryptROM with DefaultPassword: %v", err)
	}
	const want = "TB125FU_S101018_250416_ROW(SW_P98980AA1_V018_M10_WIFI_LENOVO_MAPLE_USR_TEST_ROW)"
	if !strings.Contains(string(got), want) {
		t.Fatalf("decrypted version.t = %q, want it to contain %q", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	const pw = "SomeServerProvisionedPassword"
	for _, data := range [][]byte{
		nil,
		[]byte("x"),
		[]byte("<?xml version=\"1.0\"?><data/>"),
		bytes.Repeat([]byte("scatter line\n"), 5000), // spans many AES/buffer blocks
	} {
		enc, err := EncryptROM(data, pw)
		if err != nil {
			t.Fatalf("EncryptROM(%d bytes): %v", len(data), err)
		}
		if len(enc) < headerLen || (len(enc)-headerLen)%16 != 0 {
			t.Fatalf("encrypted output malformed: %d bytes", len(enc))
		}
		got, err := DecryptROM(enc, pw)
		if err != nil {
			t.Fatalf("DecryptROM(%d bytes): %v", len(data), err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(data))
		}
	}
}

func TestWrongPassword(t *testing.T) {
	enc, err := EncryptROM([]byte("scatter"), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptROM(enc, "wrong"); err != ErrWrongPassword {
		t.Fatalf("wrong password: got %v, want ErrWrongPassword", err)
	}
}

func TestCorruptData(t *testing.T) {
	enc, err := EncryptROM(bytes.Repeat([]byte("a"), 64), "pw")
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the data region (past the 32-byte header, inside the
	// framed payload) so the magic still matches but the SHA-256 fails.
	enc[headerLen+48] ^= 0xff
	if _, err := DecryptROM(enc, "pw"); err == nil {
		t.Fatal("expected SHA-256 mismatch error, got nil")
	}
}

func TestShortInput(t *testing.T) {
	if _, err := DecryptROM(make([]byte, 20), "pw"); err == nil {
		t.Fatal("expected error for truncated header")
	}
}

// TestDeriveKeyVector pins the PBKDF1 derivation so an accidental change to the
// iteration count or concatenation order is caught. The expected value is this
// package's own formula transcribed independently: SHA-256 applied 1000 times,
// innermost over UTF-8(password) || salt.
func TestDeriveKeyVector(t *testing.T) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	cur := sha256.Sum256(append([]byte("pw"), salt...))
	for i := 1; i < iterations; i++ { // 999 more, 1000 total
		cur = sha256.Sum256(cur[:])
	}
	want := hex.EncodeToString(cur[:])
	got := hex.EncodeToString(deriveKey("pw", salt))
	if got != want {
		t.Fatalf("deriveKey mismatch:\n got %s\nwant %s", got, want)
	}
}
