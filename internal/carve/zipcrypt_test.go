package carve

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"hash/crc32"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/zipcrypto"
)

func TestFilenameCandidates(t *testing.T) {
	f := &zip.File{FileHeader: zip.FileHeader{Name: "a/fbdmisha512"}}
	cands := filenameCandidates(nil, f, []string{"a/update.ini", "a/update.zip"})
	want := []string{"FBDMI", "fbdmi", "UPDATE", "update"}
	have := map[string]bool{}
	for _, c := range cands {
		have[c] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Fatalf("filenameCandidates missing %q, got %v", w, cands)
		}
	}
}

func TestFilenameCandidatesEmptyName(t *testing.T) {
	f := &zip.File{FileHeader: zip.FileHeader{Name: ""}}
	if got := filenameCandidates(nil, f, nil); len(got) != 0 {
		t.Fatalf("expected no candidates from an empty name, got %v", got)
	}
}

func TestNumericSequenceCandidates(t *testing.T) {
	cands := numericSequenceCandidates(10)
	have := map[string]bool{}
	for _, c := range cands {
		have[c] = true
	}
	for _, want := range []string{
		"0123456789", // ascending from 0, the real-world case this was added for
		"9876543210", // descending from 9
		"0000000000", // repeated digit
		"5",          // length 1
		"89012345",   // ascending wrapping through 9->0
	} {
		if !have[want] {
			t.Fatalf("numericSequenceCandidates(10) missing %q", want)
		}
	}
	for _, c := range cands {
		if len(c) > 10 {
			t.Fatalf("candidate %q longer than requested maxLen 10", c)
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				t.Fatalf("candidate %q is not all-digit", c)
			}
		}
	}
}

func TestNumericSequenceCandidatesClampsMaxLen(t *testing.T) {
	for _, c := range numericSequenceCandidates(50) {
		if len(c) > 10 {
			t.Fatalf("maxLen should clamp to 10, got length-%d candidate %q", len(c), c)
		}
	}
	// 0 and negative both mean "use the full 10", same as the real-world
	// default -- not "generate nothing".
	if len(numericSequenceCandidates(0)) == 0 {
		t.Fatal("maxLen 0 should default to 10, not produce no candidates")
	}
}

// encryptedDeflateZip builds a one-member zip: name, deflate-compressed and
// PKWARE-encrypted under password.
func encryptedDeflateZip(t *testing.T, name string, plain []byte, password string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	fw, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	crc := crc32.ChecksumIEEE(plain)
	enc := zipcrypto.Encrypt(compressed.Bytes(), []byte(password), byte(crc>>24))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name: name, Method: zip.Deflate, Flags: 0x1, CRC32: crc,
		CompressedSize64: uint64(len(enc)), UncompressedSize64: uint64(len(plain)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(enc); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func resetBruteforceVars(t *testing.T) {
	t.Helper()
	oldZP, oldCS, oldML, oldMDL, oldMDS, oldMNL, oldPF, oldSK, oldPR :=
		ZipPasswords, BruteforceCharset, BruteforceMaxLen, BruteforceMaxDeflateLen, BruteforceMaxDeflateSize, BruteforceMaxNumericLen, PasswordFound, BruteforceSkipped, BruteforceProgress
	t.Cleanup(func() {
		ZipPasswords, BruteforceCharset, BruteforceMaxLen, BruteforceMaxDeflateLen, BruteforceMaxDeflateSize, BruteforceMaxNumericLen, PasswordFound, BruteforceSkipped, BruteforceProgress =
			oldZP, oldCS, oldML, oldMDL, oldMDS, oldMNL, oldPF, oldSK, oldPR
	})
	ZipPasswords = nil
	PasswordFound = nil
	BruteforceSkipped = nil
	BruteforceProgress = nil
	BruteforceMaxNumericLen = 0
}

func TestDecryptedZipMemberFindsFilenameCandidate(t *testing.T) {
	resetBruteforceVars(t)
	plain := []byte("hello from a brute-forced deflate member")
	// "FBDMI" is exactly the first 5 characters of the member's own name,
	// upper-cased -- the real pattern this was added for.
	data := encryptedDeflateZip(t, "fbdmisha512", plain, "FBDMI")
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	BruteforceCharset = zipcrypto.DefaultBruteforceCharset
	BruteforceMaxLen = 0 // the exhaustive search alone would find nothing at length 0 -- only the filename pre-pass can succeed here
	var found string
	PasswordFound = func(_ *Node, _, pw string) { found = pw }
	n := decryptedZipMember(nil, zr.File[0], bytes.NewReader(data), []string{"fbdmisha512"})
	if n == nil {
		t.Fatal("expected the member to decrypt via its own filename truncation")
	}
	if found != "FBDMI" {
		t.Fatalf("PasswordFound got %q, want %q", found, "FBDMI")
	}
	got, err := n.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypted content = %q, want %q", got, plain)
	}
}

// TestDecryptedZipMemberFindsSequentialNumericPassword is the Neusoft-IVI
// case: password "0123456789" (10 digits) is unreachable by any exhaustive
// search bounded at a sane length (BruteforceMaxLen 6 or even
// BruteforceMaxNumericLen's own default of 10 against a deflated member,
// capped lower by BruteforceMaxDeflateLen) -- only the cheap, unconditional
// sequential-candidate guess reaches it.
func TestDecryptedZipMemberFindsSequentialNumericPassword(t *testing.T) {
	resetBruteforceVars(t)
	plain := []byte("a7kernel.pak payload, unrelated to the password")
	data := encryptedDeflateZip(t, "a7kernel.pak", plain, "0123456789")
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	BruteforceCharset = zipcrypto.DefaultBruteforceCharset
	BruteforceMaxLen = 6
	BruteforceMaxDeflateLen = 4 // realistic default: nowhere near length 10
	BruteforceMaxNumericLen = 4 // same -- the exhaustive numeric pass can't reach this either
	var found string
	PasswordFound = func(_ *Node, _, pw string) { found = pw }
	n := decryptedZipMember(nil, zr.File[0], bytes.NewReader(data), nil)
	if n == nil {
		t.Fatal("expected the sequential-digit pre-pass to find the password")
	}
	if found != "0123456789" {
		t.Fatalf("PasswordFound got %q, want %q", found, "0123456789")
	}
}

func TestDecryptedZipMemberSkipsLargeDeflate(t *testing.T) {
	resetBruteforceVars(t)
	plain := bytes.Repeat([]byte("x"), 4096)
	data := encryptedDeflateZip(t, "big.bin", plain, "zz") // short password, well within reach
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	BruteforceCharset = zipcrypto.DefaultBruteforceCharset
	BruteforceMaxLen = 2
	BruteforceMaxDeflateLen = 2
	BruteforceMaxDeflateSize = 1 // this member's ciphertext is well over 1 byte compressed
	var skippedReason string
	BruteforceSkipped = func(_ *Node, _, reason string) { skippedReason = reason }
	if n := decryptedZipMember(nil, zr.File[0], bytes.NewReader(data), nil); n != nil {
		t.Fatal("expected the size cap to block the exhaustive search entirely")
	}
	if skippedReason == "" {
		t.Fatal("expected BruteforceSkipped to fire")
	}
}

func TestDecryptedZipMemberDeflateMaxLenSeparateFromStored(t *testing.T) {
	resetBruteforceVars(t)
	plain := []byte("short")
	data := encryptedDeflateZip(t, "x.bin", plain, "ab")
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	BruteforceCharset = zipcrypto.DefaultBruteforceCharset
	BruteforceMaxLen = 6         // plenty for a stored/zip-signature member
	BruteforceMaxDeflateLen = 1  // but deflate is capped lower...
	BruteforceMaxDeflateSize = 0 // ...no size cap in play here
	if n := decryptedZipMember(nil, zr.File[0], bytes.NewReader(data), nil); n != nil {
		t.Fatal("password \"ab\" (length 2) should be out of reach at BruteforceMaxDeflateLen=1")
	}
	BruteforceMaxDeflateLen = 2
	if n := decryptedZipMember(nil, zr.File[0], bytes.NewReader(data), nil); n == nil {
		t.Fatal("password \"ab\" should be found once BruteforceMaxDeflateLen covers it")
	}
}
