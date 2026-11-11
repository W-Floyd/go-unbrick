package zipcrypto

import (
	"bytes"
	"io"
	"testing"
)

func TestBruteforce(t *testing.T) {
	plain := []byte("hello, this is the plaintext of a brute-forced member")
	const check = 0x9a
	for _, tc := range []struct {
		name    string
		pw      string
		maxLen  int
		charset string
		wantOK  bool
	}{
		{"found, default charset", "fb9", 3, "", true},
		{"found, custom charset", "7Q", 3, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", true},
		{"too short a max length", "abc", 2, "", false},
		{"not in the charset", "FB9", 3, "0123456789", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := Encrypt(plain, []byte(tc.pw), check)
			verify := func(r *ReaderAt) bool {
				got := make([]byte, r.Size())
				n, err := r.ReadAt(got, 0)
				return err == nil && n == len(got) && bytes.Equal(got, plain)
			}
			pw, ok := Bruteforce(bytes.NewReader(ct), int64(len(plain)), []byte{check}, verify, BruteforceOptions{Charset: tc.charset, MaxLen: tc.maxLen})
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && pw != tc.pw {
				t.Fatalf("password = %q, want %q", pw, tc.pw)
			}
		})
	}
}

// TestBruteforceWrongChecksNeverMatch makes sure a verify that is never
// satisfied (as a deflate member's full-decompress check would be, against
// data that isn't actually deflate) can't produce a false positive just
// because some candidate's header check byte happens to agree.
func TestBruteforceWrongChecksNeverMatch(t *testing.T) {
	plain := []byte("some plaintext")
	ct := Encrypt(plain, []byte("fb"), 0x11)
	verify := func(r *ReaderAt) bool { return false }
	_, ok := Bruteforce(bytes.NewReader(ct), int64(len(plain)), []byte{0x11}, verify, BruteforceOptions{MaxLen: 2})
	if ok {
		t.Fatal("expected no match when verify never passes")
	}
}

// TestBruteforceProgress checks Progress fires once per length, in order,
// up through the length the match is found at (not beyond).
func TestBruteforceProgress(t *testing.T) {
	plain := []byte("plaintext")
	const check = 0x42
	ct := Encrypt(plain, []byte("abc"), check)
	verify := func(r *ReaderAt) bool {
		got := make([]byte, r.Size())
		n, err := r.ReadAt(got, 0)
		return err == nil && n == len(got) && bytes.Equal(got, plain)
	}
	var seen []int
	_, ok := Bruteforce(bytes.NewReader(ct), int64(len(plain)), []byte{check}, verify, BruteforceOptions{
		MaxLen:   5,
		Progress: func(length int) { seen = append(seen, length) },
	})
	if !ok {
		t.Fatal("expected a match")
	}
	want := []int{1, 2, 3}
	if len(seen) != len(want) {
		t.Fatalf("Progress calls = %v, want %v", seen, want)
	}
	for i, l := range want {
		if seen[i] != l {
			t.Fatalf("Progress calls = %v, want %v", seen, want)
		}
	}
}

var _ io.ReaderAt = (*bytes.Reader)(nil)
