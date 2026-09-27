package payload

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"testing"
)

// TestDecodeXZFilterChains round-trips data through the xz CLI with each BCJ
// filter; the go toolchain binary supplies real branch instructions.
func TestDecodeXZFilterChains(t *testing.T) {
	xzBin, err := exec.LookPath("xz")
	if err != nil {
		t.Skip("xz CLI not installed")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	// Odd length and junk tail exercise the filters' partial-instruction edges.
	in := append(code[:min(len(code), 3<<20)], make([]byte, 7)...)
	rand.New(rand.NewSource(1)).Read(in[len(in)-7:])

	for _, args := range [][]string{
		{"--x86", "--lzma2"},
		{"--arm", "--lzma2"},
		{"--armthumb", "--lzma2"},
		{"--arm64", "--lzma2"},
		{"--arm64=start=4096", "--lzma2"},
		{"--x86", "--lzma2", "--block-size=65536", "--check=sha256"},
		{"--arm", "--lzma2", "--check=crc32"},
	} {
		cmd := exec.Command(xzBin, append([]string{"-c", "-T1", "--format=xz"}, args...)...)
		cmd.Stdin = bytes.NewReader(in)
		enc, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		rc, err := newXZReader(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !bytes.Equal(got, in) {
			t.Errorf("%v: round-trip mismatch (%d vs %d bytes)", args, len(got), len(in))
		}
	}
}
