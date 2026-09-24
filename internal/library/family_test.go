package library

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestOriginalNameVerifiesPrefix(t *testing.T) {
	raw := []byte("loader bytes")
	s := sha256.Sum256(raw)
	m := md5.Sum(raw)
	name := hex.EncodeToString(s[:])[:16] + "_" + hex.EncodeToString(m[:])[:16] + "_prog_emmc_firehose_8909.mbn"
	if got, ok := OriginalName(name, raw); !ok || got != "prog_emmc_firehose_8909.mbn" {
		t.Fatalf("harvest prefix: %q %v", got, ok)
	}
	// A bkerler name has the same shape but leads with a HW_ID, not a digest.
	bk := "000460e100000000_99c8c13e374c34d8_fhprg_peek.bin"
	if got, ok := OriginalName(bk, raw); ok || got != bk {
		t.Fatalf("bkerler name stripped: %q %v", got, ok)
	}
}

func TestFamilyJTAG(t *testing.T) {
	for _, c := range []struct{ cert, name, want string }{
		{"0016F0E1", "anything.mbn", "0016F0E1"},
		{"00000000", "000460e100000000_99c8c13e374c34d8_fhprg.bin", "000460E1"},
		{"", "prog_emmc_firehose_8909.mbn", "00000000"},
		// A zero HW_ID must not fall through to the cert-hash token after it.
		{"", "0000000000000000_d58522cd602a501c_fhprg.bin", "00000000"},
	} {
		if got := FamilyJTAG(c.cert, c.name); got != c.want {
			t.Errorf("FamilyJTAG(%q, %q) = %s, want %s", c.cert, c.name, got, c.want)
		}
	}
}

func TestBootImageName(t *testing.T) {
	yes := []string{"rpm.mbn", "abc_tz.mbn", "keymaster", "path/widevine.mbn", "venus.mbn", "emmc_appsboot.mbn", "cmnlib64.mbn"}
	no := []string{"prog_emmc_firehose_8909.mbn", "fhprg_peek.bin", "programmer.elf", "singleimage.bin"}
	for _, n := range yes {
		if !bootImageName(n) {
			t.Errorf("%q should be a boot image name", n)
		}
	}
	for _, n := range no {
		if bootImageName(n) {
			t.Errorf("%q should NOT be a boot image name", n)
		}
	}
}
