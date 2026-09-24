package modem

import (
	"encoding/binary"
	"testing"
)

// go-ext4 refuses a filesystem without the flex_bg flag though it never depends
// on it. ensureFlexBg sets the flag on a copy for a non-flex_bg image (some
// Motorola partitions, e.g. dspso, are built that way) and leaves a flex_bg
// image — and its backing bytes — untouched.
func TestEnsureFlexBg(t *testing.T) {
	img := make([]byte, ext4FeatIncompatOff+4)
	binary.LittleEndian.PutUint32(img[ext4FeatIncompatOff:], 0x42) // extents|filetype, no flex_bg

	got := ensureFlexBg(img)
	if binary.LittleEndian.Uint32(got[ext4FeatIncompatOff:])&ext4FlexBG == 0 {
		t.Error("flex_bg not set on the returned image")
	}
	if binary.LittleEndian.Uint32(img[ext4FeatIncompatOff:])&ext4FlexBG != 0 {
		t.Error("the original slice must not be mutated")
	}

	// An image that already has flex_bg is returned as-is (same backing array).
	withFlag := make([]byte, ext4FeatIncompatOff+4)
	binary.LittleEndian.PutUint32(withFlag[ext4FeatIncompatOff:], 0x42|ext4FlexBG)
	if out := ensureFlexBg(withFlag); &out[0] != &withFlag[0] {
		t.Error("a flex_bg image should not be copied")
	}
}

func TestBaseband(t *testing.T) {
	// A raw ext4 buffer (magic at 1024+0x38) with an MPSS version string embedded,
	// as the modem firmware carries it.
	raw := make([]byte, 4096)
	raw[ext4MagicOff] = 0x53
	raw[ext4MagicOff+1] = 0xEF
	copy(raw[2048:], []byte("QC_IMAGE_VERSION_STRING=MPSS.HA.1.2-00035-DIVAR_GENSP_PACK-1.48024.106\x00"))
	if got := Baseband(raw); got != "MPSS.HA.1.2-00035-DIVAR_GENSP_PACK-1.48024.106" {
		t.Errorf("baseband = %q", got)
	}
	// No MPSS string → empty, not an error.
	blank := make([]byte, 2048)
	blank[ext4MagicOff] = 0x53
	blank[ext4MagicOff+1] = 0xEF
	if got := Baseband(blank); got != "" {
		t.Errorf("baseband = %q, want empty", got)
	}
}
