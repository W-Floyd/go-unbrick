package modem

import (
	"testing"
)

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
