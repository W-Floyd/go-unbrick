package avb

import (
	"encoding/binary"
	"testing"
)

func TestParse(t *testing.T) {
	h := make([]byte, 256)
	copy(h, "AVB0")
	be := binary.BigEndian
	be.PutUint32(h[4:], 1)    // major
	be.PutUint32(h[8:], 0)    // minor
	be.PutUint32(h[28:], 1)   // algorithm SHA256_RSA2048
	be.PutUint64(h[112:], 42) // rollback
	be.PutUint32(h[120:], 0)  // flags
	copy(h[128:], "avbtool 1.2.0\x00")

	got, err := Parse(h)
	if err != nil {
		t.Fatal(err)
	}
	if got.VersionMajor != 1 || got.Algorithm != "SHA256_RSA2048" || got.RollbackIndex != 42 || got.Release != "avbtool 1.2.0" {
		t.Errorf("parsed wrong: %+v", got)
	}
	if _, err := Parse([]byte("nope")); err == nil {
		t.Error("expected error for non-vbmeta")
	}
}
