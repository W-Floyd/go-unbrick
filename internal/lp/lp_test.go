package lp

import (
	"encoding/binary"
	"testing"
)

func TestIsSuper(t *testing.T) {
	buf := make([]byte, reservedBytes+8)
	if IsSuper(buf) {
		t.Error("zeroed buffer should not be super")
	}
	binary.LittleEndian.PutUint32(buf[reservedBytes:], geometryMagic)
	if !IsSuper(buf) {
		t.Error("geometry magic should identify super")
	}
	if _, err := Parse(buf); err == nil {
		t.Error("Parse should fail without a metadata header")
	}
}
