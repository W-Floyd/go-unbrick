package vendor

import (
	"encoding/hex"
	"testing"
)

// Synthetic get_unlock_data vectors in the layout of real fogona captures;
// target = SHA-256(salt || SHA-256(code)) with salt = UID + zero pad.
var motoUnlockVectors = []struct {
	name, wire, code string
}{
	{
		name: "sample-xt2413-2",
		wire: "0123456789ABCDEF#5A4C5445535430303031006D6F746F2067200000#E8495658209B918404261B431DC111E72E3ADA2008FE00AD547FFC704A2B861A#00C0FFEE001B80E10000000000000000",
		code: "TESTCODE00000000000A",
	},
	{
		name: "potential-usc", // mixed-case hex, as some captures print it
		wire: "FEDCBA9876543210#5A595445535430303032006D6F746F2067200000#AF54081889373E1F0BB8A4919C811660ACC7dc1E9AD531393DCBCA66A4C36864#0BADF00D001B80E10000000000000000",
		code: "TESTCODE00000000000B",
	},
}

// The Motorola driver, via the UnlockVerifier seam, accepts a real code and
// rejects a wrong one.
func TestMotorolaUnlockWire(t *testing.T) {
	for _, v := range motoUnlockVectors {
		c, err := ParseUnlock(UnlockSource{Text: v.wire})
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if c.Scheme != "moto-dbval" {
			t.Errorf("%s: scheme = %q", v.name, c.Scheme)
		}
		if !c.Verify(v.code) {
			t.Errorf("%s: correct code rejected", v.name)
		}
		if c.Verify("AAAAAAAAAAAAAAAAAAAA") {
			t.Errorf("%s: wrong code accepted", v.name)
		}
	}
}

// A raw record assembled from the same signed fields verifies identically to the
// wire path (version @2, salt @8, target @ headerBase+0x26).
func TestMotorolaUnlockRecordRoundTrip(t *testing.T) {
	v := motoUnlockVectors[0]
	mc, err := parseMotoWire(v.wire)
	if err != nil {
		t.Fatal(err)
	}
	off := motoHeaderBase(mc.version) + motoTargetRel
	blob := make([]byte, off+len(mc.target))
	blob[2] = byte(mc.version >> 8)
	blob[3] = byte(mc.version)
	copy(blob[8:24], mc.salt)
	copy(blob[off:], mc.target)

	c, err := ParseUnlock(UnlockSource{Blob: blob})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Verify(v.code) {
		t.Error("record path rejected the correct code")
	}
}

// Fields exposes serial/salt/target for `unlock show`.
func TestMotorolaUnlockFields(t *testing.T) {
	c, err := ParseUnlock(UnlockSource{Text: motoUnlockVectors[0].wire})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range c.Fields {
		got[f.Key] = f.Value
	}
	if got["version"] != "2" {
		t.Errorf("version = %q, want 2", got["version"])
	}
	if got["serial"] != "ZLTEST0001" {
		t.Errorf("serial = %q, want ZLTEST0001", got["serial"])
	}
	if _, err := hex.DecodeString(got["target"]); err != nil || len(got["target"]) != 64 {
		t.Errorf("target = %q, want 32-byte hex", got["target"])
	}
}
