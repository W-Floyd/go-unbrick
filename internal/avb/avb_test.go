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

func TestParseImageDescriptors(t *testing.T) {
	be := binary.BigEndian
	u64 := func(v uint64) []byte { b := make([]byte, 8); be.PutUint64(b, v); return b }

	// One property descriptor: com.android.build.system.os_version = 14.
	key := "com.android.build.system.os_version"
	val := "14"
	var prop []byte
	prop = append(prop, u64(uint64(len(key)))...) // key_num_bytes
	prop = append(prop, u64(uint64(len(val)))...) // value_num_bytes
	prop = append(prop, key...)
	prop = append(prop, 0)
	prop = append(prop, val...)
	prop = append(prop, 0)
	desc := append(append(u64(0), u64(uint64(len(prop)))...), prop...) // tag=0 property

	// One chain descriptor for "vbmeta_system" with a 4-byte "key".
	name := "vbmeta_system"
	ck := []byte("KEYX")
	chainBody := make([]byte, 76)
	be.PutUint32(chainBody[0:], 2) // rollback_index_location
	be.PutUint32(chainBody[4:], uint32(len(name)))
	be.PutUint32(chainBody[8:], uint32(len(ck)))
	chainBody = append(chainBody, name...)
	chainBody = append(chainBody, ck...)
	desc = append(desc, append(append(u64(4), u64(uint64(len(chainBody)))...), chainBody...)...)

	pub := []byte("PUBLICKEYBYTES")
	aux := append(append([]byte(nil), desc...), pub...)

	h := make([]byte, 256)
	copy(h, "AVB0")
	be.PutUint32(h[4:], 1)
	be.PutUint32(h[28:], 1)
	be.PutUint64(h[20:], uint64(len(aux)))   // aux block size
	be.PutUint64(h[64:], uint64(len(desc)))  // public_key_offset (after descriptors)
	be.PutUint64(h[72:], uint64(len(pub)))   // public_key_size
	be.PutUint64(h[96:], 0)                  // descriptors_offset
	be.PutUint64(h[104:], uint64(len(desc))) // descriptors_size
	be.PutUint64(h[112:], 29)                // rollback index
	img := append(h, aux...)

	got, err := ParseImage(img)
	if err != nil {
		t.Fatal(err)
	}
	if got.RollbackIndex != 29 {
		t.Errorf("rollback = %d", got.RollbackIndex)
	}
	if got.PublicKeySHA256 == "" {
		t.Error("pubkey hash not computed")
	}
	var sawProp, sawChain bool
	for _, d := range got.Descriptors {
		if d.Kind == "property" && d.Key == key && d.Value == "14" {
			sawProp = true
		}
		if d.Kind == "chain" && d.Partition == "vbmeta_system" && d.ChainRollbackLoc == 2 && d.ChainKeySHA256 != "" {
			sawChain = true
		}
	}
	if !sawProp || !sawChain {
		t.Errorf("descriptors parsed wrong: %+v", got.Descriptors)
	}
}
