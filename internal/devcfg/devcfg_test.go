package devcfg

import (
	"encoding/binary"
	"os"
	"testing"
)

// These vectors were read out of a fogona devcfg, where each device entry's
// stored dwHash equalled djb2 of the name it points at.
func TestDjb2KnownVectors(t *testing.T) {
	for _, c := range []struct {
		name string
		want uint32
	}{
		{"/tz/pmic", 0xdd540b3a},
		{"/dev/i2c", 0xe194f900},
		{"/dev/buses/qupac", 0x30c3af8d},
		{"/dev/buses/qupac/15", 0x7e276ee2},
	} {
		if got := Djb2(c.name); got != c.want {
			t.Errorf("Djb2(%q) = %#x want %#x", c.name, got, c.want)
		}
	}
}

// store builds a payload with the real DAL layout: header, DALProps root,
// PropBin (head + string pool + property records), struct table, device table.
type store struct {
	base  uint64
	pool  []string
	devs  []sdev
	stabs []uint64 // struct-table sizes
}

type sdev struct {
	name  string
	props []sprop
}

type sprop struct {
	name string
	typ  PropType
	val  uint32
}

func (s *store) build(t *testing.T) []byte {
	t.Helper()
	// String pool, and each name's offset within it.
	poolOff := map[string]uint32{}
	var pool []byte
	intern := func(n string) uint32 {
		if o, ok := poolOff[n]; ok {
			return o
		}
		o := uint32(len(pool))
		poolOff[n] = o
		pool = append(pool, n...)
		pool = append(pool, 0)
		return o
	}
	for _, d := range s.devs {
		for _, p := range d.props {
			intern(p.name)
		}
	}

	// PropBin = 32-byte head + pool + per-device property records.
	propRecs := map[int][]byte{}
	body := append([]byte(nil), pool...)
	for i, d := range s.devs {
		off := propBinHeadLen + len(body)
		var rec []byte
		for _, p := range d.props {
			var r [8]byte
			binary.LittleEndian.PutUint32(r[0:], uint32(p.typ)<<24|0x800000|poolOff[p.name])
			binary.LittleEndian.PutUint32(r[4:], p.val)
			rec = append(rec, r[:]...)
		}
		propRecs[i] = rec
		body = append(body, rec...)
		_ = off
	}
	// Recompute each device's start now that the pool length is fixed.
	starts := make([]uint32, len(s.devs))
	cur := propBinHeadLen + len(pool)
	for i := range s.devs {
		starts[i] = uint32(cur)
		cur += len(propRecs[i])
	}
	propBin := make([]byte, propBinHeadLen)
	binary.LittleEndian.PutUint32(propBin[0:], uint32(propBinHeadLen+len(body))) // end of property area
	binary.LittleEndian.PutUint32(propBin[4:], propBinHeadLen)                   // string-pool offset
	propBin = append(propBin, body...)

	// Lay the segment out: [header 64][DALProps 32][PropBin][structs][devices]
	const hdrLen, rootLen = 64, 32
	propBinAt := hdrLen + rootLen
	structAt := propBinAt + len(propBin)
	structLen := len(s.stabs) * structEntryLen
	devAt := structAt + structLen
	total := devAt + len(s.devs)*stringDeviceLen + 64
	seg := make([]byte, total)

	binary.LittleEndian.PutUint32(seg, 0x9007)
	binary.LittleEndian.PutUint64(seg[8:], s.base+hdrLen) // root pointer

	binary.LittleEndian.PutUint64(seg[hdrLen+0:], s.base+uint64(propBinAt))
	binary.LittleEndian.PutUint64(seg[hdrLen+8:], s.base+uint64(structAt))
	binary.LittleEndian.PutUint32(seg[hdrLen+16:], uint32(len(s.devs)))
	binary.LittleEndian.PutUint64(seg[hdrLen+24:], s.base+uint64(devAt))

	copy(seg[propBinAt:], propBin)

	for i, sz := range s.stabs {
		o := structAt + i*structEntryLen
		binary.LittleEndian.PutUint64(seg[o:], sz)
		binary.LittleEndian.PutUint64(seg[o+8:], s.base+uint64(propBinAt)) // any valid pointer
	}

	// Device names go in the tail, after the tables.
	nameAt := devAt + len(s.devs)*stringDeviceLen
	for i, d := range s.devs {
		o := devAt + i*stringDeviceLen
		copy(seg[nameAt:], d.name)
		binary.LittleEndian.PutUint64(seg[o:], s.base+uint64(nameAt))
		binary.LittleEndian.PutUint32(seg[o+8:], Djb2(d.name))
		binary.LittleEndian.PutUint32(seg[o+12:], starts[i])
		nameAt += len(d.name) + 1
	}
	return seg
}

func fixture(t *testing.T) (*Config, []byte) {
	t.Helper()
	s := &store{
		base:  0x10003000,
		stabs: []uint64{8, 64, 20},
		devs: []sdev{
			{"/tz/pmic", []sprop{
				{"QFPROM_rail_id", TypeUint32, 12},
				{"reg_dump_list", TypeUint32Ptr, 1},
			}},
			{"/dev/i2c", []sprop{
				{"icb_voting_ver", TypeUint32, 2},
				{"i2c_device_config", TypeUint32Ptr, 0},
			}},
		},
	}
	seg := s.build(t)
	c, ok := Parse(seg, s.base)
	if !ok {
		t.Fatal("fixture did not parse")
	}
	return c, seg
}

func TestParseDecodesDevicesAndProperties(t *testing.T) {
	c, _ := fixture(t)
	if len(c.Devices) != 2 {
		t.Fatalf("got %d devices, want 2", len(c.Devices))
	}
	byName := map[string]Device{}
	for _, d := range c.Devices {
		byName[d.Name] = d
	}
	pmic, ok := byName["/tz/pmic"]
	if !ok {
		t.Fatalf("/tz/pmic missing: %+v", c.Devices)
	}
	if pmic.Hash != Djb2("/tz/pmic") {
		t.Errorf("hash: got %#x", pmic.Hash)
	}
	if len(pmic.Props) != 2 {
		t.Fatalf("got %d props, want 2: %+v", len(pmic.Props), pmic.Props)
	}
	if pmic.Props[0].Name != "QFPROM_rail_id" || pmic.Props[0].Value != 12 ||
		pmic.Props[0].Type != TypeUint32 {
		t.Errorf("first property wrong: %+v", pmic.Props[0])
	}
	// A pointer property carries the size of the struct it indexes.
	if p := pmic.Props[1]; p.Type != TypeUint32Ptr || p.Value != 1 || p.Size != 64 || !p.Resolved {
		t.Errorf("pointer property should resolve its struct size: %+v", p)
	}
}

func TestPropertyBlocksAreBounded(t *testing.T) {
	c, _ := fixture(t)
	// Each device must get only its own records; a run-on would give /tz/pmic
	// the i2c properties too.
	for _, d := range c.Devices {
		for _, p := range d.Props {
			switch d.Name {
			case "/tz/pmic":
				if p.Name == "icb_voting_ver" || p.Name == "i2c_device_config" {
					t.Errorf("/tz/pmic ran into the next device's block: %+v", d.Props)
				}
			case "/dev/i2c":
				if p.Name == "QFPROM_rail_id" {
					t.Errorf("/dev/i2c picked up the previous block: %+v", d.Props)
				}
			}
		}
	}
}

func TestNotADevCfg(t *testing.T) {
	if _, ok := Parse([]byte("nowhere near a devcfg payload"), 0x1000); ok {
		t.Error("a segment without the magic must not parse")
	}
	// A plausible header whose root pointer goes nowhere must be rejected.
	seg := make([]byte, 64)
	binary.LittleEndian.PutUint32(seg, 0x9007)
	binary.LittleEndian.PutUint64(seg[8:], 0xdeadbeef)
	if _, ok := Parse(seg, 0x10003000); ok {
		t.Error("a root pointer outside the segment must not parse")
	}
}

// Truncated or hostile input must not panic.
func TestParseTruncated(t *testing.T) {
	_, seg := fixture(t)
	for n := 0; n < len(seg); n += 7 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %d-byte input: %v", n, r)
				}
			}()
			Parse(seg[:n], 0x10003000)
		}()
	}
}

func TestCompareEquivalentAndChanged(t *testing.T) {
	a, _ := fixture(t)
	b, _ := fixture(t)
	if d := Compare(a, b); !d.Equivalent() {
		t.Errorf("identical stores should compare equivalent: %+v", d)
	}

	// Change one value.
	b.Devices[0].Props[0].Value = 99
	d := Compare(a, b)
	if d.Equivalent() {
		t.Fatal("a changed value must not compare equivalent")
	}
	if len(d.Values) != 1 {
		t.Fatalf("expected 1 change, got %+v", d.Values)
	}
	if d.Values[0].A == d.Values[0].B {
		t.Errorf("change should record both sides: %+v", d.Values[0])
	}
	if d.ComparedValues != 4 {
		t.Errorf("all four properties should be compared, got %d", d.ComparedValues)
	}
}

func TestCompareReportsMissingNames(t *testing.T) {
	a, _ := fixture(t)
	b, _ := fixture(t)
	b.Devices = b.Devices[:1]                   // drop a device
	a.Devices[0].Props = a.Devices[0].Props[:1] // drop a property
	d := Compare(a, b)
	var sawDevice, sawProp bool
	for _, n := range d.NamesOnlyA {
		if n == b.Devices[0].Name {
			continue
		}
		sawDevice = true
	}
	for _, n := range d.NamesOnlyB {
		if len(n) > 0 {
			sawProp = true
		}
	}
	if !sawDevice {
		t.Errorf("a device present only in A should be reported: %+v", d.NamesOnlyA)
	}
	if !sawProp {
		t.Errorf("a property present only in B should be reported: %+v", d.NamesOnlyB)
	}
}

func TestPropTypeNaming(t *testing.T) {
	if !TypeUint32Ptr.Pointer() || TypeUint32.Pointer() {
		t.Error("only the pointer types should report Pointer()")
	}
	if TypeUint32.String() != "uint32" || TypeStrPtr.String() != "str" {
		t.Errorf("type names: %s %s", TypeUint32, TypeStrPtr)
	}
}

// TestOEMPolicyFromSample decodes the /tz/oem secure-boot policy from a real
// devcfg.mbn. The sample is gitignored, so this skips where it is absent.
func TestOEMPolicyFromSample(t *testing.T) {
	data, err := os.ReadFile("../../samples/devcfg_a_ZLTEST0001.bin")
	if err != nil {
		t.Skip("sample devcfg not present")
	}
	stores := FromELF(data)
	if len(stores) == 0 {
		t.Fatal("no devcfg store parsed from the ELF")
	}
	var p OEMPolicy
	for _, c := range stores {
		if q := c.OEM(); q.Found {
			p = q
			break
		}
	}
	if !p.Found {
		t.Fatal("no /tz/oem node found across stores")
	}
	// Fogona retail posture: SendROT off, RPMB keystore on, MRC lists empty,
	// the OEM RSA pubkey and ROT PK-hash field both present.
	if p.ROTTransferAPPS || p.ROTTransferMODEM {
		t.Errorf("ROT transfer should be disabled: APPS=%v MODEM=%v", p.ROTTransferAPPS, p.ROTTransferMODEM)
	}
	if !p.RPMBKeystore || !p.RPMBCounter {
		t.Errorf("RPMB keystore/counter should be enabled: %+v", p)
	}
	if p.MRCActivation != 0 || p.MRCRevocation != 0 {
		t.Errorf("MRC lists should be empty: act=%d rev=%d", p.MRCActivation, p.MRCRevocation)
	}
	if !p.HasPubKey || !p.HasPKHashFuse {
		t.Errorf("OEM pubkey / PK-hash field should be present: %+v", p)
	}
}
