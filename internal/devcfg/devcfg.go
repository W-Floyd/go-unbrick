// Package devcfg decodes the Qualcomm device-configuration blob carried in
// devcfg.mbn, so two builds can be compared by meaning instead of by bytes.
//
// The layout is Qualcomm's DAL property store. Public headers (DALSys.h,
// DALSysTypes.h) name the structures and the images match them field for field:
//
//	struct DALProps {                  // root table, reached from the header
//	    const byte *pDALPROP_PropBin;  // property records + their string pool
//	    const void **pDALPROP_StructPtrs;
//	    uint32 dwDeviceSize;           // number of devices
//	    const StringDevice *pDevices;
//	};
//	struct StringDevice {              // 40 bytes on 64-bit
//	    const char *pszName;
//	    uint32 dwHash;                 // djb2 of pszName: h = h*33 + c, seed 5381
//	    uint32 dwOffset;               // into PropBin, NOT into the segment
//	    DALREG_DriverInfo *pFunctionName;
//	    uint32 dwNumCollision;
//	    uint32 *pdwCollisions;
//	};
//
// dwHash and dwOffset share one 64-bit word, so a device entry reads as a packed
// "(offset << 32) | djb2(name)". The hash is stable across builds; dwOffset
// moves, which re-sorts the table and is why a byte diff of two devcfgs looks
// enormous when nothing has changed.
//
// PropBin opens with eight uint32s: [0] is the distance to the end of the
// property area, [1] the offset of the string pool (32 in every image seen).
// A device's properties are 8-byte records at PropBin+dwOffset, running to the
// next device's block: a uint32 of (type << 24) | flags | name-offset, then a
// uint32 value, where the name-offset is relative to the string pool. UINT32
// holds its value inline; the pointer types hold an index into StructPtrs,
// itself 16-byte {size, pointer} records -- size first, the other order makes
// the extents appear to overlap.
//
// One trap worth naming: resolving dwOffset against the segment base rather
// than PropBin lands in the struct-pointer area and produces convincing
// nonsense -- plausibly-sized records tiling contiguously over bytes that
// measure as random. Decoded names are the check; if they are not real
// identifiers, the base is wrong.
//
// The struct area holds, in every device, exactly three 4096-byte values. Those
// pages are not device data: fleet-wide they take only eight distinct values
// drawn from a shared pool, chosen by SoC family, one of them common to every
// device, and some devices carry the same page twice. They are incompressible
// and uniform, and remain unidentified.
package devcfg

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// DALSYS_PROP_TYPE_* from DALSys.h.
type PropType uint8

const (
	TypeUint32    PropType = 0x02
	TypeStrPtr    PropType = 0x10
	TypeBytePtr   PropType = 0x11
	TypeUint32Ptr PropType = 0x12
)

func (t PropType) String() string {
	switch t {
	case TypeUint32:
		return "uint32"
	case TypeStrPtr:
		return "str"
	case TypeBytePtr:
		return "bytes"
	case TypeUint32Ptr:
		return "uint32[]"
	}
	return "type" + itoa(int(t))
}

// Pointer reports whether the value is an index into the struct table rather
// than an inline literal.
func (t PropType) Pointer() bool { return t == TypeStrPtr || t == TypeBytePtr || t == TypeUint32Ptr }

// Property is one decoded name/value pair on a device.
type Property struct {
	Name  string
	Type  PropType
	Value uint32 // inline literal, or a reference for the pointer types
	// Size is the length of the referenced struct, valid only when Resolved.
	Size uint32
	// Resolved reports that Value indexed the struct table. UINT32_PTR values
	// do; BYTE_PTR and STR_PTR values are routinely far larger than the table
	// (984 where 55 entries exist) and are not struct indices. What they do
	// address is not established -- they are not offsets into the string pool,
	// PropBin, or the segment, so those values are reported raw.
	Resolved bool
}

// Device is one configuration node, e.g. "/tz/pmic" or "keymaster64".
type Device struct {
	Name  string
	Hash  uint32 // djb2(Name), as stored
	Props []Property
}

// Config is a decoded device-configuration payload.
type Config struct {
	Ver     uint32 // format version word; varies by SoC generation
	Devices []Device
	// Structs holds the bytes each struct-table entry points at, in index
	// order. A pointer property's value is an index here, and that index shifts
	// when the table is laid out differently, so comparing two configs means
	// comparing these contents rather than the indices.
	Structs [][]byte
}

// Djb2 is the hash the device table is keyed on: seed 5381, h = h*33 + c.
func Djb2(s string) uint32 {
	h := uint32(5381)
	for i := 0; i < len(s); i++ {
		h = h*33 + uint32(s[i])
	}
	return h
}

// The first word of the payload is a format version, not a fixed magic: across
// 56 Motorola devices it falls in three families tracking SoC generation --
// 0x60xx, 0x90xx, 0xa0xx -- with at least 18 distinct values. Detection is
// therefore structural: a non-zero version word and a root pointer that
// resolves into the segment.
func Is(seg []byte, base uint64) bool {
	return len(seg) >= 16 &&
		binary.LittleEndian.Uint32(seg) != 0 &&
		deref(seg, base, binary.LittleEndian.Uint64(seg[8:])) > 0
}

const (
	stringDeviceLen = 40 // sizeof(StringDevice) on 64-bit
	structEntryLen  = 16 // {uint64 size, uint64 pointer}
	propRecordLen   = 8  // {uint32 type|nameOffset, uint32 value}
	propBinHeadLen  = 32 // eight uint32s before the string pool
)

// Parse decodes a payload. base is the segment's load address, which the
// in-image pointers are relative to.
func Parse(seg []byte, base uint64) (*Config, bool) {
	if !Is(seg, base) {
		return nil, false
	}
	root := deref(seg, base, binary.LittleEndian.Uint64(seg[8:]))
	if root < 0 || root+32 > len(seg) {
		return nil, false
	}
	propBin := deref(seg, base, binary.LittleEndian.Uint64(seg[root:]))
	structPtrs := deref(seg, base, binary.LittleEndian.Uint64(seg[root+8:]))
	nDev := int(binary.LittleEndian.Uint32(seg[root+16:]))
	devs := deref(seg, base, binary.LittleEndian.Uint64(seg[root+24:]))
	if propBin < 0 || devs < 0 || nDev <= 0 || nDev > 4096 {
		return nil, false
	}
	if propBin+propBinHeadLen > len(seg) || devs+nDev*stringDeviceLen > len(seg) {
		return nil, false
	}

	// PropBin head: [0] end of the property area, [1] string-pool offset.
	propEnd := propBin + int(binary.LittleEndian.Uint32(seg[propBin:]))
	pool := propBin + int(binary.LittleEndian.Uint32(seg[propBin+4:]))
	if pool < propBin || pool > len(seg) || propEnd > len(seg) || propEnd <= propBin {
		return nil, false
	}

	c := &Config{Ver: binary.LittleEndian.Uint32(seg)}
	c.Structs = structTable(seg, base, structPtrs)

	// Device entries carry a start offset each; a block runs to the next start,
	// so they must be read in offset order regardless of table order.
	type devRef struct {
		name string
		hash uint32
		off  int
	}
	refs := make([]devRef, 0, nDev)
	for i := 0; i < nDev; i++ {
		o := devs + i*stringDeviceLen
		np := deref(seg, base, binary.LittleEndian.Uint64(seg[o:]))
		name, ok := cstring(seg, np)
		if !ok {
			continue
		}
		refs = append(refs, devRef{
			name: name,
			hash: binary.LittleEndian.Uint32(seg[o+8:]),
			off:  int(binary.LittleEndian.Uint32(seg[o+12:])),
		})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].off < refs[j].off })

	for i, r := range refs {
		end := propEnd
		if i+1 < len(refs) {
			end = propBin + refs[i+1].off
		}
		d := Device{Name: r.name, Hash: r.hash}
		d.Props = properties(seg, propBin+r.off, end, pool, c.Structs)
		c.Devices = append(c.Devices, d)
	}
	sort.Slice(c.Devices, func(i, j int) bool { return c.Devices[i].Name < c.Devices[j].Name })
	return c, true
}

// properties decodes the 8-byte records of one device's block.
func properties(seg []byte, start, end, pool int, structs [][]byte) []Property {
	if start < 0 || end > len(seg) || start >= end {
		return nil
	}
	var out []Property
	for o := start; o+propRecordLen <= end; o += propRecordLen {
		head := binary.LittleEndian.Uint32(seg[o:])
		val := binary.LittleEndian.Uint32(seg[o+4:])
		t := PropType(head >> 24)
		name, ok := cstring(seg, pool+int(head&0xffff))
		if !ok {
			continue
		}
		p := Property{Name: name, Type: t, Value: val}
		if t.Pointer() && int(val) < len(structs) {
			p.Size, p.Resolved = uint32(len(structs[val])), true
		}
		out = append(out, p)
	}
	return out
}

// structTable reads the {size, pointer} entries the pointer types index into,
// returning the bytes each one covers.
func structTable(seg []byte, base uint64, off int) [][]byte {
	if off < 0 {
		return nil
	}
	var out [][]byte
	// The pointer is what terminates the table: the first entry whose pointer
	// does not resolve into the segment is past the end. A size running past
	// the segment is clamped rather than ending the scan, so one bad entry does
	// not hide the rest.
	for o := off; o+structEntryLen <= len(seg); o += structEntryLen {
		size := binary.LittleEndian.Uint64(seg[o:])
		p := deref(seg, base, binary.LittleEndian.Uint64(seg[o+8:]))
		if p < 0 {
			break
		}
		end := p + int(size)
		if size > uint64(len(seg)) || end > len(seg) || end < p {
			end = len(seg)
		}
		out = append(out, seg[p:end])
	}
	return out
}

func deref(seg []byte, base, p uint64) int {
	if p < base || p >= base+uint64(len(seg)) {
		return -1
	}
	return int(p - base)
}

func cstring(seg []byte, off int) (string, bool) {
	if off < 0 || off >= len(seg) {
		return "", false
	}
	n := bytes.IndexByte(seg[off:], 0)
	if n <= 0 || n > 128 {
		return "", false
	}
	s := seg[off : off+n]
	for _, ch := range s {
		if ch < 0x20 || ch > 0x7e {
			return "", false
		}
	}
	return string(s), true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
