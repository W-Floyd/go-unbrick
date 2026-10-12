// Package arsc reads Android's compiled resource table (resources.arsc): the
// named values an APK or overlay defines, per configuration. It reads what a
// device's behaviour is configured by (strings, dimensions, ints, booleans,
// references, and arrays of them), not layouts or drawables, which are files
// the table only points at.
package arsc

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"unicode/utf16"
)

const (
	chunkStringPool = 0x0001
	chunkTable      = 0x0002
	chunkPackage    = 0x0200
	chunkType       = 0x0201

	poolUTF8 = 1 << 8

	entryComplex = 0x0001
	entryCompact = 0x0008
	typeSparse   = 0x01
	typeOffset16 = 0x02 // 16-bit entry offsets, in 4-byte units
	noEntry      = 0xFFFFFFFF
	noEntry16    = 0xFFFF
)

// Kind is a value's data type.
type Kind uint8

const (
	Null      Kind = 0x00
	Reference Kind = 0x01
	Attribute Kind = 0x02
	Str       Kind = 0x03
	Float     Kind = 0x04
	Dimension Kind = 0x05
	Fraction  Kind = 0x06
	Int       Kind = 0x10
	Hex       Kind = 0x11
	Bool      Kind = 0x12
)

// Value is one resource value under one configuration.
type Value struct {
	Kind Kind
	Str  string // Str kind
	Data uint32 // raw data word, for every other kind
	// Config is empty for the default configuration, else the raw
	// configuration bytes in hex (mcc/mnc, locale, density, ...).
	Config string
}

// Entry is one named resource: a single value per configuration, or for an
// array/plurals/style the items of its map.
type Entry struct {
	ID    uint32 // 0xPPTTEEEE
	Type  string // "string", "dimen", "array", ...
	Name  string
	Items []Value // a map entry's items, under the default configuration
	// Values holds one entry per configuration that defines a simple value.
	Values []Value
}

// Table is a parsed resource table.
type Table struct {
	Package string
	ID      uint8
	Entries []*Entry
}

// OpenAPK reads the table out of an APK held in memory.
func OpenAPK(apk []byte) (*Table, error) {
	zr, err := zip.NewReader(bytes.NewReader(apk), int64(len(apk)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name != "resources.arsc" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		return Parse(b)
	}
	return nil, fmt.Errorf("arsc: no resources.arsc in the APK")
}

// Lookup returns the named resource ("dimen", "rounded_corner_radius"), or nil.
func (t *Table) Lookup(typ, name string) *Entry {
	for _, e := range t.Entries {
		if e.Type == typ && e.Name == name {
			return e
		}
	}
	return nil
}

// Default is the entry's value under the default configuration, if it has one.
func (e *Entry) Default() (Value, bool) {
	for _, v := range e.Values {
		if v.Config == "" {
			return v, true
		}
	}
	return Value{}, false
}

// Dimension reads a dimension value as a number and its unit ("px", "dp", "sp",
// "pt", "in", "mm").
func (v Value) Dimension() (float64, string, bool) {
	if v.Kind != Dimension {
		return 0, "", false
	}
	mult := [4]float64{1.0 / (1 << 8), 1.0 / (1 << 15), 1.0 / (1 << 23), 1.0 / (1 << 31)}
	n := float64(int32(v.Data&0xffffff00)) * mult[(v.Data>>4)&3]
	units := [6]string{"px", "dp", "sp", "pt", "in", "mm"}
	u := v.Data & 0xf
	if int(u) >= len(units) {
		return n, "", false
	}
	return n, units[u], true
}

// Float32 reads a float value.
func (v Value) Float32() (float32, bool) {
	if v.Kind != Float {
		return 0, false
	}
	return math.Float32frombits(v.Data), true
}

// Parse reads a resource table. Only the first package is read; an overlay or
// app has one, and the framework table's others are not needed here.
func Parse(b []byte) (*Table, error) {
	typ, hdr, size, err := chunkAt(b, 0)
	if err != nil || typ != chunkTable {
		return nil, fmt.Errorf("arsc: not a resource table")
	}
	end := min(size, len(b))
	var global *pool
	t := &Table{}
	for off := hdr; off < end; {
		ct, ch, cs, err := chunkAt(b, off)
		if err != nil {
			return nil, err
		}
		chunk := b[off:min(off+cs, end)]
		switch ct {
		case chunkStringPool:
			if global == nil {
				if global, err = parsePool(chunk); err != nil {
					return nil, err
				}
			}
		case chunkPackage:
			if t.Package == "" {
				if err := parsePackage(t, chunk, ch, global); err != nil {
					return nil, err
				}
			}
		}
		off += cs
	}
	return t, nil
}

func parsePackage(t *Table, b []byte, hdr int, global *pool) error {
	le := binary.LittleEndian
	if hdr < 288 {
		return fmt.Errorf("arsc: short package header")
	}
	t.ID = uint8(le.Uint32(b[8:]))
	name := make([]uint16, 0, 128)
	for i := 0; i < 128; i++ {
		c := le.Uint16(b[12+2*i:])
		if c == 0 {
			break
		}
		name = append(name, c)
	}
	t.Package = string(utf16.Decode(name))
	if t.Package == "" {
		t.Package = "?"
	}
	typeOff, keyOff := int(le.Uint32(b[268:])), int(le.Uint32(b[276:]))
	if typeOff <= 0 || keyOff <= 0 || typeOff >= len(b) || keyOff >= len(b) {
		return fmt.Errorf("arsc: package string pools out of range")
	}
	types, err := parsePool(b[typeOff:])
	if err != nil {
		return err
	}
	keys, err := parsePool(b[keyOff:])
	if err != nil {
		return err
	}

	byID := map[uint32]*Entry{}
	for off := hdr; off+8 <= len(b); {
		ct, ch, cs, err := chunkAt(b, off)
		if err != nil {
			return err
		}
		if ct == chunkType {
			if err := parseType(t, byID, b[off:min(off+cs, len(b))], ch, types, keys, global); err != nil {
				return err
			}
		}
		off += cs
	}
	return nil
}

func parseType(t *Table, byID map[uint32]*Entry, b []byte, hdr int, types, keys, global *pool) error {
	le := binary.LittleEndian
	if hdr < 20 {
		return fmt.Errorf("arsc: short type header")
	}
	typeID := uint32(b[8])
	flags := b[9]
	count := int(le.Uint32(b[12:]))
	start := int(le.Uint32(b[16:]))
	cfgSize := int(le.Uint32(b[20:]))
	config := ""
	if cfgSize > 4 && 20+cfgSize <= len(b) {
		for _, c := range b[24 : 20+cfgSize] {
			if c != 0 {
				config = fmt.Sprintf("%x", b[24:20+cfgSize])
				break
			}
		}
	}
	typeName := types.str(int(typeID) - 1)

	read := func(idx int, off uint32) error {
		pos := start + int(off)
		if pos+8 > len(b) {
			return fmt.Errorf("arsc: entry past the type chunk")
		}
		esize, eflags := int(le.Uint16(b[pos:])), le.Uint16(b[pos+2:])
		id := uint32(t.ID)<<24 | typeID<<16 | uint32(idx)
		e := byID[id]
		if e == nil {
			e = &Entry{ID: id, Type: typeName}
			byID[id] = e
			t.Entries = append(t.Entries, e)
		}
		if eflags&entryCompact != 0 {
			// A compact entry packs a simple value into the 8-byte header:
			// the size field is the key index, the high byte of flags the data
			// type, and the word after it the data.
			e.Name = keys.str(esize)
			v := Value{Kind: Kind(eflags >> 8), Data: le.Uint32(b[pos+4:]), Config: config}
			if v.Kind == Str {
				v.Str = global.str(int(v.Data))
			}
			e.Values = append(e.Values, v)
			return nil
		}
		e.Name = keys.str(int(le.Uint32(b[pos+4:])))
		if eflags&entryComplex != 0 {
			n := int(le.Uint32(b[pos+12:]))
			p := pos + esize
			for i := 0; i < n && p+12 <= len(b); i++ {
				if config == "" {
					e.Items = append(e.Items, readValue(b[p+4:], global, ""))
				}
				p += 12
			}
			return nil
		}
		if pos+esize+8 > len(b) {
			return fmt.Errorf("arsc: value past the type chunk")
		}
		e.Values = append(e.Values, readValue(b[pos+esize:], global, config))
		return nil
	}

	if flags&typeSparse != 0 {
		for i := 0; i < count; i++ {
			w := le.Uint32(b[hdr+4*i:])
			if err := read(int(w&0xffff), (w>>16)*4); err != nil {
				return err
			}
		}
		return nil
	}
	if flags&typeOffset16 != 0 {
		for i := 0; i < count; i++ {
			off := le.Uint16(b[hdr+2*i:])
			if off == noEntry16 {
				continue
			}
			if err := read(i, uint32(off)*4); err != nil {
				return err
			}
		}
		return nil
	}
	for i := 0; i < count; i++ {
		off := le.Uint32(b[hdr+4*i:])
		if off == noEntry {
			continue
		}
		if err := read(i, off); err != nil {
			return err
		}
	}
	return nil
}

func readValue(b []byte, global *pool, config string) Value {
	k := Kind(b[3])
	data := binary.LittleEndian.Uint32(b[4:])
	v := Value{Kind: k, Data: data, Config: config}
	if k == Str {
		v.Str = global.str(int(data))
	}
	return v
}

// chunkAt reads a chunk header.
func chunkAt(b []byte, off int) (typ, hdr, size int, err error) {
	if off+8 > len(b) {
		return 0, 0, 0, fmt.Errorf("arsc: truncated chunk header at %d", off)
	}
	typ = int(binary.LittleEndian.Uint16(b[off:]))
	hdr = int(binary.LittleEndian.Uint16(b[off+2:]))
	size = int(binary.LittleEndian.Uint32(b[off+4:]))
	if size < 8 || hdr > size {
		return 0, 0, 0, fmt.Errorf("arsc: bad chunk size at %d", off)
	}
	return typ, hdr, size, nil
}

type pool struct {
	b       []byte
	n       int
	utf8    bool
	strings int
}

func parsePool(b []byte) (*pool, error) {
	typ, hdr, _, err := chunkAt(b, 0)
	if err != nil || typ != chunkStringPool || hdr < 28 {
		return nil, fmt.Errorf("arsc: not a string pool")
	}
	le := binary.LittleEndian
	p := &pool{b: b, n: int(le.Uint32(b[8:])), utf8: le.Uint32(b[16:])&poolUTF8 != 0, strings: int(le.Uint32(b[20:]))}
	if hdr+4*p.n > len(b) {
		return nil, fmt.Errorf("arsc: string pool index past the chunk")
	}
	return p, nil
}

// str returns string i, or "" when out of range.
func (p *pool) str(i int) string {
	if p == nil || i < 0 || i >= p.n {
		return ""
	}
	le := binary.LittleEndian
	hdr := int(le.Uint16(p.b[2:]))
	pos := p.strings + int(le.Uint32(p.b[hdr+4*i:]))
	if pos >= len(p.b) {
		return ""
	}
	if p.utf8 {
		_, pos = utf8Len(p.b, pos) // characters
		n, pos := utf8Len(p.b, pos)
		if pos+n > len(p.b) {
			return ""
		}
		return string(p.b[pos : pos+n])
	}
	if pos+2 > len(p.b) {
		return ""
	}
	n := int(le.Uint16(p.b[pos:]))
	pos += 2
	if n&0x8000 != 0 {
		n = (n&0x7fff)<<16 | int(le.Uint16(p.b[pos:]))
		pos += 2
	}
	if pos+2*n > len(p.b) {
		return ""
	}
	u := make([]uint16, n)
	for j := range u {
		u[j] = le.Uint16(p.b[pos+2*j:])
	}
	return string(utf16.Decode(u))
}

// utf8Len reads a pool's one- or two-byte length.
func utf8Len(b []byte, pos int) (n, next int) {
	if pos >= len(b) {
		return 0, pos
	}
	n = int(b[pos])
	if n&0x80 != 0 && pos+1 < len(b) {
		return (n&0x7f)<<8 | int(b[pos+1]), pos + 2
	}
	return n, pos + 1
}
