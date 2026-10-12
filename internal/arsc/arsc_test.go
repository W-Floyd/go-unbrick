package arsc

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"unicode/utf16"
)

var le = binary.LittleEndian

func u16(v int) []byte { b := make([]byte, 2); le.PutUint16(b, uint16(v)); return b }
func u32(v uint32) []byte {
	b := make([]byte, 4)
	le.PutUint32(b, v)
	return b
}
func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func chunk(typ, hdr int, header, body []byte) []byte {
	size := 8 + len(header) + len(body)
	return cat(u16(typ), u16(hdr), u32(uint32(size)), header, body)
}

// stringPool builds a UTF-8 or UTF-16 pool.
func stringPool(utf8 bool, ss ...string) []byte {
	var data []byte
	var offs []byte
	for _, s := range ss {
		offs = append(offs, u32(uint32(len(data)))...)
		if utf8 {
			data = append(data, byte(len([]rune(s))), byte(len(s)))
			data = append(data, s...)
			data = append(data, 0)
		} else {
			u := utf16.Encode([]rune(s))
			data = append(data, u16(len(u))...)
			for _, c := range u {
				data = append(data, u16(int(c))...)
			}
			data = append(data, 0, 0)
		}
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	var flags uint32
	if utf8 {
		flags = poolUTF8
	}
	start := 28 + len(offs)
	return chunk(chunkStringPool, 28, cat(u32(uint32(len(ss))), u32(0), u32(flags), u32(uint32(start)), u32(0)), cat(offs, data))
}

// typeChunk builds a dense type chunk of {key index, dataType, data} entries.
func typeChunk(id int, entries [][3]uint32) []byte {
	var offs, body []byte
	for _, e := range entries {
		offs = append(offs, u32(uint32(len(body)))...)
		body = append(body, cat(u16(8), u16(0), u32(e[0]), u16(8), []byte{0, byte(e[1])}, u32(e[2]))...)
	}
	cfg := make([]byte, 28) // all-default configuration
	le.PutUint32(cfg, 28)
	hdr := cat([]byte{byte(id), 0}, u16(0), u32(uint32(len(entries))), u32(uint32(8+4+4+4+28+len(offs))), cfg)
	return chunk(chunkType, 8+len(hdr), hdr, cat(offs, body))
}

// buildAPK writes an APK holding a table with a string and a dimension.
func buildAPK(t *testing.T, utf8 bool) []byte {
	global := stringPool(utf8, "M -35,0 L 35,0 Z")
	types := stringPool(utf8, "string", "dimen")
	keys := stringPool(utf8, "cutout", "corner")

	name := make([]byte, 256)
	for i, c := range utf16.Encode([]rune("com.example.rro")) {
		le.PutUint16(name[2*i:], c)
	}
	const pkgHdr = 8 + 4 + 256 + 5*4
	body := cat(types, keys,
		typeChunk(1, [][3]uint32{{0, uint32(Str), 0}}),
		typeChunk(2, [][3]uint32{{1, uint32(Dimension), 62<<8 | 0}}), // 62px
	)
	pkg := chunk(chunkPackage, pkgHdr, cat(u32(0x7f), name, u32(pkgHdr), u32(2), u32(uint32(pkgHdr+len(types))), u32(2), u32(0)), body)
	table := chunk(chunkTable, 12, u32(1), cat(global, pkg))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("resources.arsc")
	w.Write(table)
	zw.Close()
	return buf.Bytes()
}

func TestOpenAPK(t *testing.T) {
	for _, utf8 := range []bool{true, false} {
		tb, err := OpenAPK(buildAPK(t, utf8))
		if err != nil {
			t.Fatalf("utf8=%v: %v", utf8, err)
		}
		if tb.Package != "com.example.rro" || tb.ID != 0x7f {
			t.Errorf("package %q id %#x", tb.Package, tb.ID)
		}
		s := tb.Lookup("string", "cutout")
		if s == nil {
			t.Fatalf("utf8=%v: string/cutout missing: %+v", utf8, tb.Entries)
		}
		if v, ok := s.Default(); !ok || v.Str != "M -35,0 L 35,0 Z" || s.ID != 0x7f010000 {
			t.Errorf("string/cutout = %+v id %#x", v, s.ID)
		}
		d := tb.Lookup("dimen", "corner")
		v, ok := d.Default()
		if n, unit, isDim := v.Dimension(); !ok || !isDim || n != 62 || unit != "px" {
			t.Errorf("dimen/corner = %v %q (%v)", n, unit, isDim)
		}
	}
}

func TestDimensionUnits(t *testing.T) {
	// 24dp: mantissa 24 in radix 23p0 (0), unit dip (1).
	if n, u, ok := (Value{Kind: Dimension, Data: 24<<8 | 1}).Dimension(); !ok || n != 24 || u != "dp" {
		t.Errorf("24dp = %v %q %v", n, u, ok)
	}
	// 0.5mm: mantissa 0.5 in radix 0p23 (3): 0.5 * 2^23 << 8.
	if n, u, _ := (Value{Kind: Dimension, Data: uint32(0.5*(1<<23))<<8 | 3<<4 | 5}).Dimension(); n != 0.5 || u != "mm" {
		t.Errorf("0.5mm = %v %q", n, u)
	}
	if _, _, ok := (Value{Kind: Int}).Dimension(); ok {
		t.Error("an int is not a dimension")
	}
}

func TestNotATable(t *testing.T) {
	if _, err := Parse([]byte("not a resource table")); err == nil {
		t.Error("expected an error")
	}
}

// testdata/{plain,compact}.apk are built from testdata/values.xml by
//
//	aapt2 compile -o res.zip --dir res
//	aapt2 link -I android.jar --manifest AndroidManifest.xml --min-sdk-version 34 [--enable-compact-entries] -o X.apk res.zip
//
// so the compact one holds the same resources in the compact entry encoding.
func TestCompactEntriesMatchPlain(t *testing.T) {
	load := func(name string) *Table {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		tb, err := OpenAPK(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return tb
	}
	plain, compact := load("plain.apk"), load("compact.apk")
	if len(plain.Entries) != 7 || len(compact.Entries) != len(plain.Entries) {
		t.Fatalf("entries: plain %d, compact %d, want 7", len(plain.Entries), len(compact.Entries))
	}
	for _, p := range plain.Entries {
		c := compact.Lookup(p.Type, p.Name)
		if c == nil {
			t.Errorf("%s/%s missing from the compact table", p.Type, p.Name)
			continue
		}
		if c.ID != p.ID || len(c.Values) != len(p.Values) || len(c.Items) != len(p.Items) {
			t.Errorf("%s/%s: compact %+v, plain %+v", p.Type, p.Name, c, p)
			continue
		}
		for i := range p.Values {
			if c.Values[i] != p.Values[i] {
				t.Errorf("%s/%s value %d: compact %+v, plain %+v", p.Type, p.Name, i, c.Values[i], p.Values[i])
			}
		}
	}
	if v, _ := compact.Lookup("string", "cutout").Default(); v.Str != "M -35,0 L 35,0 L 35,80 L -35,80 Z" {
		t.Errorf("compact string = %q", v.Str)
	}
	if v, _ := compact.Lookup("dimen", "radius").Default(); v.Kind != Dimension {
		t.Errorf("compact dimen kind = %#x", v.Kind)
	} else if n, u, _ := v.Dimension(); n != 24 || u != "dp" {
		t.Errorf("compact dimen = %v%s", n, u)
	}
}
