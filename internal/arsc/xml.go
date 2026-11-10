package arsc

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"math"
	"strings"
)

const (
	chunkXML         = 0x0003
	chunkXMLStartNS  = 0x0100
	chunkXMLEndNS    = 0x0101
	chunkXMLStart    = 0x0102
	chunkXMLEnd      = 0x0103
	chunkXMLCData    = 0x0104
	chunkXMLResource = 0x0180

	maxXMLDepth = 256
)

// DecodeXML renders compiled binary XML (an APK's AndroidManifest.xml or a
// res/ layout) as text. t, when not nil, names the references it can resolve
// ("@string/app_name" rather than "@0x7f120034").
func DecodeXML(b []byte, t *Table) (string, error) {
	typ, hdr, size, err := chunkAt(b, 0)
	if err != nil || typ != chunkXML {
		return "", fmt.Errorf("arsc: not binary XML")
	}
	le := binary.LittleEndian
	end := min(size, len(b))
	d := xmlDecoder{names: t.names(), uris: map[string]string{}}
	var out strings.Builder
	out.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	depth := 0
	open := false // the last start tag is not yet closed with ">"
	closeOpen := func() {
		if open {
			out.WriteString(">\n")
			open = false
		}
	}
	for off := hdr; off < end; {
		ct, ch, cs, err := chunkAt(b, off)
		if err != nil {
			return "", err
		}
		c := b[off:min(off+cs, end)]
		off += cs
		body := c[min(ch, len(c)):]
		u32 := func(i int) uint32 {
			if i+4 > len(body) {
				return noEntry
			}
			return le.Uint32(body[i:])
		}
		switch ct {
		case chunkStringPool:
			if d.pool == nil {
				if d.pool, err = parsePool(c); err != nil {
					return "", err
				}
			}
		case chunkXMLResource:
			for i := ch; i+4 <= len(c); i += 4 {
				d.resIDs = append(d.resIDs, le.Uint32(c[i:]))
			}
		case chunkXMLStartNS:
			prefix, uri := d.pool.str(int(u32(0))), d.pool.str(int(u32(4)))
			d.uris[uri] = prefix
			d.pending = append(d.pending, fmt.Sprintf(`xmlns:%s="%s"`, prefix, escape(uri)))
		case chunkXMLEndNS:
		case chunkXMLStart:
			closeOpen()
			if depth >= maxXMLDepth {
				return "", fmt.Errorf("arsc: XML nested past %d elements", maxXMLDepth)
			}
			if len(body) < 20 {
				return "", fmt.Errorf("arsc: truncated XML element")
			}
			ind := strings.Repeat("  ", depth)
			out.WriteString(ind + "<" + d.qname(u32(0), u32(4)))
			attrStart, attrSize, attrCount := int(le.Uint16(body[8:])), int(le.Uint16(body[10:])), int(le.Uint16(body[12:]))
			attrs := d.pending
			d.pending = nil
			for i := range attrCount {
				a := attrStart + i*attrSize
				if attrSize < 20 || a+20 > len(body) {
					return "", fmt.Errorf("arsc: XML attribute past its element")
				}
				name := d.attrName(le.Uint32(body[a:]), le.Uint32(body[a+4:]))
				attrs = append(attrs, fmt.Sprintf(`%s="%s"`, name, escape(d.value(le.Uint32(body[a+8:]), body[a+12:a+20]))))
			}
			for i, a := range attrs {
				if i == 0 && len(attrs) == 1 {
					out.WriteString(" " + a)
				} else {
					out.WriteString("\n" + ind + "    " + a)
				}
			}
			open = true
			depth++
		case chunkXMLEnd:
			if depth == 0 {
				return "", fmt.Errorf("arsc: XML end tag with no element open")
			}
			depth--
			if open {
				out.WriteString(" />\n")
				open = false
			} else {
				out.WriteString(strings.Repeat("  ", depth) + "</" + d.qname(u32(0), u32(4)) + ">\n")
			}
		case chunkXMLCData:
			closeOpen()
			out.WriteString(strings.Repeat("  ", depth) + escape(d.pool.str(int(u32(0)))) + "\n")
		}
	}
	return out.String(), nil
}

type xmlDecoder struct {
	pool    *pool
	resIDs  []uint32
	uris    map[string]string // namespace URI to prefix
	pending []string          // xmlns declarations for the next element
	names   map[uint32]string
}

func (d *xmlDecoder) qname(ns, name uint32) string {
	n := d.pool.str(int(name))
	if ns == noEntry {
		return n
	}
	if p := d.uris[d.pool.str(int(ns))]; p != "" {
		return p + ":" + n
	}
	return n
}

// attrName falls back to the attribute's resource ID when an obfuscator has
// emptied its name; the platform reads attributes by ID, not by name.
func (d *xmlDecoder) attrName(ns, name uint32) string {
	q := d.qname(ns, name)
	if !strings.HasSuffix(q, ":") && q != "" {
		return q
	}
	if int(name) < len(d.resIDs) {
		return fmt.Sprintf("%sattr_0x%08x", q, d.resIDs[name])
	}
	return q + "unnamed"
}

func (d *xmlDecoder) value(raw uint32, rv []byte) string {
	if raw != noEntry {
		return d.pool.str(int(raw))
	}
	v := Value{Kind: Kind(rv[3]), Data: binary.LittleEndian.Uint32(rv[4:])}
	if v.Kind == Str {
		v.Str = d.pool.str(int(v.Data))
	}
	return v.format(d.names)
}

// names maps resource IDs to "type/name", for rendering references.
func (t *Table) names() map[uint32]string {
	if t == nil {
		return nil
	}
	t.nameOnce.Do(func() {
		t.nameMap = make(map[uint32]string, len(t.Entries))
		for _, e := range t.Entries {
			t.nameMap[e.ID] = e.Type + "/" + e.Name
		}
	})
	return t.nameMap
}

// format renders v the way aapt2 dump does; names resolves references.
func (v Value) format(names map[uint32]string) string {
	ref := func(sigil string) string {
		if n, ok := names[v.Data]; ok {
			return sigil + n
		}
		return fmt.Sprintf("%s0x%08x", sigil, v.Data)
	}
	switch v.Kind {
	case Null:
		if v.Data == 1 {
			return "@empty"
		}
		return "@null"
	case Reference:
		return ref("@")
	case Attribute:
		return ref("?")
	case Str:
		return v.Str
	case Float:
		return fmt.Sprint(math.Float32frombits(v.Data))
	case Dimension:
		n, u, _ := v.Dimension()
		return fmt.Sprint(n) + u
	case Fraction:
		mult := [4]float64{1.0 / (1 << 8), 1.0 / (1 << 15), 1.0 / (1 << 23), 1.0 / (1 << 31)}
		n := float64(int32(v.Data&0xffffff00)) * mult[(v.Data>>4)&3] * 100
		if v.Data&0xf == 1 {
			return fmt.Sprintf("%g%%p", n)
		}
		return fmt.Sprintf("%g%%", n)
	case Int:
		return fmt.Sprint(int32(v.Data))
	case Hex:
		return fmt.Sprintf("0x%x", v.Data)
	case Bool:
		return fmt.Sprint(v.Data != 0)
	}
	if v.Kind >= 0x1c && v.Kind <= 0x1f { // ARGB8, RGB8, ARGB4, RGB4
		return fmt.Sprintf("#%08x", v.Data)
	}
	return fmt.Sprintf("(type 0x%02x)0x%x", uint8(v.Kind), v.Data)
}

// Text lists every entry, one value per line, its configurations indented
// beneath it.
func (t *Table) Text() string {
	names := t.names()
	var b strings.Builder
	fmt.Fprintf(&b, "package %s (0x%02x)\n", t.Package, t.ID)
	for _, e := range t.Entries {
		fmt.Fprintf(&b, "0x%08x %s/%s", e.ID, e.Type, e.Name)
		if def, ok := e.Default(); ok {
			fmt.Fprintf(&b, " = %s", quote(def, names))
		}
		b.WriteString("\n")
		for _, v := range e.Values {
			if v.Config != "" {
				fmt.Fprintf(&b, "    [%s] = %s\n", v.Config, quote(v, names))
			}
		}
		for _, v := range e.Items {
			fmt.Fprintf(&b, "    - %s\n", quote(v, names))
		}
	}
	return b.String()
}

func quote(v Value, names map[uint32]string) string {
	if v.Kind == Str {
		return fmt.Sprintf("%q", v.Str)
	}
	return v.format(names)
}

func escape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
