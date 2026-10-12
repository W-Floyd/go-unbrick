package fdt

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// build assembles a one-level DTB: root{model="m"; child{compatible="a","b"; reg=<1 2>}}.
func build() []byte {
	be := binary.BigEndian
	var st, strs bytes.Buffer
	str := func(s string) uint32 { o := uint32(strs.Len()); strs.WriteString(s + "\x00"); return o }
	w := func(v uint32) { binary.Write(&st, be, v) }
	pad := func() {
		for st.Len()%4 != 0 {
			st.WriteByte(0)
		}
	}
	prop := func(name string, v []byte) {
		w(tokProp)
		w(uint32(len(v)))
		w(str(name))
		st.Write(v)
		pad()
	}
	w(tokBeginNode)
	st.WriteString("\x00")
	pad()
	prop("model", []byte("m\x00"))
	w(tokBeginNode)
	st.WriteString("child\x00")
	pad()
	prop("compatible", []byte("a\x00b\x00"))
	prop("reg", []byte{0, 0, 0, 1, 0, 0, 0, 2})
	w(tokEndNode)
	w(tokEndNode)
	w(tokEnd)

	var h bytes.Buffer
	offStruct := uint32(40)
	offStrings := offStruct + uint32(st.Len())
	for _, v := range []uint32{magic, offStrings + uint32(strs.Len()), offStruct, offStrings, 0, 17, 16, 0, uint32(strs.Len()), uint32(st.Len())} {
		binary.Write(&h, be, v)
	}
	return append(append(h.Bytes(), st.Bytes()...), strs.Bytes()...)
}

func TestParse(t *testing.T) {
	root, err := Parse(build())
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := root.Str("model"); m != "m" {
		t.Errorf("model = %q", m)
	}
	if len(root.Children) != 1 {
		t.Fatalf("children = %d", len(root.Children))
	}
	c := root.Children[0]
	if got := c.Strs("compatible"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("compatible = %q", got)
	}
	if got := c.U32s("reg"); len(got) != 2 || got[1] != 2 {
		t.Errorf("reg = %v", got)
	}
}

func TestSplit(t *testing.T) {
	one := build()
	if got := Split(append(append([]byte{}, one...), one...)); len(got) != 2 {
		t.Errorf("Split found %d DTBs, want 2", len(got))
	}
	if got := Split([]byte("junk junk junk junk")); len(got) != 0 {
		t.Errorf("Split found %d in junk", len(got))
	}
}
