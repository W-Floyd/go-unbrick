// Package fdt reads flattened device trees (DTB): the node tree, its
// properties, and the common typed views of a property's bytes. Nothing here
// resolves phandles or applies overlays; a DTBO fragment is read as the tree it
// is.
package fdt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const magic = 0xd00dfeed

const (
	tokBeginNode = 1
	tokEndNode   = 2
	tokProp      = 3
	tokNop       = 4
	tokEnd       = 9
)

// Node is one device-tree node.
type Node struct {
	Name     string
	Props    map[string][]byte
	Keys     []string // property names in file order
	Children []*Node
}

// Split returns each DTB in b, which may be several concatenated (a
// vendor_boot dtb section is). Anything that is not a DTB ends the walk.
func Split(b []byte) [][]byte {
	var out [][]byte
	for len(b) >= 8 && binary.BigEndian.Uint32(b) == magic {
		n := int(binary.BigEndian.Uint32(b[4:]))
		if n < 40 || n > len(b) {
			break
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

// Parse reads one DTB.
func Parse(b []byte) (*Node, error) {
	if len(b) < 40 || binary.BigEndian.Uint32(b) != magic {
		return nil, fmt.Errorf("fdt: not a device tree")
	}
	be := binary.BigEndian
	total, offStruct, offStrings := int(be.Uint32(b[4:])), int(be.Uint32(b[8:])), int(be.Uint32(b[12:]))
	sizeStrings, sizeStruct := int(be.Uint32(b[32:])), int(be.Uint32(b[36:]))
	if total > len(b) || offStruct+sizeStruct > total || offStrings+sizeStrings > total {
		return nil, fmt.Errorf("fdt: header sizes run past the blob")
	}
	st, strs := b[offStruct:offStruct+sizeStruct], b[offStrings:offStrings+sizeStrings]

	var stack []*Node
	var root *Node
	for p := 0; p+4 <= len(st); {
		tok := be.Uint32(st[p:])
		p += 4
		switch tok {
		case tokBeginNode:
			end := bytes.IndexByte(st[p:], 0)
			if end < 0 {
				return nil, fmt.Errorf("fdt: unterminated node name")
			}
			n := &Node{Name: string(st[p : p+end]), Props: map[string][]byte{}}
			p += (end + 1 + 3) &^ 3
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, n)
			} else {
				root = n
			}
			stack = append(stack, n)
		case tokEndNode:
			if len(stack) == 0 {
				return nil, fmt.Errorf("fdt: unbalanced end of node")
			}
			stack = stack[:len(stack)-1]
		case tokProp:
			if p+8 > len(st) || len(stack) == 0 {
				return nil, fmt.Errorf("fdt: bad property")
			}
			n, nameOff := int(be.Uint32(st[p:])), int(be.Uint32(st[p+4:]))
			p += 8
			if p+n > len(st) || nameOff >= len(strs) {
				return nil, fmt.Errorf("fdt: property runs past the structure block")
			}
			end := bytes.IndexByte(strs[nameOff:], 0)
			if end < 0 {
				return nil, fmt.Errorf("fdt: unterminated property name")
			}
			name := string(strs[nameOff : nameOff+end])
			cur := stack[len(stack)-1]
			if _, dup := cur.Props[name]; !dup {
				cur.Keys = append(cur.Keys, name)
			}
			cur.Props[name] = st[p : p+n]
			p += (n + 3) &^ 3
		case tokNop:
		case tokEnd:
			if root == nil {
				return nil, fmt.Errorf("fdt: empty tree")
			}
			return root, nil
		default:
			return nil, fmt.Errorf("fdt: unknown token %#x", tok)
		}
	}
	return nil, fmt.Errorf("fdt: no end token")
}

// Str is a property read as one string; ok is false if absent.
func (n *Node) Str(name string) (string, bool) {
	v, ok := n.Props[name]
	if !ok {
		return "", false
	}
	return strings.TrimRight(string(v), "\x00"), true
}

// Strs is a property read as a string list ("compatible").
func (n *Node) Strs(name string) []string {
	v := n.Props[name]
	if len(v) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(v), "\x00"), "\x00")
}

// U32s is a property read as big-endian cells.
func (n *Node) U32s(name string) []uint32 {
	v := n.Props[name]
	out := make([]uint32, 0, len(v)/4)
	for i := 0; i+4 <= len(v); i += 4 {
		out = append(out, binary.BigEndian.Uint32(v[i:]))
	}
	return out
}

// Walk calls f on n and every descendant, with its slash path from n.
func (n *Node) Walk(f func(path string, n *Node)) {
	var rec func(p string, n *Node)
	rec = func(p string, n *Node) {
		f(p, n)
		for _, c := range n.Children {
			rec(p+"/"+c.Name, c)
		}
	}
	rec(n.Name, n)
}
