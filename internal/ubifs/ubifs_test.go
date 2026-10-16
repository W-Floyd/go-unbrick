package ubifs

import (
	"bytes"
	"io"
	"io/fs"
	"testing"
)

const leb = 4096

type img struct {
	b   []byte
	off int
	sq  uint64
}

// node appends a node with the common header and body at the next 8-byte slot.
func (m *img) node(typ byte, body []byte) {
	m.sq++
	n := chSize + len(body)
	h := m.b[m.off:]
	le.PutUint32(h, nodeMagic)
	le.PutUint64(h[8:], m.sq)
	le.PutUint32(h[16:], uint32(n))
	h[20] = typ
	copy(h[chSize:], body)
	m.off += (n + 7) &^ 7
}

func key(inum uint32, low uint32) []byte {
	k := make([]byte, 16)
	le.PutUint32(k, inum)
	le.PutUint32(k[4:], low)
	return k
}

func ino(inum, mode uint32, size uint64, nlink uint32) []byte {
	b := make([]byte, inoSize-chSize)
	copy(b, key(inum, 0))
	le.PutUint64(b[48-chSize:], size)
	le.PutUint32(b[92-chSize:], nlink)
	le.PutUint32(b[104-chSize:], mode)
	return b
}

func dentBody(parent uint32, inum uint64, name string) []byte {
	b := make([]byte, dentSize-chSize, dentSize-chSize+len(name))
	copy(b, key(parent, 2<<29))
	le.PutUint64(b[40-chSize:], inum)
	le.PutUint16(b[50-chSize:], uint16(len(name)))
	return append(b, name...)
}

func dataBody(inum, blk uint32, payload string) []byte {
	b := make([]byte, dataSize-chSize)
	copy(b, key(inum, 1<<29|blk))
	le.PutUint32(b[40-chSize:], uint32(len(payload)))
	return append(b, payload...)
}

func TestOpen(t *testing.T) {
	m := &img{b: bytes.Repeat([]byte{0xff}, 2*leb)}
	sb := make([]byte, 64)
	le.PutUint32(sb[36-chSize:], leb)
	m.node(nodeSB, sb)
	m.off = leb // journal LEB
	m.node(nodeIno, ino(1, 0o040755, 0, 2))
	m.node(nodeIno, ino(2, 0o100644, 5, 1))
	m.node(nodeDent, dentBody(1, 2, "hello.txt"))
	m.node(nodeData, dataBody(2, 0, "old!!"))
	m.node(nodeData, dataBody(2, 0, "world")) // newer wins
	m.node(nodeIno, ino(3, 0o100644, 1, 1))
	m.node(nodeDent, dentBody(1, 3, "gone"))
	m.node(nodeDent, dentBody(1, 0, "gone")) // deletion

	f, err := Open(bytes.NewReader(m.b), int64(len(m.b)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile(f, "hello.txt")
	if err != nil || string(got) != "world" {
		t.Fatalf("hello.txt = %q, %v", got, err)
	}
	ents, _ := fs.ReadDir(f, ".")
	if len(ents) != 1 || ents[0].Name() != "hello.txt" {
		t.Errorf("root lists %v", ents)
	}
	if _, err := f.Open("gone"); err == nil {
		t.Error("deleted entry still opens")
	}
	d, _ := f.Open("hello.txt")
	if n, err := d.Read(make([]byte, 99)); n != 5 || (err != nil && err != io.EOF) {
		t.Errorf("read %d %v", n, err)
	}
}
