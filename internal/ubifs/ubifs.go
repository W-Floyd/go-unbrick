// Package ubifs reads a UBIFS volume as an fs.FS without replaying its journal
// or walking its index: it scans every eraseblock for nodes and keeps the one
// with the highest sequence number for each inode, directory entry and data
// block. That reproduces the live tree, since an update only ever adds a newer
// node, and it reads an image whose index or log is damaged.
package ubifs

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/anchore/go-lzo"
)

const (
	nodeMagic = 0x06101831
	chSize    = 24

	nodeIno  = 0
	nodeData = 1
	nodeDent = 2
	nodeSB   = 6

	inoSize  = 160
	dentSize = 56
	dataSize = 48

	rootInum = 1

	comprNone = 0
	comprLZO  = 1
	comprZlib = 2
)

var le = binary.LittleEndian

type inode struct {
	sqnum uint64
	mode  uint32
	size  uint64
	nlink uint32
	mtime int64
	data  []byte // symlink target
}

type dent struct {
	sqnum uint64
	inum  uint64
	typ   uint8
}

type block struct {
	sqnum  uint64
	off    int64 // absolute offset of the data node
	length int   // node length
}

// FS is a UBIFS volume.
type FS struct {
	ra     io.ReaderAt
	inodes map[uint64]*inode
	dents  map[uint64]map[string]dent
	blocks map[uint64]map[uint32]block
}

// Open scans the UBIFS volume in ra.
func Open(ra io.ReaderAt, size int64) (*FS, error) {
	head := make([]byte, 64)
	if _, err := ra.ReadAt(head, 0); err != nil || le.Uint32(head) != nodeMagic || head[20] != nodeSB {
		return nil, errors.New("ubifs: no superblock")
	}
	lebSize := int64(le.Uint32(head[36:]))
	if lebSize < 4096 || lebSize > 16<<20 {
		return nil, fmt.Errorf("ubifs: implausible LEB size %d", lebSize)
	}
	f := &FS{
		ra: ra, inodes: map[uint64]*inode{},
		dents: map[uint64]map[string]dent{}, blocks: map[uint64]map[uint32]block{},
	}
	leb := make([]byte, lebSize)
	for base := int64(0); base+lebSize <= size; base += lebSize {
		if _, err := ra.ReadAt(leb, base); err != nil && err != io.EOF {
			return nil, err
		}
		f.scan(leb, base)
	}
	if _, ok := f.inodes[rootInum]; !ok {
		return nil, errors.New("ubifs: no root inode")
	}
	return f, nil
}

func (f *FS) scan(leb []byte, base int64) {
	for off := 0; off+chSize <= len(leb); {
		if le.Uint32(leb[off:]) != nodeMagic {
			return
		}
		sq := le.Uint64(leb[off+8:])
		n := int(le.Uint32(leb[off+16:]))
		typ := leb[off+20]
		if n < chSize || off+n > len(leb) {
			return
		}
		node := leb[off : off+n]
		key := func() (inum uint64, low uint32) {
			return uint64(le.Uint32(node[24:])), le.Uint32(node[28:])
		}
		switch {
		case typ == nodeIno && n >= inoSize:
			inum, _ := key()
			if old := f.inodes[inum]; old == nil || sq > old.sqnum {
				ino := &inode{
					sqnum: sq, size: le.Uint64(node[48:]), nlink: le.Uint32(node[92:]),
					mode: le.Uint32(node[104:]), mtime: int64(le.Uint64(node[72:])),
				}
				if dl := int(le.Uint32(node[112:])); dl > 0 && inoSize+dl <= n {
					ino.data = append([]byte(nil), node[inoSize:inoSize+dl]...)
				}
				f.inodes[inum] = ino
			}
		case typ == nodeDent && n >= dentSize:
			parent, _ := key()
			nlen := int(le.Uint16(node[50:]))
			if dentSize+nlen > n {
				break
			}
			name := string(node[dentSize : dentSize+nlen])
			m := f.dents[parent]
			if m == nil {
				m = map[string]dent{}
				f.dents[parent] = m
			}
			if old, ok := m[name]; !ok || sq > old.sqnum {
				m[name] = dent{sqnum: sq, inum: le.Uint64(node[40:]), typ: node[49]}
			}
		case typ == nodeData && n > dataSize:
			inum, low := key()
			blk := low & 0x1fffffff
			m := f.blocks[inum]
			if m == nil {
				m = map[uint32]block{}
				f.blocks[inum] = m
			}
			if old, ok := m[blk]; !ok || sq > old.sqnum {
				m[blk] = block{sqnum: sq, off: base + int64(off), length: n}
			}
		}
		off += (n + 7) &^ 7
	}
}

// readBlock returns the decompressed contents of one 4 KiB block.
func (f *FS) readBlock(b block) ([]byte, error) {
	node := make([]byte, b.length)
	if _, err := f.ra.ReadAt(node, b.off); err != nil && err != io.EOF {
		return nil, err
	}
	usize := int(le.Uint32(node[40:]))
	payload := node[dataSize:]
	switch le.Uint16(node[44:]) {
	case comprNone:
		return payload, nil
	case comprLZO:
		out := make([]byte, usize)
		n, err := lzo.Decompress(payload, out)
		if err != nil {
			return nil, err
		}
		return out[:n], nil
	case comprZlib:
		return io.ReadAll(flate.NewReader(bytes.NewReader(payload)))
	}
	return nil, fmt.Errorf("ubifs: unsupported compression %d", le.Uint16(node[44:]))
}

// lookup walks name from the root, returning its inode number.
func (f *FS) lookup(name string) (uint64, bool) {
	inum := uint64(rootInum)
	if name == "." {
		return inum, true
	}
	for _, part := range strings.Split(name, "/") {
		d, ok := f.dents[inum][part]
		if !ok || d.inum == 0 {
			return 0, false
		}
		inum = d.inum
	}
	return inum, f.inodes[inum] != nil
}

func (f *FS) info(name string, inum uint64) *fileInfo {
	ino := f.inodes[inum]
	return &fileInfo{name: path.Base(name), ino: ino}
}

// Open implements fs.FS.
func (f *FS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	inum, ok := f.lookup(name)
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	fi := f.info(name, inum)
	if fi.IsDir() {
		return &dir{fs: f, name: name, inum: inum, fi: fi}, nil
	}
	return &file{fs: f, inum: inum, fi: fi}, nil
}

// ReadDir implements fs.ReadDirFS.
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	d, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	return d.(fs.ReadDirFile).ReadDir(-1)
}

type fileInfo struct {
	name string
	ino  *inode
}

func (i *fileInfo) Name() string       { return i.name }
func (i *fileInfo) Size() int64        { return int64(i.ino.size) }
func (i *fileInfo) ModTime() time.Time { return time.Unix(i.ino.mtime, 0) }
func (i *fileInfo) IsDir() bool        { return i.Mode().IsDir() }
func (i *fileInfo) Sys() any           { return nil }
func (i *fileInfo) Mode() fs.FileMode {
	m := fs.FileMode(i.ino.mode & 0o777)
	switch i.ino.mode & 0o170000 {
	case 0o040000:
		m |= fs.ModeDir
	case 0o120000:
		m |= fs.ModeSymlink
	case 0o020000:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case 0o060000:
		m |= fs.ModeDevice
	case 0o010000:
		m |= fs.ModeNamedPipe
	case 0o140000:
		m |= fs.ModeSocket
	}
	return m
}

type entry struct{ *fileInfo }

func (e entry) Type() fs.FileMode          { return e.Mode().Type() }
func (e entry) Info() (fs.FileInfo, error) { return e.fileInfo, nil }

type dir struct {
	fs   *FS
	name string
	inum uint64
	fi   *fileInfo
	ents []fs.DirEntry
	done bool
}

func (d *dir) Stat() (fs.FileInfo, error) { return d.fi, nil }
func (d *dir) Close() error               { return nil }
func (d *dir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}

func (d *dir) ReadDir(n int) ([]fs.DirEntry, error) {
	if !d.done {
		var names []string
		for name, e := range d.fs.dents[d.inum] {
			if e.inum != 0 && d.fs.inodes[e.inum] != nil && d.fs.inodes[e.inum].nlink > 0 {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			e := d.fs.dents[d.inum][name]
			d.ents = append(d.ents, entry{d.fs.info(name, e.inum)})
		}
		d.done = true
	}
	if n <= 0 {
		out := d.ents
		d.ents = nil
		return out, nil
	}
	if len(d.ents) == 0 {
		return nil, io.EOF
	}
	k := min(n, len(d.ents))
	out := d.ents[:k]
	d.ents = d.ents[k:]
	return out, nil
}

type file struct {
	fs   *FS
	inum uint64
	fi   *fileInfo
	pos  int64
}

func (f *file) Stat() (fs.FileInfo, error) { return f.fi, nil }
func (f *file) Close() error               { return nil }

func (f *file) Read(p []byte) (int, error) {
	ino := f.fi.ino
	if ino.mode&0o170000 == 0o120000 {
		if f.pos >= int64(len(ino.data)) {
			return 0, io.EOF
		}
		n := copy(p, ino.data[f.pos:])
		f.pos += int64(n)
		return n, nil
	}
	size := int64(ino.size)
	if f.pos >= size {
		return 0, io.EOF
	}
	const blockSize = 4096
	n := 0
	for n < len(p) && f.pos < size {
		bn := uint32(f.pos / blockSize)
		in := int(f.pos % blockSize)
		buf := make([]byte, blockSize) // a hole reads as zeros
		if b, ok := f.fs.blocks[f.inum][bn]; ok {
			data, err := f.fs.readBlock(b)
			if err != nil {
				return n, err
			}
			copy(buf, data)
		}
		end := min(int64(blockSize), size-int64(bn)*blockSize)
		c := copy(p[n:], buf[in:end])
		n += c
		f.pos += int64(c)
	}
	return n, nil
}
