// Package ext4fs reads an ext4 image as an fs.FS without holding it: a path
// is resolved directory by directory, so opening one file of a multi-GB
// partition reads only the blocks on its path and its own.
package ext4fs

import (
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	ext4 "github.com/W-Floyd/go-ext4"
)

const (
	incompatOff = 1024 + 0x60
	flexBG      = 0x200
)

// FS is an ext4 image. Safe for concurrent use: each operation reads through
// its own section of the image.
type FS struct {
	ra   io.ReaderAt
	size int64
	bgdl *ext4.BlockGroupDescriptorList
}

// Open reads the superblock and group descriptors of the image at ra.
func Open(ra io.ReaderAt, size int64) (*FS, error) {
	f := &FS{ra: flexOverlay{ra}, size: size}
	r := f.reader()
	if _, err := r.Seek(ext4.Superblock0Offset, io.SeekStart); err != nil {
		return nil, err
	}
	sb, err := ext4.NewSuperblockWithReader(r)
	if err != nil {
		return nil, err
	}
	if !sb.Is64Bit() {
		gdt := int64(sb.Data().SFirstDataBlock+1) * int64(sb.BlockSize())
		w, err := widen(f.ra, gdt, int64(sb.BlockGroupCount()))
		if err != nil {
			return nil, err
		}
		r = io.NewSectionReader(w, 0, f.size)
	}
	if f.bgdl, err = ext4.NewBlockGroupDescriptorListWithReadSeeker(r, sb); err != nil {
		return nil, err
	}
	return f, nil
}

// widened presents a 32-byte group descriptor table at the 64-byte stride
// go-ext4 always reads it at, which without the 64bit feature puts every
// group past the first at the wrong inode table.
type widened struct {
	io.ReaderAt
	off   int64
	table []byte
}

func widen(ra io.ReaderAt, off, groups int64) (widened, error) {
	raw := make([]byte, groups*32)
	if _, err := ra.ReadAt(raw, off); err != nil {
		return widened{}, err
	}
	table := make([]byte, groups*64)
	for g := int64(0); g < groups; g++ {
		copy(table[g*64:], raw[g*32:g*32+32])
	}
	return widened{ra, off, table}, nil
}

func (w widened) ReadAt(p []byte, off int64) (int, error) {
	end := w.off + int64(len(w.table))
	if off+int64(len(p)) <= w.off || off >= end {
		return w.ReaderAt.ReadAt(p, off)
	}
	n := 0
	if off < w.off {
		k, err := w.ReaderAt.ReadAt(p[:w.off-off], off)
		if n += k; err != nil {
			return n, err
		}
	}
	n += copy(p[n:], w.table[off+int64(n)-w.off:])
	if n < len(p) {
		k, err := w.ReaderAt.ReadAt(p[n:], off+int64(n))
		return n + k, err
	}
	return n, nil
}

// flexOverlay reports the flex_bg feature set, which go-ext4 insists on but
// never depends on: it locates each group's inode table from that group's
// descriptor either way. Small images (Motorola's dspso) are built without it.
type flexOverlay struct{ io.ReaderAt }

func (o flexOverlay) ReadAt(p []byte, off int64) (int, error) {
	n, err := o.ReaderAt.ReadAt(p, off)
	if lo, hi := int64(incompatOff), int64(incompatOff+4); off <= lo && off+int64(n) >= hi {
		i := lo - off
		binary.LittleEndian.PutUint32(p[i:], binary.LittleEndian.Uint32(p[i:])|flexBG)
	}
	return n, err
}

func (f *FS) reader() *io.SectionReader { return io.NewSectionReader(f.ra, 0, f.size) }

func (f *FS) inode(n int) (*ext4.Inode, *io.SectionReader, error) {
	bgd, err := f.bgdl.GetWithAbsoluteInode(n)
	if err != nil {
		return nil, nil, err
	}
	r := f.reader()
	in, err := ext4.NewInodeWithReadSeeker(bgd, r, n)
	return in, r, err
}

type entry struct {
	name  string
	inode int
	dir   bool
	reg   bool
}

func (f *FS) entries(n int) ([]entry, error) {
	in, r, err := f.inode(n)
	if err != nil {
		return nil, err
	}
	db := ext4.NewDirectoryBrowser(r, in)
	var out []entry
	for {
		de, err := db.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if name := de.Name(); name != "." && name != ".." && de.Data().Inode != 0 {
			out = append(out, entry{name, int(de.Data().Inode), de.IsDirectory(), de.IsRegular()})
		}
	}
}

// lookup resolves name to its entry, the root being a directory.
func (f *FS) lookup(name string) (entry, error) {
	e := entry{name: ".", inode: ext4.InodeRootDirectory, dir: true}
	if name == "." {
		return e, nil
	}
	for _, part := range strings.Split(name, "/") {
		if !e.dir {
			return entry{}, fs.ErrNotExist
		}
		es, err := f.entries(e.inode)
		if err != nil {
			return entry{}, err
		}
		found := false
		for _, c := range es {
			if c.name == part {
				e, found = c, true
				break
			}
		}
		if !found {
			return entry{}, fs.ErrNotExist
		}
	}
	return e, nil
}

func (f *FS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	e, err := f.lookup(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	if !e.dir && !e.reg {
		return nil, &fs.PathError{Op: "open", Path: name, Err: errors.New("not a regular file or directory")}
	}
	in, r, err := f.inode(e.inode)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	info := fileInfo{name: path.Base(name), size: int64(in.Size()), dir: e.dir, mod: in.ModificationTime(), imode: in.Data().IMode}
	if e.dir {
		return &dirFile{fs: f, e: e, info: info}, nil
	}
	return &file{info: info, r: ext4.NewInodeReader(ext4.NewExtentNavigatorWithReadSeeker(r, in))}, nil
}

func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	e, err := f.lookup(name)
	if err == nil && !e.dir {
		err = errors.New("not a directory")
	}
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	return f.readDir(e)
}

func (f *FS) readDir(e entry) ([]fs.DirEntry, error) {
	es, err := f.entries(e.inode)
	if err != nil {
		return nil, err
	}
	var out []fs.DirEntry
	for _, c := range es {
		if c.dir || c.reg {
			out = append(out, dirEntry{f, c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

type file struct {
	info fileInfo
	r    io.Reader
	read int64
}

func (f *file) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *file) Close() error               { return nil }
func (f *file) Read(p []byte) (int, error) {
	if f.read >= f.info.size {
		return 0, io.EOF
	}
	p = p[:min(int64(len(p)), f.info.size-f.read)]
	n, err := f.r.Read(p)
	f.read += int64(n)
	if err == io.EOF && f.read < f.info.size {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

type dirFile struct {
	fs   *FS
	e    entry
	info fileInfo
	rest []fs.DirEntry
	read bool
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dirFile) Close() error               { return nil }
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.info.name, Err: errors.New("is a directory")}
}

func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if !d.read {
		es, err := d.fs.readDir(d.e)
		if err != nil {
			return nil, err
		}
		d.rest, d.read = es, true
	}
	if n <= 0 {
		out := d.rest
		d.rest = nil
		return out, nil
	}
	if len(d.rest) == 0 {
		return nil, io.EOF
	}
	k := min(n, len(d.rest))
	out := d.rest[:k]
	d.rest = d.rest[k:]
	return out, nil
}

type dirEntry struct {
	fs *FS
	e  entry
}

func (d dirEntry) Name() string { return d.e.name }
func (d dirEntry) IsDir() bool  { return d.e.dir }
func (d dirEntry) Type() fs.FileMode {
	if d.e.dir {
		return fs.ModeDir
	}
	return 0
}

// Info reads the entry's inode, for its size.
func (d dirEntry) Info() (fs.FileInfo, error) {
	in, _, err := d.fs.inode(d.e.inode)
	if err != nil {
		return nil, err
	}
	return fileInfo{name: d.e.name, size: int64(in.Size()), dir: d.e.dir, mod: in.ModificationTime(), imode: in.Data().IMode}, nil
}

type fileInfo struct {
	name  string
	size  int64
	dir   bool
	mod   time.Time
	imode uint16 // the inode's raw i_mode: type bits, permissions, setuid/setgid/sticky
}

func (i fileInfo) Name() string       { return i.name }
func (i fileInfo) Size() int64        { return i.size }
func (i fileInfo) ModTime() time.Time { return i.mod }
func (i fileInfo) IsDir() bool        { return i.dir }
func (i fileInfo) Sys() any           { return nil }
func (i fileInfo) Mode() fs.FileMode  { return modeFromIMode(i.imode) }

// modeFromIMode decodes an ext4 inode's i_mode (the on-disk POSIX st_mode:
// S_IFMT type bits in the high nibbles, permissions and setuid/setgid/sticky
// in the low 12 bits) into the fs.FileMode go-unbrick's callers rely on to
// see real permissions, not a guess.
func modeFromIMode(m uint16) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & 0o170000 {
	case 0o040000:
		mode |= fs.ModeDir
	case 0o120000:
		mode |= fs.ModeSymlink
	case 0o140000:
		mode |= fs.ModeSocket
	case 0o060000:
		mode |= fs.ModeDevice
	case 0o020000:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case 0o010000:
		mode |= fs.ModeNamedPipe
	}
	if m&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}
