package carve

import (
	"bytes"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/modem"
)

// firmwareFS is a FAT or ext4 image as an fs.FS: the file list is read once,
// a file's bytes only when it is opened.
func firmwareFS(n *Node) (fs.FS, error) {
	img, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	entries, err := modem.List(img)
	if err != nil {
		return nil, err
	}
	f := &listFS{img: img, files: map[string]int64{}, dirs: map[string]map[string]bool{".": {}}}
	for _, e := range entries {
		p := strings.Trim(path.Clean("/"+e.Path), "/")
		f.files[p] = int64(e.Size)
		for child, dir := p, path.Dir(p); ; child, dir = dir, path.Dir(dir) {
			if f.dirs[dir] == nil {
				f.dirs[dir] = map[string]bool{}
			}
			f.dirs[dir][path.Base(child)] = true
			if dir == "." {
				break
			}
		}
	}
	return f, nil
}

type listFS struct {
	img   []byte
	files map[string]int64
	dirs  map[string]map[string]bool
}

func (f *listFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if _, ok := f.dirs[name]; ok {
		return &listFile{info: f.info(name)}, nil
	}
	if _, ok := f.files[name]; !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	b, err := modem.Extract(f.img, name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &listFile{info: f.info(name), r: bytes.NewReader(b)}, nil
}

// ReadDir lets fs.Glob and fs.WalkDir list a directory without opening it.
func (f *listFS) ReadDir(name string) ([]fs.DirEntry, error) {
	kids, ok := f.dirs[name]
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	var out []fs.DirEntry
	for k := range kids {
		out = append(out, fs.FileInfoToDirEntry(f.info(path.Join(name, k))))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

func (f *listFS) info(name string) fileInfo {
	_, dir := f.dirs[name]
	return fileInfo{name: path.Base(name), size: f.files[name], dir: dir}
}

type listFile struct {
	info fileInfo
	r    *bytes.Reader
}

func (l *listFile) Stat() (fs.FileInfo, error) { return l.info, nil }
func (l *listFile) Close() error               { return nil }
func (l *listFile) Read(p []byte) (int, error) {
	if l.r == nil {
		return 0, &fs.PathError{Op: "read", Path: l.info.name, Err: fs.ErrInvalid}
	}
	return l.r.Read(p)
}

type fileInfo struct {
	name string
	size int64
	dir  bool
}

func (i fileInfo) Name() string       { return i.name }
func (i fileInfo) Size() int64        { return i.size }
func (i fileInfo) ModTime() time.Time { return time.Time{} }
func (i fileInfo) IsDir() bool        { return i.dir }
func (i fileInfo) Sys() any           { return nil }
func (i fileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
