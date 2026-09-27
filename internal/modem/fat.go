package modem

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/diskfs/go-diskfs/backend"
	"github.com/diskfs/go-diskfs/filesystem/fat12"
	"github.com/diskfs/go-diskfs/filesystem/fat16"
	"github.com/diskfs/go-diskfs/filesystem/fat32"
)

// Qualcomm reference builds (Xiaomi, Samsung, …) ship NON-HLOS and BTFM as FAT
// images rather than ext4.

func isFAT(b []byte) bool {
	if len(b) < 512 || b[510] != 0x55 || b[511] != 0xaa {
		return false
	}
	return string(b[0x36:0x39]) == "FAT" || string(b[0x52:0x57]) == "FAT32"
}

type fatFS interface {
	ReadDir(p string) ([]iofs.DirEntry, error)
	Open(name string) (iofs.File, error)
}

// openFAT tries each variant; each Read rejects the others' boot sectors.
func openFAT(raw []byte) (fatFS, error) {
	st := memStorage{bytes.NewReader(raw)}
	size := int64(len(raw))
	if fs, err := fat32.Read(st, size, 0, 0); err == nil {
		return fs, nil
	}
	if fs, err := fat16.Read(st, size, 0, 0); err == nil {
		return fs, nil
	}
	fs, err := fat12.Read(st, size, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("modem: unreadable FAT filesystem: %w", err)
	}
	return fs, nil
}

func fatWalk(fs fatFS, dir string, depth int, visit func(p string, e iofs.DirEntry)) error {
	if depth > 32 {
		return nil
	}
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		if e.IsDir() {
			if err := fatWalk(fs, p, depth+1, visit); err != nil {
				return err
			}
			continue
		}
		visit(p, e)
	}
	return nil
}

func fatList(raw []byte) ([]Entry, error) {
	fs, err := openFAT(raw)
	if err != nil {
		return nil, err
	}
	var out []Entry
	err = fatWalk(fs, ".", 0, func(p string, e iofs.DirEntry) {
		var size uint64
		if fi, err := e.Info(); err == nil {
			size = uint64(fi.Size())
		}
		out = append(out, Entry{Path: p, Size: size})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// fatExtract matches like Extract, but case-insensitively, as FAT itself does.
func fatExtract(raw []byte, name string) ([]byte, error) {
	fs, err := openFAT(raw)
	if err != nil {
		return nil, err
	}
	n := strings.ToLower(strings.TrimPrefix(name, "/"))
	var matches []string
	err = fatWalk(fs, ".", 0, func(p string, _ iofs.DirEntry) {
		lp := strings.ToLower(p)
		if lp == n || strings.HasSuffix(lp, "/"+n) {
			matches = append(matches, p)
		}
	})
	if err != nil {
		return nil, err
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("modem: %q: %w", name, ErrNotFound)
	case 1:
		return fatReadFile(fs, matches[0])
	}
	return nil, fmt.Errorf("modem: %q is ambiguous (%s and %s); use a full path", name, matches[0], matches[1])
}

// fatReadFile reads a whole file in one Read from offset 0. go-diskfs v1.9.4's
// File.Read bounds a read resuming mid-cluster by the buffer rather than the
// file size, so io.ReadAll's small first read makes it return cluster slack.
func fatReadFile(fs fatFS, p string) ([]byte, error) {
	f, err := fs.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	b := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, b); err != nil && !(err == io.EOF && len(b) == 0) {
		return nil, err
	}
	return b, nil
}

// memStorage is a read-only backend.Storage over an in-memory image.
type memStorage struct{ *bytes.Reader }

var errReadOnly = errors.New("modem: in-memory image is read-only")

func (m memStorage) Stat() (iofs.FileInfo, error)            { return memInfo(m.Size()), nil }
func (m memStorage) Close() error                            { return nil }
func (m memStorage) Sys() (*os.File, error)                  { return nil, backend.ErrNotSuitable }
func (m memStorage) Writable() (backend.WritableFile, error) { return nil, errReadOnly }
func (m memStorage) Path() string                            { return "" }

type memInfo int64

func (s memInfo) Name() string        { return "image" }
func (s memInfo) Size() int64         { return int64(s) }
func (s memInfo) Mode() iofs.FileMode { return 0o444 }
func (s memInfo) ModTime() time.Time  { return time.Time{} }
func (s memInfo) IsDir() bool         { return false }
func (s memInfo) Sys() any            { return nil }
