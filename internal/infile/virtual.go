package infile

import (
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"
)

// Virtual files: a member of a container presented as an input path, so code that
// takes a path (recon) can be run on it without writing it to disk first. The path
// is "virtual:<n>/<name>": the name keeps its extension, which decides how some
// inputs are read, and Base gives it back.

const virtualPrefix = "virtual:"

type virtualFile struct {
	name string
	at   io.ReaderAt
	size int64
	id   string
}

var virtuals = struct {
	sync.Mutex
	next int
	m    map[string]*virtualFile
}{m: map[string]*virtualFile{}}

// IsVirtual reports whether p names a file made by RegisterVirtual.
func IsVirtual(p string) bool { return strings.HasPrefix(p, virtualPrefix) }

// RegisterVirtual makes a path for bytes that read at random: name is what Base
// gives for it, id what Identity gives (names the content for caches; "" disables
// caching). release forgets it; use it when the work on the path is done.
func RegisterVirtual(name string, at io.ReaderAt, size int64, id string) (path string, release func()) {
	virtuals.Lock()
	defer virtuals.Unlock()
	virtuals.next++
	path = fmt.Sprintf("%s%d/%s", virtualPrefix, virtuals.next, name)
	virtuals.m[path] = &virtualFile{name: name, at: at, size: size, id: id}
	return path, func() {
		virtuals.Lock()
		delete(virtuals.m, path)
		virtuals.Unlock()
	}
}

func lookupVirtual(p string) (*virtualFile, bool) {
	virtuals.Lock()
	defer virtuals.Unlock()
	v, ok := virtuals.m[p]
	return v, ok
}

func openVirtual(p string) (*File, error) {
	v, ok := lookupVirtual(p)
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	return &File{SectionReader: io.NewSectionReader(v.at, 0, v.size), name: p}, nil
}

func statVirtual(p string) (fs.FileInfo, error) {
	v, ok := lookupVirtual(p)
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
	}
	return remoteInfo{name: v.name, size: v.size, mod: time.Time{}}, nil
}
