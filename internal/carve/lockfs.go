package carve

import (
	"io"
	"io/fs"
	"sync"
)

// lockedFS makes a filesystem safe to use from more than one goroutine at once.
// The readers behind them are not: go-ext4, for one, seeks a single reader and
// then reads it, so two reads at once return each other's blocks. A viewer reads
// files while a comparison is still reading others, so every use of one
// filesystem takes the same lock. It is held for a whole call, network reads
// included, so concurrent users wait their turn rather than corrupt each other.
type lockedFS struct {
	inner fs.FS
	mu    sync.Mutex
	// oa is the filesystem's way of handing out a file read at random, if it has one.
	oa interface{ OpenAt(string) io.ReaderAt }
}

func lockFS(inner fs.FS) *lockedFS {
	l := &lockedFS{inner: inner}
	l.oa, _ = inner.(interface{ OpenAt(string) io.ReaderAt })
	return l
}

func (l *lockedFS) Open(name string) (fs.File, error) {
	l.mu.Lock()
	f, err := l.inner.Open(name)
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &lockedFile{File: f, mu: &l.mu}, nil
}

func (l *lockedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return fs.ReadDir(l.inner, name)
}

func (l *lockedFS) Stat(name string) (fs.FileInfo, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return fs.Stat(l.inner, name)
}

// openAt is the inner filesystem's random-access file, read under the lock.
func (l *lockedFS) openAt(name string) io.ReaderAt {
	return &lockedAt{inner: l.oa.OpenAt(name), mu: &l.mu}
}

type lockedFile struct {
	fs.File
	mu *sync.Mutex
}

func (f *lockedFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.File.Read(p)
}

type lockedAt struct {
	inner io.ReaderAt
	mu    *sync.Mutex
}

func (a *lockedAt) ReadAt(p []byte, off int64) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inner.ReadAt(p, off)
}
