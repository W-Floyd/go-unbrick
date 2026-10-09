// Package rapidgzip binds librapidarchive's ParallelGzipReader
// (third_party/librapidarchive, header-only C++17): parallel gzip decoding over
// any io.ReaderAt, and a seek index that can be exported once and imported
// later to seek without decoding what precedes the target.
//
// Without an index, a seek still decodes everything before the target, in
// parallel; an index is what makes later seeks cheap.
package rapidgzip

/*
#cgo CXXFLAGS: -std=c++17 -O2 -I${SRCDIR}/../../third_party/librapidarchive/src
#cgo darwin CXXFLAGS: -Wno-deprecated-literal-operator
#cgo LDFLAGS: -lz
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"runtime/cgo"
	"sync"
	"unsafe"
)

// Options tunes decoding. Zero values take the library defaults: one thread
// per core and 4 MiB chunks.
type Options struct {
	Parallelization int
	ChunkSize       int64
}

// Reader decompresses a gzip stream. It is an io.Reader, io.Seeker and
// io.ReaderAt; calls are serialized, since the underlying reader has one
// position.
type Reader struct {
	mu     sync.Mutex
	r      *C.rg_reader
	handle cgo.Handle
}

// NewReader opens the gzip stream in src, which is size bytes long.
func NewReader(src io.ReaderAt, size int64, opts Options) (*Reader, error) {
	h := cgo.NewHandle(src)
	var cerr *C.char
	r := C.rg_open(C.uintptr_t(h), C.uint64_t(size), C.size_t(opts.Parallelization), C.uint64_t(opts.ChunkSize), &cerr)
	if r == nil {
		h.Delete()
		msg := "rapidgzip: open failed"
		if cerr != nil {
			msg = "rapidgzip: " + C.GoString(cerr)
			C.free(unsafe.Pointer(cerr))
		}
		return nil, errors.New(msg)
	}
	return &Reader{r: r, handle: h}, nil
}

func (z *Reader) err(op string) error {
	return fmt.Errorf("rapidgzip: %s: %s", op, C.GoString(C.rg_error(z.r)))
}

// Close releases the decoder. src is no longer read after it returns.
func (z *Reader) Close() error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.r == nil {
		return nil
	}
	C.rg_close(z.r)
	z.r = nil
	z.handle.Delete()
	return nil
}

func (z *Reader) Read(p []byte) (int, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.read(p)
}

func (z *Reader) read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := C.rg_read(z.r, (*C.char)(unsafe.Pointer(&p[0])), C.size_t(len(p)))
	switch {
	case n < 0:
		return 0, z.err("read")
	case n == 0:
		return 0, io.EOF
	}
	return int(n), nil
}

func (z *Reader) Seek(offset int64, whence int) (int64, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.seek(offset, whence)
}

func (z *Reader) seek(offset int64, whence int) (int64, error) {
	n := C.rg_seek(z.r, C.longlong(offset), C.int(whence))
	if n < 0 {
		return 0, z.err("seek")
	}
	return int64(n), nil
}

// ReadAt reads decompressed bytes at off. It moves the shared position.
func (z *Reader) ReadAt(p []byte, off int64) (int, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if _, err := z.seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n := 0
	for n < len(p) {
		m, err := z.read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Size is the decompressed size, known once the whole stream has been seen or
// an index has been imported.
func (z *Reader) Size() (int64, bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	n := C.rg_size(z.r)
	return int64(n), n >= 0
}

// ExportIndex writes the seek index in indexed_gzip format. The index covers
// only what has been decoded, so export after reading to the end.
func (z *Reader) ExportIndex(w io.Writer) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	h := cgo.NewHandle(w)
	defer h.Delete()
	if C.rg_export_index(z.r, C.uintptr_t(h)) != 0 {
		return z.err("export index")
	}
	return nil
}

// ImportIndex loads a seek index previously written by ExportIndex (or by
// indexed_gzip or rapidgzip) from idx, which is size bytes long.
func (z *Reader) ImportIndex(idx io.ReaderAt, size int64) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	h := cgo.NewHandle(idx)
	defer h.Delete()
	if C.rg_import_index(z.r, C.uintptr_t(h), C.uint64_t(size)) != 0 {
		return z.err("import index")
	}
	return nil
}
