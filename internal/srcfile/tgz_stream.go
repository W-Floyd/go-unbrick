//go:build !cgo

package srcfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// Without cgo there is no rapidgzip, and a gzip stream can only be read from
// its start: a .tgz is indexed in one pass and remembered for the process —
// heads of every member, and the whole of each small one, which is all most
// callers ask for. A larger member re-streams the archive up to it.
const (
	tgzHead = 64 << 10
	tgzKeep = 8 << 20
)

var tgzCache = struct {
	sync.Mutex
	m map[string][]entry
}{m: map[string][]entry{}}

func openTGZ(path string) (*archive, error) {
	tgzCache.Lock()
	defer tgzCache.Unlock()
	if es, ok := tgzCache.m[path]; ok {
		return &archive{entries: es, close: func() error { return nil }}, nil
	}
	var es []entry
	err := streamTGZ(path, func(i int, hdr *tar.Header, r io.Reader) (bool, error) {
		e := entry{name: hdr.Name, size: uint64(hdr.Size)}
		if hdr.Size <= tgzKeep {
			data, err := io.ReadAll(r)
			if err != nil {
				return false, err
			}
			e.head = data[:min(len(data), tgzHead)]
			e.open = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
		} else {
			head := make([]byte, tgzHead)
			n, err := io.ReadFull(r, head)
			if err != nil && err != io.ErrUnexpectedEOF {
				return false, err
			}
			e.head = head[:n]
			e.open = func() (io.ReadCloser, error) { return restreamTGZ(path, i) }
		}
		es = append(es, e)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	tgzCache.m[path] = es
	return &archive{entries: es, close: func() error { return nil }}, nil
}

// streamTGZ walks the regular files of a .tgz in order, numbering them; fn
// returns false to stop.
func streamTGZ(path string, fn func(i int, hdr *tar.Header, r io.Reader) (bool, error)) error {
	f, err := infile.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for i := 0; ; {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if !isMember(hdr) {
			continue
		}
		more, err := fn(i, hdr, tr)
		if err != nil || !more {
			return err
		}
		i++
	}
}

// restreamTGZ returns member i of a .tgz, read through from the start.
func restreamTGZ(path string, i int) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(streamTGZ(path, func(j int, _ *tar.Header, r io.Reader) (bool, error) {
			if j < i {
				return true, nil
			}
			_, err := io.Copy(pw, r)
			return false, err
		}))
	}()
	return pr, nil
}
