//go:build cgo

package srcfile

import (
	"archive/tar"
	"io"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/rapidgzip"
)

// With cgo, a .tgz is decoded by rapidgzip: in parallel, building a seek index
// as it goes. Listing is one pass (tar.Reader seeks past member bodies, which
// rapidgzip decodes without handing them over), and from then on every member
// is a section of the decompressed stream that the index reaches directly. The
// decoder is kept for the life of the process, as the listing is.
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
	f, err := infile.Open(path)
	if err != nil {
		return nil, err
	}
	z, err := rapidgzip.NewReader(f, f.Size(), rapidgzip.Options{})
	if err != nil {
		f.Close()
		return nil, err
	}
	fail := func(err error) (*archive, error) {
		z.Close()
		f.Close()
		return nil, err
	}
	var es []entry
	tr := tar.NewReader(z)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
		if !isMember(hdr) {
			continue
		}
		off, err := z.Seek(0, io.SeekCurrent)
		if err != nil {
			return fail(err)
		}
		sr := io.NewSectionReader(z, off, hdr.Size)
		es = append(es, entry{name: hdr.Name, size: uint64(hdr.Size), at: sr,
			open: func() (io.ReadCloser, error) { return io.NopCloser(io.NewSectionReader(sr, 0, sr.Size())), nil }})
	}
	tgzCache.m[path] = es
	return &archive{entries: es, close: func() error { return nil }}, nil
}
