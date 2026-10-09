// Package srcfile resolves a command's input to the bytes it needs, accepting
// the *least specific wrapping*: a stock firmware archive (.zip, .tar, .tgz), or
// the inner artifact itself. A command names the member(s) it wants (e.g.
// "radio.img"); if the path is an archive, srcfile finds the matching member,
// otherwise it returns the file as given. This lets every file operation take
// the whole stock package without each command re-implementing archive handling.
package srcfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/infile"
)

type kind int

const (
	notArchive kind = iota
	zipKind
	tarKind
	tgzKind
)

// kindOf sniffs the container format from content, not the extension.
func kindOf(path string) kind {
	f, err := infile.Open(path)
	if err != nil {
		return notArchive
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		return zipKind
	case isTarHeader(head):
		return tarKind
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(io.NewSectionReader(f, 0, f.Size()))
		if err != nil {
			return notArchive
		}
		inner := make([]byte, 512)
		n, _ := io.ReadFull(gz, inner)
		if isTarHeader(inner[:n]) {
			return tgzKind
		}
	}
	return notArchive
}

// isAppleDouble reports a "._name" resource-fork sidecar, which macOS tar adds
// beside every file it archives; it is never firmware.
func isAppleDouble(name string) bool {
	return strings.HasPrefix(filepath.Base(name), "._")
}

// isTarHeader checks the ustar magic at offset 257 of the first header block.
func isTarHeader(b []byte) bool {
	return len(b) >= 262 && bytes.Equal(b[257:262], []byte("ustar"))
}

// IsZip reports whether path is a zip.
func IsZip(path string) bool { return kindOf(path) == zipKind }

// IsArchive reports whether path is a container srcfile can look inside.
func IsArchive(path string) bool { return kindOf(path) != notArchive }

// Member is an archive entry with a small head sample for format detection.
type Member struct {
	Name string
	Size uint64
	Head []byte
}

// entry is one regular file in an archive, however the archive stores it.
type entry struct {
	name string
	size uint64
	head []byte // prefilled when reading the head again would be costly (tgz)
	open func() (io.ReadCloser, error)
}

type archive struct {
	entries []entry
	close   func() error
}

func openArchive(path string) (*archive, error) {
	switch kindOf(path) {
	case zipKind:
		zr, err := infile.OpenZip(path)
		if err != nil {
			return nil, err
		}
		a := &archive{close: zr.Close}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			a.entries = append(a.entries, entry{name: f.Name, size: f.UncompressedSize64, open: f.Open})
		}
		return a, nil
	case tarKind:
		return openTar(path)
	case tgzKind:
		return openTGZ(path)
	}
	return nil, fmt.Errorf("%s: not an archive", infile.Base(path))
}

// openTar indexes an uncompressed tar. tar.Reader seeks past member bodies, so
// listing costs only the headers — over HTTP too — and each member is then a
// section of the file.
func openTar(path string) (*archive, error) {
	f, err := infile.Open(path)
	if err != nil {
		return nil, err
	}
	a := &archive{close: f.Close}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return a, nil
		}
		if err != nil {
			f.Close()
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || isAppleDouble(hdr.Name) {
			continue
		}
		off, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			f.Close()
			return nil, err
		}
		sr := io.NewSectionReader(f, off, hdr.Size)
		a.entries = append(a.entries, entry{name: hdr.Name, size: uint64(hdr.Size),
			open: func() (io.ReadCloser, error) { return io.NopCloser(io.NewSectionReader(sr, 0, sr.Size())), nil }})
	}
}

// A gzip stream can only be read from its start, so a .tgz is indexed in one
// pass and remembered for the process: heads of every member, and the whole of
// each small one, which is all most callers ask for. A larger member re-streams
// the archive up to it.
const (
	tgzHead = 64 << 10
	tgzKeep = 8 << 20
)

var tgzCache = struct {
	sync.Mutex
	m map[string][]entry
}{m: map[string][]entry{}}

func openTGZ(path string) (*archive, error) {
	if infile.IsRemote(path) {
		return nil, fmt.Errorf("%s: a compressed tar cannot be read by range; reading it would mean fetching all of it", infile.Base(path))
	}
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
		if hdr.Typeflag != tar.TypeReg || isAppleDouble(hdr.Name) {
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

// Members lists an archive's files, each with up to headLen bytes for
// magic-based typing. Cheap even for a huge package: only the head of each
// member is read. Returns nil (no error) when path is not an archive.
func Members(path string, headLen int) ([]Member, error) {
	if !IsArchive(path) {
		return nil, nil
	}
	a, err := openArchive(path)
	if err != nil {
		return nil, err
	}
	defer a.close()
	out := make([]Member, 0, len(a.entries))
	for _, e := range a.entries {
		m := Member{Name: e.name, Size: e.size}
		if e.head != nil {
			m.Head = e.head[:min(len(e.head), headLen)]
		} else if rc, err := e.open(); err == nil {
			head := make([]byte, headLen)
			n, _ := io.ReadFull(rc, head)
			m.Head = head[:n]
			rc.Close()
		}
		out = append(out, m)
	}
	return out, nil
}

// Glob returns the base names of members whose base name matches pattern
// (filepath.Match syntax), in archive order. It returns nil (no error) when path
// is not an archive, so a caller can fall back to treating path as the artifact
// itself.
func Glob(path, pattern string) ([]string, error) {
	if !IsArchive(path) {
		return nil, nil
	}
	a, err := openArchive(path)
	if err != nil {
		return nil, err
	}
	defer a.close()
	var out []string
	for _, e := range a.entries {
		base := filepath.Base(e.name)
		if ok, _ := filepath.Match(pattern, base); ok {
			out = append(out, base)
		}
	}
	return out, nil
}

// Open returns the wanted artifact from path. If path is an archive, it returns
// the first member whose base name case-insensitively equals one of names, tried
// in priority order; an archive that has none is an error listing what was
// sought. If path is not an archive, its own bytes are returned (the caller
// passed the artifact directly) and names are ignored. member is the chosen
// member's name.
func Open(path string, names ...string) (member string, data []byte, err error) {
	if !IsArchive(path) {
		data, err = infile.ReadFile(path)
		return infile.Base(path), data, err
	}
	a, err := openArchive(path)
	if err != nil {
		return "", nil, err
	}
	defer a.close()
	for _, want := range names {
		for _, e := range a.entries {
			if strings.EqualFold(filepath.Base(e.name), want) {
				rc, err := e.open()
				if err != nil {
					return "", nil, err
				}
				defer rc.Close()
				b, err := io.ReadAll(rc)
				return e.name, b, err
			}
		}
	}
	return "", nil, fmt.Errorf("%s: none of %v found in the archive", infile.Base(path), names)
}
