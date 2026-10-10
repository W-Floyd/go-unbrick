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
	partial string // why entries may not be all of them; "" when they are
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
		if infile.IsRemote(path) {
			return openRemoteTGZ(path)
		}
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
		if !isMember(hdr) {
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

// isMember reports a tar entry that is a package member: a regular file that is
// not a macOS sidecar.
func isMember(hdr *tar.Header) bool {
	return hdr.Typeflag == tar.TypeReg && !isAppleDouble(hdr.Name)
}

// Incomplete returns why path's listing may be missing members, or "" when
// it is complete or path is not an archive. Only a remote .tgz can be
// incomplete: its members are found by search under a fetch budget.
func Incomplete(path string) string {
	if !IsArchive(path) {
		return ""
	}
	a, err := openArchive(path)
	if err != nil {
		return ""
	}
	defer a.close()
	return a.partial
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
	if a.partial != "" {
		return "", nil, fmt.Errorf("%s: none of %v found in the archive (%s)", infile.Base(path), names, a.partial)
	}
	return "", nil, fmt.Errorf("%s: none of %v found in the archive", infile.Base(path), names)
}
