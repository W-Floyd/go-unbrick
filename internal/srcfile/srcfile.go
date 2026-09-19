// Package srcfile resolves a command's input to the bytes it needs, accepting
// the *least specific wrapping*: a stock firmware .zip, or the inner artifact
// itself. A command names the member(s) it wants (e.g. "radio.img"); if the path
// is a zip, srcfile finds the matching member, otherwise it returns the file as
// given. This lets every file operation take the whole stock zip without each
// command re-implementing zip handling.
package srcfile

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// zipMagic is the local-file-header signature "PK\x03\x04".
var zipMagic = []byte{'P', 'K', 0x03, 0x04}

// IsZip reports whether path begins with the zip signature.
func IsZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [4]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return false
	}
	return string(b[:]) == string(zipMagic)
}

// Member is a zip entry with a small head sample for format detection.
type Member struct {
	Name string
	Size uint64
	Head []byte
}

// Members lists a zip's entries, each with up to headLen bytes decompressed for
// magic-based typing. Cheap even for a huge zip: only the head of each entry is
// read. Returns nil (no error) when path is not a zip.
func Members(path string, headLen int) ([]Member, error) {
	if !IsZip(path) {
		return nil, nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := make([]Member, 0, len(zr.File))
	for _, f := range zr.File {
		m := Member{Name: f.Name, Size: f.UncompressedSize64}
		if rc, err := f.Open(); err == nil {
			head := make([]byte, headLen)
			n, _ := io.ReadFull(rc, head)
			m.Head = head[:n]
			rc.Close()
		}
		out = append(out, m)
	}
	return out, nil
}

// Glob returns the base names of zip members whose base name matches pattern
// (filepath.Match syntax), in archive order. It returns nil (no error) when path
// is not a zip, so a caller can fall back to treating path as the artifact itself.
func Glob(path, pattern string) ([]string, error) {
	if !IsZip(path) {
		return nil, nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var out []string
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if ok, _ := filepath.Match(pattern, base); ok {
			out = append(out, base)
		}
	}
	return out, nil
}

// Open returns the wanted artifact from path. If path is a zip, it returns the
// first member whose base name case-insensitively equals one of names, tried in
// priority order; a zip that has none is an error listing what was sought. If
// path is not a zip, its own bytes are returned (the caller passed the artifact
// directly) and names are ignored. member is the chosen base name.
func Open(path string, names ...string) (member string, data []byte, err error) {
	if !IsZip(path) {
		data, err = os.ReadFile(path)
		return filepath.Base(path), data, err
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", nil, err
	}
	defer zr.Close()
	// Priority order: first name that any member matches wins.
	for _, want := range names {
		for _, f := range zr.File {
			if strings.EqualFold(filepath.Base(f.Name), want) {
				rc, err := f.Open()
				if err != nil {
					return "", nil, err
				}
				defer rc.Close()
				b, err := io.ReadAll(rc)
				return f.Name, b, err
			}
		}
	}
	return "", nil, fmt.Errorf("%s: none of %v found in the zip", filepath.Base(path), names)
}
