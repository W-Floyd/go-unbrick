// Package srcfile resolves a command's input to the bytes it needs, accepting
// the *least specific wrapping*: a stock firmware archive (.zip, .tar, .tgz), or
// the inner artifact itself. A command names the member(s) it wants (e.g.
// "radio.img"); if the path is an archive, srcfile finds the matching member,
// otherwise it returns the file as given. This lets every file operation take
// the whole stock package without each command re-implementing archive handling.
package srcfile

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/infile"
)

type kind int

const (
	notArchive kind = iota
	zipKind
	tarKind
	tgzKind
	sevenZipKind
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
	case bytes.HasPrefix(head, []byte("7z\xbc\xaf\x27\x1c")):
		return sevenZipKind
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
	name   string
	size   uint64
	head   []byte // prefilled when reading the head again would be costly (tgz)
	open   func() (io.ReadCloser, error)
	at     io.ReaderAt // the member at random, when its container allows; nil otherwise
	defl   *Deflated
	crc    uint32 // the zip directory's checksum, when hasCRC
	hasCRC bool
	// srcOff and srcLen are where the member's bytes sit in the archive file
	// (compressed, for a deflated zip member), when hasSrc.
	srcOff, srcLen int64
	hasSrc         bool
	modified       time.Time // when the archive records the member last changed; zero if not
	// srcFn and deflFn find what srcOff/srcLen and defl are, on demand, for an
	// archive where that costs a read per member (a zip).
	srcFn  func() (off, length int64, ok bool)
	deflFn func() *Deflated
}

// Deflated locates a member stored as a raw deflate stream, for a reader
// that enters it mid-stream (tgzseek) rather than decoding from the start.
type Deflated struct {
	R          io.ReaderAt
	Start, End int64 // byte range of the stream in R
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
			e := entry{name: f.Name, size: f.UncompressedSize64, open: f.Open, crc: f.CRC32, hasCRC: true, modified: f.Modified}
			// Where a member's data starts is in its local header: a read of its own,
			// which for a few hundred members of an APK read through a slow source (a
			// file inside a compressed filesystem) is most of the time of listing it.
			// So it is found when a member is read, not for every member up front.
			// (A remote archive keeps looking up front: its headers are fetched into the
			// chunk cache ahead of any member being streamed, which is what keeps a
			// member's fetch to its own bytes.)
			lo := &lazyOffset{f: f}
			in := zr.Input()
			if infile.IsRemote(path) {
				lo.get()
			}
			e.srcFn = func() (int64, int64, bool) {
				off, ok := lo.get()
				return off, int64(f.CompressedSize64), ok
			}
			switch f.Method {
			case zip.Store:
				e.at = &lazyAt{lo: lo, ra: in, size: int64(f.UncompressedSize64)}
			case zip.Deflate:
				e.deflFn = func() *Deflated {
					off, ok := lo.get()
					if !ok {
						return nil
					}
					return &Deflated{R: in, Start: off, End: off + int64(f.CompressedSize64)}
				}
			}
			a.entries = append(a.entries, e)
		}
		return a, nil
	case sevenZipKind:
		return openSevenZip(path)
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
		a.entries = append(a.entries, entry{name: filepath.ToSlash(filepath.Clean(hdr.Name)), size: uint64(hdr.Size), at: sr,
			srcOff: off, srcLen: hdr.Size, hasSrc: true, modified: hdr.ModTime, // "./x" would never match a cleaned lookup path
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
	out := make([]Member, len(a.entries))
	// Concurrently: over HTTP each head is a round trip, and a package can
	// have a hundred members.
	var wg sync.WaitGroup
	sem := make(chan struct{}, headReaders)
	for i, e := range a.entries {
		out[i] = Member{Name: e.name, Size: e.size}
		if headLen <= 0 {
			continue // names and sizes only: opening each member would decode it for nothing
		}
		if e.head != nil {
			out[i].Head = e.head[:min(len(e.head), headLen)]
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			if rc, err := e.open(); err == nil {
				head := make([]byte, headLen)
				n, _ := io.ReadFull(rc, head)
				out[i].Head = head[:n]
				rc.Close()
			}
		}()
	}
	wg.Wait()
	return out, nil
}

// headReaders bounds the member heads read at once.
const headReaders = 8

// Entry is an archive member as a walker of nested containers needs it.
type Entry struct {
	Name string
	Size uint64
	Open func() (io.ReadCloser, error)
	// At reads the member at random without decoding what precedes it: a tar
	// member, a stored zip member, a .tgz member under rapidgzip. Nil when the
	// member can only be streamed.
	At io.ReaderAt
	// Deflate is set for a deflated zip member.
	Deflate *Deflated
	// CRC32 is the checksum the zip directory states for the member, valid
	// when HasCRC.
	CRC32  uint32
	HasCRC bool
	// SrcOff and SrcLen are where the member's bytes sit in the archive file
	// (compressed, for a deflated zip member), when HasSrc.
	SrcOff, SrcLen int64
	HasSrc         bool
	// Modified is when the archive records the member last changed; zero if not.
	Modified time.Time
	// SrcFn and DeflateFn are SrcOff/SrcLen and Deflate found on demand, for an archive
	// where that costs a read per member (a zip): nil when the fields above are set.
	SrcFn     func() (off, length int64, ok bool)
	DeflateFn func() *Deflated
}

// Entries lists path's members for reading, which stays possible until close.
// It returns nil (no error) when path is not an archive.
func Entries(path string) ([]Entry, io.Closer, error) {
	if !IsArchive(path) {
		return nil, nil, nil
	}
	a, err := openArchive(path)
	if err != nil {
		return nil, nil, err
	}
	out := make([]Entry, 0, len(a.entries))
	for _, e := range a.entries {
		out = append(out, Entry{Name: e.name, Size: e.size, Open: e.open, At: e.at, Deflate: e.defl, CRC32: e.crc, HasCRC: e.hasCRC,
			SrcOff: e.srcOff, SrcLen: e.srcLen, HasSrc: e.hasSrc, Modified: e.modified, SrcFn: e.srcFn, DeflateFn: e.deflFn})
	}
	return out, closerFunc(a.close), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// Names lists path's member names without reading any member, so it is cheap
// however many there are. nil (no error) when path is not an archive.
func Names(path string) ([]string, error) {
	if !IsArchive(path) {
		return nil, nil
	}
	a, err := openArchive(path)
	if err != nil {
		return nil, err
	}
	defer a.close()
	out := make([]string, len(a.entries))
	for i, e := range a.entries {
		out[i] = e.name
	}
	return out, nil
}

// sourceTreeMin is how many members make an archive a source tree rather than a
// firmware package, which holds tens of images.
const sourceTreeMin = 2000

var sourceExts = map[string]bool{
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".hh": true, ".hpp": true, ".cxx": true,
	".S": true, ".s": true, ".py": true, ".js": true, ".java": true, ".kt": true, ".rs": true,
	".go": true, ".sh": true, ".txt": true, ".html": true, ".css": true, ".json": true,
	".xml": true, ".dts": true, ".dtsi": true, ".mk": true, ".cmake": true, ".md": true,
}

// IsSourceTree says names are a source release: thousands of members, mostly
// source files. Reading each member of one for firmware facts finds nothing and
// costs a directory parse per member.
func IsSourceTree(names []string) bool {
	if len(names) < sourceTreeMin {
		return false
	}
	src := 0
	for _, n := range names {
		if i := strings.LastIndexByte(n, '.'); i >= 0 && sourceExts[n[i:]] {
			src++
		}
	}
	return src*2 > len(names)
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

// lazyOffset finds where a zip member's data starts, once, when first asked.
type lazyOffset struct {
	f    *zip.File
	once sync.Once
	off  int64
	ok   bool
}

func (l *lazyOffset) get() (int64, bool) {
	l.once.Do(func() {
		off, err := l.f.DataOffset()
		l.off, l.ok = off, err == nil
	})
	return l.off, l.ok
}

// lazyAt reads a stored zip member at random, finding where its data starts on
// first use.
type lazyAt struct {
	lo   *lazyOffset
	ra   io.ReaderAt
	size int64
}

func (a *lazyAt) ReadAt(p []byte, off int64) (int, error) {
	start, ok := a.lo.get()
	if !ok {
		return 0, fmt.Errorf("srcfile: no data offset for %s", a.lo.f.Name)
	}
	return io.NewSectionReader(a.ra, start, a.size).ReadAt(p, off)
}
