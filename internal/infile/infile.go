// Package infile opens a command's input path, which is either a local file or
// an http(s) URL. A URL is read with range requests through a persistent chunk
// cache (see remote.go), so inspecting a multi-GB package costs only the bytes
// actually read — the zip directory, a few member heads, a payload manifest —
// and re-running costs nothing. The API mirrors the os/zip calls it replaces, so
// a call site swaps os.Stat → infile.Stat, zip.OpenReader → infile.OpenZip.
package infile

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/hashcache"
	"github.com/W-Floyd/go-unbrick/internal/progress"
)

// IsRemote reports whether p names an http(s) or ssh:// URL rather than a local path.
func IsRemote(p string) bool {
	return isHTTP(p) || IsSSH(p)
}

func isHTTP(p string) bool {
	return strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://")
}

// Base is filepath.Base for a local path; for a URL it is the unescaped last
// path element, ignoring any query string (signed CDN links carry long ones),
// or, once the URL is open, the name the server gave it.
func Base(p string) string {
	if v, ok := lookupVirtual(p); ok {
		return path.Base(v.name)
	}
	if !IsRemote(p) {
		return filepath.Base(p)
	}
	if n, ok := filenames.Load(p); ok {
		return n.(string)
	}
	u, err := url.Parse(p)
	if err != nil {
		return filepath.Base(p)
	}
	return path.Base(u.Path)
}

// File is an open input: random access, sequential reads, and its size.
type File struct {
	*io.SectionReader
	name   string
	closer io.Closer
}

func (f *File) Name() string { return f.name }

func (f *File) Close() error {
	if f.closer == nil {
		return nil
	}
	return f.closer.Close()
}

// Open opens p for reading. A remote File is backed by the shared per-URL cache,
// so opening the same URL repeatedly costs one validation request per process.
func Open(p string) (*File, error) {
	if IsVirtual(p) {
		return openVirtual(p)
	}
	if IsSSH(p) {
		return openSSH(p)
	}
	if IsRemote(p) {
		r, err := openRemote(p)
		if err != nil {
			return nil, err
		}
		return &File{SectionReader: io.NewSectionReader(r, 0, r.size), name: p}, nil
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &File{SectionReader: io.NewSectionReader(f, 0, fi.Size()), name: p, closer: f}, nil
}

// Stat is os.Stat; an http URL is never a directory.
func Stat(p string) (fs.FileInfo, error) {
	if IsVirtual(p) {
		return statVirtual(p)
	}
	if IsSSH(p) {
		return statSSH(p)
	}
	if !IsRemote(p) {
		return os.Stat(p)
	}
	r, err := openRemote(p)
	if err != nil {
		return nil, err
	}
	return remoteInfo{name: Base(p), size: r.size, mod: r.meta.modTime()}, nil
}

// MaxRemoteRead bounds ReadFile over a URL. Callers that slurp their input are
// sized for a local disk; over the network the same call is a full download.
var MaxRemoteRead int64 = 256 << 20

// ReadFile is os.ReadFile, refusing a URL larger than MaxRemoteRead.
func ReadFile(p string) ([]byte, error) {
	if IsVirtual(p) {
		f, err := openVirtual(p)
		if err != nil {
			return nil, err
		}
		b := make([]byte, f.Size())
		if _, err := f.ReadAt(b, 0); err != nil && err != io.EOF {
			return nil, err
		}
		recordDigest(p, b)
		return b, nil
	}
	if !IsRemote(p) {
		b, err := os.ReadFile(p)
		if err == nil {
			recordDigest(p, b)
		}
		return b, err
	}
	f, err := Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Size() > MaxRemoteRead && !FullDownload {
		return nil, fmt.Errorf("%s: %d bytes is too large to fetch whole", Base(p), f.Size())
	}
	b := make([]byte, f.Size())
	task := progress.Begin("downloading "+Base(p), f.Size())
	defer task.End()
	const step = 4 << 20
	for off := 0; off < len(b); off += step {
		end := min(off+step, len(b))
		if _, err := f.ReadAt(b[off:end], int64(off)); err != nil && err != io.EOF {
			return nil, err
		}
		task.Add(int64(end - off))
	}
	recordDigest(p, b)
	return b, nil
}

// recordDigest opportunistically remembers b's sha256 under p's Identity, in
// hashcache, keyed the same way digests already are elsewhere (see
// pkg/analysis's cacheKey): so a later caller — this recon's own cache key
// builder, a diff, anything that asks hashcache first — inherits it, even for
// an unrelated path whose content turns out to be byte-identical (the same
// partition image shared across two firmware packages, under the same name or
// a different one). Cheap: ReadFile just paid for these bytes anyway, sha256
// over what's already in memory is small next to that.
//
// hashcache.Put also indexes the sum by size alone (GetBySize), a cheap
// stat-only signal a later, unrelated path can use to decide it's worth
// reading and hashing on the strength of that alone -- see
// contentOrPathIdentity's use of it.
func recordDigest(p string, b []byte) {
	id := Identity(p)
	if id == "" {
		return
	}
	key := id + "\x00sha256"
	size := int64(len(b))
	if _, ok := hashcache.Get(key, size, false); ok {
		return
	}
	digest := sha256.Sum256(b)
	hashcache.Put(key, size, hex.EncodeToString(digest[:]), false)
}

// ZipReader is a zip.ReadCloser over any input.
type ZipReader struct {
	*zip.Reader
	f *File
}

func (z *ZipReader) Close() error { return z.f.Close() }

// Input is what the zip is read from, for reading a stored member in place.
func (z *ZipReader) Input() *File { return z.f }

// OpenZip is zip.OpenReader. Over a URL only the end-of-central-directory and
// the directory itself are fetched; members are fetched as they are read.
func OpenZip(p string) (*ZipReader, error) {
	f, err := Open(p)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(f, f.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	return &ZipReader{Reader: zr, f: f}, nil
}

type remoteInfo struct {
	name string
	size int64
	mod  time.Time
}

func (i remoteInfo) Name() string       { return i.name }
func (i remoteInfo) Size() int64        { return i.size }
func (i remoteInfo) Mode() fs.FileMode  { return 0o444 }
func (i remoteInfo) ModTime() time.Time { return i.mod }
func (i remoteInfo) IsDir() bool        { return false }
func (i remoteInfo) Sys() any           { return nil }
