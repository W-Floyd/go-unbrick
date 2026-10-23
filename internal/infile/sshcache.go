package infile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
)

// SSHCacheDir overrides the disk cache root for ssh:// blocks; "" means
// <UserCacheDir>/go-unbrick/ssh. Unlike the in-process block cache in
// sshfile.go (which dies with the process), this survives it: a recon that
// walks the same remote file across many separate command invocations - as
// browsing a big decrypted image does, one "unbrick ls"/"extract" at a time -
// fetches each block once, not once per invocation.
var SSHCacheDir string

func sshCacheRoot() (string, error) {
	if SSHCacheDir != "" {
		return SSHCacheDir, nil
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "go-unbrick", "ssh"), nil
}

// sshDisk is one remote file's on-disk block cache: a sparse data file plus a
// one-byte-per-block presence map, the same shape as the http(s) cache in
// remote.go. Keyed by path + size + mtime, so a changed file (or a
// never-fetchable one, SSHCacheDir unset and no user cache dir) is never
// confused with an old entry rather than simply going uncached.
type sshDisk struct {
	data *os.File
	have *os.File
	got  []atomic.Bool
	size int64
}

// openSSHDisk opens (or creates) the disk cache entry for p, whose current
// identity is size/modNS (mtime as UnixNano). Returns nil, err when caching
// is unavailable; callers treat that as "no disk cache", not a hard failure.
func openSSHDisk(p string, size, modNS int64) (*sshDisk, error) {
	root, err := sshCacheRoot()
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(sshCacheKey(p, size, modNS))
	dir := filepath.Join(root, hex.EncodeToString(key[:]))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	data, err := os.OpenFile(filepath.Join(dir, "data"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := data.Truncate(size); err != nil { // sparse; unfetched blocks cost no disk
		data.Close()
		return nil, err
	}
	have, err := os.OpenFile(filepath.Join(dir, "chunks"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		data.Close()
		return nil, err
	}
	n := int((size + blockSize - 1) / blockSize)
	bits := make([]byte, n)
	if _, err := have.ReadAt(bits, 0); err != nil && !errors.Is(err, io.EOF) {
		data.Close()
		have.Close()
		return nil, err
	}
	got := make([]atomic.Bool, n)
	for i, b := range bits {
		got[i].Store(b == 1)
	}
	return &sshDisk{data: data, have: have, got: got, size: size}, nil
}

func sshCacheKey(p string, size, modNS int64) []byte {
	return []byte(fmt.Sprintf("%s|%d|%d", p, size, modNS))
}

// read returns block i, if the cache has it.
func (d *sshDisk) read(i int64) ([]byte, bool) {
	if d == nil || i < 0 || int(i) >= len(d.got) || !d.got[i].Load() {
		return nil, false
	}
	n := min(int64(blockSize), d.size-i*blockSize)
	buf := make([]byte, n)
	if _, err := d.data.ReadAt(buf, i*blockSize); err != nil {
		return nil, false
	}
	return buf, true
}

// diskHit returns blocks lo..hi from d if every one of them is cached; a
// partial hit still has to fetch the whole span over the network (today's
// behavior), so it is reported as a miss rather than read block by block.
func diskHit(d *sshDisk, lo, hi int64) ([][]byte, bool) {
	out := make([][]byte, hi-lo+1)
	for i := lo; i <= hi; i++ {
		b, ok := d.read(i)
		if !ok {
			return nil, false
		}
		out[i-lo] = b
	}
	return out, true
}

// write stores block i, unless it is already cached.
func (d *sshDisk) write(i int64, b []byte) {
	if d == nil || i < 0 || int(i) >= len(d.got) || d.got[i].Load() {
		return
	}
	if _, err := d.data.WriteAt(b, i*blockSize); err != nil {
		return
	}
	_, _ = d.have.WriteAt([]byte{1}, i)
	d.got[i].Store(true)
}
