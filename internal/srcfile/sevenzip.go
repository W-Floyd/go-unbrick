package srcfile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bodgit/sevenzip"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/progress"
)

// spoolMax bounds how much a solid 7z is decoded to disk for random access.
const spoolMax = 8 << 30

// spoolCacheMax bounds all the kept spools together; the least recently used go
// first. A variable so a test can make it small.
var spoolCacheMax int64 = 16 << 30

// spoolDir is where decoded archives are kept between runs; "" for nowhere. A
// variable so a test can point it elsewhere.
var spoolDir = func() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "go-unbrick", "spool")
}

// nativeSevenZip finds a 7-Zip binary to decode with, "" if there is none. It
// decodes several times faster than the pure Go decoder; a variable so a test can
// turn it off.
var nativeSevenZip = func() string {
	for _, b := range []string{"7zz", "7z", "7zr", "7za"} {
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
	}
	return ""
}

// spool is a solid 7z decoded once, in archive order, into a file: a member of a
// solid block is otherwise decoded from the block's start on every read, seconds
// each for a browser that reads one per keystroke. The file is kept in the cache,
// so the archive is decoded once, not once per run.
type spool struct {
	once sync.Once
	name string // shown while it is built
	path string // the archive
	key  string // names the archive's identity: path, size and time
	f    *os.File
	offs []int64 // start of each regular member, by its index in the archive
	err  error
}

// spools is kept for the life of the process, so each archive is opened once
// however often it is read. The key names the file's identity, not its path.
var spools sync.Map

// spoolKey names an archive by where it is and what state it is in.
func spoolKey(path string, fi os.FileInfo) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d", path, fi.Size(), fi.ModTime().UnixNano())))
	return hex.EncodeToString(h[:12])
}

func (s *spool) build(files []*sevenzip.File) {
	s.once.Do(func() {
		var total int64
		for _, m := range files {
			s.offs = append(s.offs, total)
			total += int64(m.UncompressedSize)
		}
		dir := spoolDir()
		final := ""
		if dir != "" && s.key != "" {
			final = filepath.Join(dir, s.key+".bin")
			if st, err := os.Stat(final); err == nil && st.Size() == total {
				if f, err := os.Open(final); err == nil {
					now := time.Now()
					os.Chtimes(final, now, now) //nolint:errcheck // recency for eviction only
					s.f = f
					return
				}
			}
		}
		f, tmp, err := createSpool(dir, s.key, total)
		if err != nil {
			s.err = err
			return
		}
		task := progress.Begin("unpacking "+s.name, total)
		defer task.End()
		if !s.fill(f, files, total, task) {
			f.Close()
			if tmp != "" {
				os.Remove(tmp)
			}
			return
		}
		if tmp != "" && final != "" {
			if err := os.Rename(tmp, final); err == nil {
				f.Close()
				if f, err = os.Open(final); err != nil {
					s.err = err
					return
				}
			}
		}
		s.f = f
	})
}

// createSpool makes the file a spool is written into: in the cache, made room for;
// or, with no cache, an unlinked temp file that goes with the process.
func createSpool(dir, key string, total int64) (f *os.File, tmp string, err error) {
	if dir != "" && key != "" && os.MkdirAll(dir, 0o755) == nil {
		evictSpools(dir, total)
		if f, err = os.CreateTemp(dir, key+".tmp-*"); err == nil {
			return f, f.Name(), nil
		}
	}
	if f, err = os.CreateTemp("", "unbrick-7z-*"); err != nil {
		return nil, "", err
	}
	os.Remove(f.Name())
	return f, "", nil
}

// fill decodes the archive into f, natively if it can and checking what it got,
// else with the Go decoder. It sets s.err and returns false on failure.
func (s *spool) fill(f *os.File, files []*sevenzip.File, total int64, task *progress.Task) bool {
	if bin := nativeSevenZip(); bin != "" && s.path != "" {
		if s.fillNative(bin, f, files, total, task) {
			return true
		}
		// Whatever it did, the Go decoder starts again from nothing.
		if err := f.Truncate(0); err != nil {
			s.err = err
			return false
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			s.err = err
			return false
		}
		task.Reset()
	}
	for _, m := range files {
		rc, err := m.Open()
		if err != nil {
			s.err = err
			return false
		}
		_, err = io.Copy(countWriter{f, task}, rc)
		rc.Close()
		if err != nil {
			s.err = err
			return false
		}
	}
	return true
}

// fillNative has 7-Zip write every file's content to a pipe in archive order, and
// checks the result against what the archive's header says: the total, and each
// member's CRC. Anything that does not agree is not trusted.
func (s *spool) fillNative(bin string, f *os.File, files []*sevenzip.File, total int64, task *progress.Task) bool {
	cmd := exec.Command(bin, "e", "-so", "-y", "-bso0", "-bsp0", s.path)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return false
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	n, copyErr := io.Copy(countWriter{f, task}, out)
	waitErr := cmd.Wait()
	if copyErr != nil || waitErr != nil || n != total {
		return false
	}
	for i, m := range files {
		if m.UncompressedSize == 0 {
			continue
		}
		h := crc32.NewIEEE()
		if _, err := io.Copy(h, io.NewSectionReader(f, s.offs[i], int64(m.UncompressedSize))); err != nil || h.Sum32() != m.CRC32 {
			return false
		}
	}
	return true
}

// evictSpools makes room for need bytes under the cap by removing the least
// recently used spools, and any temporary file a run that died left behind.
func evictSpools(dir string, need int64) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type kept struct {
		path string
		size int64
		mod  time.Time
	}
	var all []kept
	var sum int64
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if strings.Contains(e.Name(), ".tmp-") {
			if time.Since(fi.ModTime()) > 24*time.Hour {
				os.Remove(p)
			}
			continue
		}
		if strings.HasSuffix(e.Name(), ".bin") {
			all = append(all, kept{p, fi.Size(), fi.ModTime()})
			sum += fi.Size()
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod.Before(all[j].mod) })
	for _, k := range all {
		if sum+need <= spoolCacheMax {
			return
		}
		if os.Remove(k.path) == nil {
			sum -= k.size
		}
	}
}

// spoolAt reads one member from the spool, building it on first use.
type spoolAt struct {
	sp    *spool
	files []*sevenzip.File
	i     int
	size  int64
}

func (a *spoolAt) ReadAt(p []byte, off int64) (int, error) {
	a.sp.build(a.files)
	if a.sp.err != nil {
		return 0, a.sp.err
	}
	if off >= a.size {
		return 0, io.EOF
	}
	return io.NewSectionReader(a.sp.f, a.sp.offs[a.i], a.size).ReadAt(p, off)
}

// openSevenZip indexes a 7z from its header.
func openSevenZip(path string) (*archive, error) {
	f, err := infile.Open(path)
	if err != nil {
		return nil, err
	}
	zr, err := sevenzip.NewReader(f, f.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	var files []*sevenzip.File
	var total uint64
	solid := false
	streams := map[int]bool{}
	for _, m := range zr.File {
		if m.FileInfo().IsDir() {
			continue
		}
		files = append(files, m)
		total += m.UncompressedSize
		if m.UncompressedSize > 0 {
			solid = solid || streams[m.Stream]
			streams[m.Stream] = true
		}
	}
	var sp *spool
	if solid && total <= spoolMax && !infile.IsRemote(path) {
		key := ""
		if fi, err := infile.Stat(path); err == nil {
			key = spoolKey(path, fi)
		}
		v, _ := spools.LoadOrStore(fmt.Sprintf("%s\x00%d", path, f.Size()), &spool{name: infile.Base(path), path: path, key: key})
		sp = v.(*spool)
	}
	a := &archive{close: f.Close}
	for i, m := range files {
		e := entry{name: m.Name, size: m.UncompressedSize, open: m.Open, crc: m.CRC32, hasCRC: true, modified: m.Modified}
		if sp != nil {
			at := &spoolAt{sp: sp, files: files, i: i, size: int64(m.UncompressedSize)}
			e.at = at
			e.open = func() (io.ReadCloser, error) {
				at.sp.build(at.files)
				if at.sp.err != nil {
					return nil, at.sp.err
				}
				return io.NopCloser(io.NewSectionReader(at.sp.f, at.sp.offs[at.i], at.size)), nil
			}
		}
		a.entries = append(a.entries, e)
	}
	return a, nil
}

// countWriter reports what it writes to a task.
type countWriter struct {
	w io.Writer
	t *progress.Task
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.t.Add(int64(n))
	return n, err
}
