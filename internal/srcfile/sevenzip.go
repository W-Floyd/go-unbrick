package srcfile

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bodgit/sevenzip"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/progress"
)

// spoolMax bounds how much a solid 7z is decoded to disk for random access.
const spoolMax = 8 << 30

// spool is a solid 7z decoded once, in archive order, into an unlinked temp
// file: a member of a solid block is otherwise decoded from the block's start
// on every read, seconds each for a browser that reads one per keystroke.
type spool struct {
	once sync.Once
	name string // shown while it is built
	f    *os.File
	offs []int64 // start of each regular member, by its index in the archive
	err  error
}

// spools is kept for the life of the process, so each archive is decoded once
// however often it is opened. The key names the file's identity, not its path.
var spools sync.Map

func (s *spool) build(files []*sevenzip.File) {
	s.once.Do(func() {
		f, err := os.CreateTemp("", "unbrick-7z-*")
		if err != nil {
			s.err = err
			return
		}
		os.Remove(f.Name()) // gone with the process, whatever way it ends
		var total int64
		for _, m := range files {
			total += int64(m.UncompressedSize)
		}
		task := progress.Begin("unpacking "+s.name, total)
		defer task.End()
		var pos int64
		for _, m := range files {
			s.offs = append(s.offs, pos)
			rc, err := m.Open()
			if err != nil {
				s.err = err
				return
			}
			n, err := io.Copy(countWriter{f, task}, rc)
			rc.Close()
			if err != nil {
				s.err = err
				return
			}
			pos += n
		}
		s.f = f
	})
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
		v, _ := spools.LoadOrStore(fmt.Sprintf("%s\x00%d", path, f.Size()), &spool{name: infile.Base(path)})
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
