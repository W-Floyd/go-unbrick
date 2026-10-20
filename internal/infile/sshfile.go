package infile

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/pkg/sftp"
)

// An ssh:// file is read in blocks fetched by background goroutines, so the
// network and whoever is consuming the bytes work at the same time: a
// sequential reader has the next blocks arriving while it hashes the current
// one, and Warm lets a caller start the next file before it is wanted.
//
// A block is small, because a random read (a tar header, an ext4 inode) should
// cost one small round trip, not a megabyte. A reader that proves it is going
// through the file in order (several contiguous reads in a row) is fetched in
// spans of many blocks per request instead, which is what keeps the link full.
const (
	blockSize   = 64 << 10
	spanBlocks  = 16  // blocks per request once a reader is sequential, or warmed
	idleBlocks  = 64  // blocks kept for a file nobody warmed, beyond its read-ahead
	maxAhead    = 128 // read-ahead depth of a sequential reader, in blocks
	seqReads    = 3   // contiguous reads in a row before a reader counts as sequential
	warmFetches = 4   // background (warm) requests in flight, across all files
)

// warmSem bounds Warm's requests, so warming the next files cannot crowd out
// the blocks the current one is waiting for, which are never held back.
var warmSem = make(chan struct{}, warmFetches)

type blk struct {
	done chan struct{}
	data []byte
	err  error
}

// sshFile is one remote file, shared by every Open of its URL.
type sshFile struct {
	f    *sftp.File
	size int64

	mu      sync.Mutex
	blocks  map[int64]*blk
	lastEnd int64          // where the last read ended
	run     int            // contiguous reads in a row
	ahead   int            // current read-ahead depth, in blocks
	aheadTo int64          // the last block read-ahead has requested
	pinned  map[int64]bool // warmed blocks: kept until Evict, whatever else is read
}

func (s *sshFile) nblocks() int64 { return (s.size + blockSize - 1) / blockSize }

// fetch begins fetching blocks lo..hi that nobody has yet, as few requests as
// possible: each run of missing blocks, at most spanBlocks long, is one read.
// It returns the block at lo. s.mu is held.
func (s *sshFile) fetch(lo, hi int64, background bool) *blk {
	hi = min(hi, s.nblocks()-1)
	for i := lo; i <= hi; {
		if _, ok := s.blocks[i]; ok {
			i++
			continue
		}
		j := i
		for j+1 <= hi && j+1-i < spanBlocks-1 {
			if _, ok := s.blocks[j+1]; ok {
				break
			}
			j++
		}
		s.fetchRun(i, j, background)
		i = j + 1
	}
	return s.blocks[lo]
}

// fetchRun reads blocks lo..hi, all missing, in one request. s.mu is held.
func (s *sshFile) fetchRun(lo, hi int64, background bool) {
	bs := make([]*blk, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		b := &blk{done: make(chan struct{})}
		s.blocks[i] = b
		bs = append(bs, b)
	}
	go func() {
		if background {
			warmSem <- struct{}{}
			defer func() { <-warmSem }()
		}
		off := lo * blockSize
		buf := make([]byte, min((hi-lo+1)*blockSize, s.size-off))
		t := time.Now()
		n, err := s.f.ReadAt(buf, off)
		if OnSSHRead != nil {
			OnSSHRead(n, time.Since(t))
		}
		failed := err != nil && !(err == io.EOF && n == len(buf))
		for k, b := range bs {
			if failed {
				b.err = err
			} else {
				b.data = buf[int64(k)*blockSize : min(int64(k+1)*blockSize, int64(len(buf)))]
			}
			close(b.done)
		}
		if failed { // let a later read try again
			s.mu.Lock()
			for k, b := range bs {
				if s.blocks[lo+int64(k)] == b {
					delete(s.blocks, lo+int64(k))
				}
			}
			s.mu.Unlock()
		}
	}()
}

func isDone(b *blk) bool {
	select {
	case <-b.done:
		return true
	default:
		return false
	}
}

// get returns block i. A reader that has proved sequential gets the blocks
// after it coming too, in spans.
func (s *sshFile) get(i int64, sequential bool) ([]byte, error) {
	s.mu.Lock()
	var b *blk
	if sequential {
		s.ahead = min(max(2*s.ahead, spanBlocks), maxAhead)
		if _, ok := s.blocks[i]; !ok {
			s.fetch(i, i+spanBlocks-1, false)
			s.aheadTo = max(s.aheadTo, i+spanBlocks-1)
		}
		// Refill the window in big runs once it is half drained, not a block at
		// a time as it slides.
		if s.aheadTo-i < int64(s.ahead)/2 {
			hi := i + int64(s.ahead)
			s.fetch(max(s.aheadTo+1, i+1), hi, false)
			s.aheadTo = hi
		}
		b = s.blocks[i]
	} else {
		s.ahead, s.aheadTo = 0, -1
		b = s.fetch(i, i, false)
	}
	s.trim(i)
	s.mu.Unlock()
	<-b.done
	return b.data, b.err
}

// trim drops fetched blocks furthest from i once more are held than a file
// nobody warmed needs. s.mu is held.
func (s *sshFile) trim(i int64) {
	held := len(s.blocks) - len(s.pinned)
	if held <= idleBlocks+s.ahead {
		return
	}
	var done []int64
	for k, b := range s.blocks {
		if !s.pinned[k] && isDone(b) {
			done = append(done, k)
		}
	}
	dist := func(k int64) int64 {
		if k < i {
			return (i - k) * 2 // behind the reader is the first to go
		}
		return k - i
	}
	sort.Slice(done, func(a, b int) bool { return dist(done[a]) > dist(done[b]) })
	for _, k := range done {
		if held <= idleBlocks+s.ahead {
			break
		}
		delete(s.blocks, k)
		held--
	}
}

func (s *sshFile) ReadAt(p []byte, off int64) (int, error) {
	// Contiguous with the last read? Tar's "read the last byte, then the next
	// header" alternates with a seek, so it never builds a run.
	s.mu.Lock()
	if off == s.lastEnd {
		s.run++
	} else {
		s.run = 1
	}
	sequential := s.run >= seqReads
	s.lastEnd = min(off+int64(len(p)), s.size)
	s.mu.Unlock()

	n := 0
	for n < len(p) && off < s.size {
		b, err := s.get(off/blockSize, sequential)
		if err != nil {
			return n, err
		}
		c := copy(p[n:], b[off%blockSize:])
		n += c
		off += int64(c)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

type sshEntry struct {
	once sync.Once
	sf   *sshFile
	err  error
}

var sshFiles sync.Map // URL -> *sshEntry

// shared returns the one sshFile for p, opening it on first use. Its handle
// lives as long as the process; every Open of p reads through it.
func sharedSSH(p string) (*sshFile, error) {
	e, _ := sshFiles.LoadOrStore(p, &sshEntry{})
	en := e.(*sshEntry)
	en.once.Do(func() {
		cl, rp, err := sftpFor(p)
		if err != nil {
			en.err = err
			return
		}
		f, err := cl.Open(rp)
		if err != nil {
			en.err = err
			return
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			en.err = err
			return
		}
		if fi.IsDir() {
			f.Close()
			en.err = fmt.Errorf("%s is a directory", p)
			return
		}
		en.sf = &sshFile{f: f, size: fi.Size(), blocks: map[int64]*blk{}, lastEnd: -1}
	})
	return en.sf, en.err
}

func openSSH(p string) (*File, error) {
	sf, err := sharedSSH(p)
	if err != nil {
		return nil, err
	}
	return &File{SectionReader: io.NewSectionReader(sf, 0, sf.size), name: p}, nil
}

// pin keeps blocks lo..hi until released, and starts fetching them in the
// background. s.mu is held.
func (s *sshFile) pin(lo, hi int64) {
	hi = min(hi, s.nblocks()-1)
	if lo < 0 || lo > hi {
		return
	}
	if s.pinned == nil {
		s.pinned = map[int64]bool{}
	}
	for i := lo; i <= hi; i++ {
		s.pinned[i] = true
	}
	s.fetch(lo, hi, true)
}

// Warm starts fetching the first n bytes of the ssh:// file p, and its last
// block (where a zip or a footer keeps its index), in the background, and
// returns at once. What is fetched is kept until Evict. Anything else is a
// no-op. Errors surface when the file is read.
func Warm(p string, n int64) {
	if !IsSSH(p) || n <= 0 {
		return
	}
	go func() {
		sf, err := sharedSSH(p)
		if err != nil {
			return
		}
		sf.mu.Lock()
		defer sf.mu.Unlock()
		sf.pin(0, (n-1)/blockSize)
		sf.pin(sf.nblocks()-1, sf.nblocks()-1)
	}()
}

// WarmRange is Warm for bytes [off, off+n) of p: a member stored in an archive,
// say. Kept until EvictRange.
func WarmRange(p string, off, n int64) {
	if !IsSSH(p) || n <= 0 || off < 0 {
		return
	}
	go func() {
		sf, err := sharedSSH(p)
		if err != nil {
			return
		}
		sf.mu.Lock()
		defer sf.mu.Unlock()
		sf.pin(off/blockSize, (off+n-1)/blockSize)
	}()
}

// Evict releases what Warm and reading held of p; a later read fetches again.
func Evict(p string) {
	evict(p, 0, -1)
}

// EvictRange releases what WarmRange held of bytes [off, off+n) of p.
func EvictRange(p string, off, n int64) {
	if n > 0 {
		evict(p, off, n)
	}
}

// evict drops the fetched blocks overlapping [off, off+n), or all of them
// when n < 0, and unpins them.
func evict(p string, off, n int64) {
	e, ok := sshFiles.Load(p)
	if !ok {
		return
	}
	sf := e.(*sshEntry).sf
	if sf == nil {
		return
	}
	sf.mu.Lock()
	defer sf.mu.Unlock()
	lo, hi := int64(0), int64(1)<<62
	if n >= 0 {
		lo, hi = off/blockSize, (off+n-1)/blockSize
	}
	for k, b := range sf.blocks {
		if k >= lo && k <= hi && isDone(b) {
			delete(sf.blocks, k)
		}
	}
	for k := range sf.pinned {
		if k >= lo && k <= hi {
			delete(sf.pinned, k)
		}
	}
}
