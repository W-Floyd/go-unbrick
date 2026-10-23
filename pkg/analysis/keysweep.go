package analysis

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// Searching an input for key material: each value looked for as a rolling window
// through every byte of every file, through nested containers and after
// decryption, to find where else it is embedded than where it is known to be.

// KeyValue is a byte string to search for: a key or an IV.
type KeyValue struct {
	Name  string // what to call it in a hit: every secrets file holding this value, comma separated
	Bytes []byte
	Role  string // "key" or "IV", for Name as a whole: "key" if any file sharing this value is one
	// Roles is each name in Name's own role, by its own file, independent of the others: two files
	// can share a value (a key's first half guessed to equal another vehicle's IV, say) without one's
	// role deciding the other's.
	Roles map[string]string
}

// LoadedKeyValues is the keys and IVs a host has loaded as secrets (the
// secrets directory), each once, named by its file. A secret that only combines
// a key with a framing (zero IV, ECB) adds nothing.
func LoadedKeyValues() []KeyValue {
	var out []KeyValue
	index := map[string]int{}
	add := func(b []byte, name, role string) {
		if len(b) == 0 {
			return
		}
		i, seen := index[string(b)]
		if !seen {
			index[string(b)] = len(out)
			out = append(out, KeyValue{Name: name, Bytes: b, Role: role, Roles: map[string]string{name: role}})
			return
		}
		if !strings.Contains(", "+out[i].Name+", ", ", "+name+", ") {
			out[i].Name += ", " + name
		}
		out[i].Roles[name] = role
		if role == "key" {
			out[i].Role = "key" // a value that is both is a key, whichever use was seen first
		}
	}
	for _, s := range aeskeys.Secrets() {
		name := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(s.Name, " (zero IV)"), " (ecb)"), " (prefixed IV)")
		add(s.Key, name, "key")
		if s.IVName != "" {
			add(s.IV, s.IVName, "IV")
		}
	}
	return out
}

// KeyHit is one place a value was found.
type KeyHit struct {
	Path     string // from the input's root, through nested containers
	Offset   int64  // in the file's (decrypted) bytes
	Name     string // the value's KeyValue.Name
	Encoding string // "raw", "hex" or "HEX" (as lower- or upper-case hex text)
	Known    bool   // the path is where the value is already known to be
}

// KeySweepProgress is how far a sweep has got.
type KeySweepProgress struct {
	Path       string // the file being read
	Size       int64  // its size, -1 if unknown
	Done       int64  // bytes of it read
	TotalBytes int64  // bytes read of all files so far, this one included
	Files      int    // files finished
}

// KeySweepOptions says what to search for and how far to look.
type KeySweepOptions struct {
	// Values are the strings to find, as raw bytes and as hex text. Default: LoadedKeyValues.
	Values []KeyValue
	// Depth is how many container levels to open. Default: unlimited.
	Depth int
	// Workers is how many files are searched at once: those read at random (a
	// file in a decrypted filesystem, in a tar on disk); a file that can only be
	// read in order is searched as the listing reaches it. Default: the CPUs, at
	// most 8; 1 searches one at a time.
	Workers int
	// Skip leaves out entries whose path (as in KeyHit.Path) matches any of these
	// regular expressions, and does not open a container that matches. See SkipPath.
	Skip []string
	// Known, if set, says whether a path is where a value is already known to be.
	Known func(path string) bool
	// OnHit is called for each hit as it is found, one call at a time (from any
	// goroutine), in no fixed order.
	OnHit func(KeyHit)
	// OnProgress is called while files are read, at most every 100 ms per file, and
	// as each file starts and ends; one call at a time, from any goroutine, about
	// whichever file is reporting.
	OnProgress func(KeySweepProgress)
}

// KeySweepResult is everything a sweep found.
type KeySweepResult struct {
	Hits  []KeyHit
	Files int
	Bytes int64
	// Unreadable is what could not be read as listed ("path: why"). A container
	// with an unreadable member was searched whole as well.
	Unreadable []string
	// Searched is how many strings were looked for.
	Searched int
}

// SweepKeys searches every byte of every file under input (a file, a package, an
// image or a directory, local or ssh://) for the values, through nested
// containers and after decryption (the host loads the secrets that decrypt, as
// for browsing). It stops early with ctx's error if ctx ends.
func SweepKeys(ctx context.Context, input string, opt KeySweepOptions) (*KeySweepResult, error) {
	values := opt.Values
	if values == nil {
		values = LoadedKeyValues()
	}
	m := newKeyMatcher(values)
	if len(m.pats) == 0 {
		return nil, fmt.Errorf("no keys or IVs to search for")
	}
	root, err := diffRoot(input)
	if err != nil {
		return nil, err
	}
	depth := opt.Depth
	if depth <= 0 {
		depth = 1 << 20
	}
	s := &keySweeper{ctx: ctx, m: m, opt: opt, res: &KeySweepResult{Searched: len(m.pats)}}
	workers := opt.Workers
	if workers <= 0 {
		workers = min(runtime.NumCPU(), 8)
	}
	if workers > 1 {
		s.sem = make(chan struct{}, workers)
	}
	s.walk(root, "", depth)
	s.wg.Wait()
	s.res.Files, s.res.Bytes = int(s.files.Load()), s.bytes.Load()
	sort.Slice(s.res.Hits, func(i, j int) bool {
		a, b := s.res.Hits[i], s.res.Hits[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Offset < b.Offset
	})
	sort.Strings(s.res.Unreadable)
	if err := ctx.Err(); err != nil {
		return s.res, err
	}
	return s.res, nil
}

type keySweeper struct {
	ctx context.Context
	m   *keyMatcher
	opt KeySweepOptions
	res *KeySweepResult

	sem   chan struct{} // a token per file being searched in the background; nil for one at a time
	wg    sync.WaitGroup
	mu    sync.Mutex // guards res.Hits and res.Unreadable
	cbMu  sync.Mutex // one callback at a time
	files atomic.Int64
	bytes atomic.Int64
}

func (s *keySweeper) unreadable(msg string) {
	s.mu.Lock()
	s.res.Unreadable = append(s.res.Unreadable, msg)
	s.mu.Unlock()
}

func (s *keySweeper) skipped(path string) bool { return SkipPath(s.opt.Skip, path) }

// walk searches n and what is inside it, and reports whether every byte was read.
// A container with a member that could not be read is searched whole as well, so
// those bytes are not lost to it.
func (s *keySweeper) walk(n *carve.Node, path string, depth int) bool {
	return <-s.visit(n, path, depth)
}

// visit is walk, with the answer delivered when it is known: a file read at random
// is searched in the background while the listing goes on.
func (s *keySweeper) visit(n *carve.Node, path string, depth int) <-chan bool {
	done := make(chan bool, 1)
	if s.ctx.Err() != nil {
		done <- false
		return done
	}
	if n.IsDirNode() {
		_, kids, err := n.Children()
		if err != nil {
			s.unreadable(path + ": " + err.Error())
			done <- false
			return done
		}
		done <- s.members(kids, path, depth)
		return done
	}
	if depth > 0 {
		if _, isContainer := carve.Format(n); isContainer {
			if _, kids, err := n.Children(); err == nil {
				ok := s.members(kids, path, depth-1)
				if !ok && s.ctx.Err() == nil {
					s.scanFile(n, strings.TrimPrefix(path, "/")+" (as bytes)")
				}
				done <- true // its own bytes are covered
				return done
			}
			// Not readable as the container it looks like: its bytes are all there is.
		}
	}
	name := strings.TrimPrefix(path, "/")
	if s.sem != nil && n.RandomAccess() {
		s.sem <- struct{}{} // held back while every worker is busy
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ok := s.scanFile(n, name)
			<-s.sem
			done <- ok
		}()
		return done
	}
	done <- s.scanFile(n, name)
	return done
}

// members searches kids and reports whether every byte of them was read.
func (s *keySweeper) members(kids []*carve.Node, path string, depth int) bool {
	var pending []<-chan bool
	for _, k := range kids {
		if !s.skipped(path + "/" + k.Name) {
			pending = append(pending, s.visit(k, path+"/"+k.Name, depth))
		}
	}
	ok := true
	for _, c := range pending {
		ok = <-c && ok
	}
	return ok
}

// scanFile searches one file's bytes and reports whether they were all read.
func (s *keySweeper) scanFile(n *carve.Node, path string) bool {
	r, err := n.Reader()
	if err != nil {
		s.unreadable(path + ": " + err.Error())
		return false
	}
	defer r.Close()
	cr := &sweepReader{ctx: s.ctx, r: r, s: s, path: path, size: n.Size}
	cr.report()
	err = s.m.scan(cr, func(h keyHit) {
		kh := KeyHit{Path: path, Offset: h.off, Name: h.pat.name, Encoding: h.pat.enc,
			Known: s.opt.Known != nil && s.opt.Known(path)}
		s.mu.Lock()
		s.res.Hits = append(s.res.Hits, kh)
		s.mu.Unlock()
		if s.opt.OnHit != nil {
			s.cbMu.Lock()
			s.opt.OnHit(kh)
			s.cbMu.Unlock()
		}
	})
	s.files.Add(1)
	cr.report()
	if err != nil {
		if s.ctx.Err() == nil {
			s.unreadable(fmt.Sprintf("%s: read stopped after %d bytes: %v", path, cr.n, err))
		}
		return false
	}
	return true
}

// sweepReader counts what is read and reports progress as it goes.
type sweepReader struct {
	ctx  context.Context
	r    io.Reader
	s    *keySweeper
	path string
	size int64
	n    int64
	last time.Time
}

func (c *sweepReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	c.s.bytes.Add(int64(n))
	if time.Since(c.last) >= 100*time.Millisecond {
		c.report()
	}
	return n, err
}

func (c *sweepReader) report() {
	c.last = time.Now()
	if c.s.opt.OnProgress != nil {
		c.s.cbMu.Lock()
		c.s.opt.OnProgress(KeySweepProgress{Path: c.path, Size: c.size, Done: c.n, TotalBytes: c.s.bytes.Load(), Files: int(c.s.files.Load())})
		c.s.cbMu.Unlock()
	}
}

// keyPat is one byte string to find: a value as raw bytes or as hex text.
type keyPat struct {
	name string // the value's name(s)
	enc  string // raw, hex, HEX
	b    []byte
	// bounded: a match counts only when no hex digit sits either side, for a value so
	// regular (00 01 02 …) that it is the start of every hex table.
	bounded bool
}

// keyMatcher finds many patterns in one pass: a 64 Ki table on the first two
// bytes of each position says whether any pattern could start there, and only
// those are compared in full.
type keyMatcher struct {
	pats   []keyPat
	has    [1 << 16]bool
	first  map[uint16][]int
	maxLen int
}

func newKeyMatcher(values []KeyValue) *keyMatcher {
	m := &keyMatcher{first: map[uint16][]int{}}
	seen := map[string]bool{}
	for _, v := range values {
		b := v.Bytes
		if len(b) < 16 || uniform(b) || seen[string(b)] {
			continue
		}
		seen[string(b)] = true
		// 00 01 02 … is in every binary, and its hex text starts every hex table:
		// only the hex text, standing alone, means anything.
		weak := progression(b)
		if !weak {
			m.add(keyPat{name: v.Name, enc: "raw", b: b})
		}
		lo := []byte(hex.EncodeToString(b))
		m.add(keyPat{name: v.Name, enc: "hex", b: lo, bounded: weak})
		if up := bytes.ToUpper(lo); !bytes.Equal(up, lo) {
			m.add(keyPat{name: v.Name, enc: "HEX", b: up, bounded: weak})
		}
	}
	return m
}

// progression is bytes that each step by the same amount: 00 01 02 …, or one byte repeated.
func progression(b []byte) bool {
	for i := 2; i < len(b); i++ {
		if b[i]-b[i-1] != b[1]-b[0] {
			return false
		}
	}
	return true
}

func uniform(b []byte) bool {
	for _, c := range b {
		if c != b[0] {
			return false
		}
	}
	return true
}

func (m *keyMatcher) add(p keyPat) {
	k := uint16(p.b[0]) | uint16(p.b[1])<<8
	m.has[k] = true
	m.first[k] = append(m.first[k], len(m.pats))
	m.pats = append(m.pats, p)
	m.maxLen = max(m.maxLen, len(p.b))
}

type keyHit struct {
	pat *keyPat
	off int64
}

const scanChunk = 4 << 20

var scanBufs sync.Pool

// scan reads r through and reports every match, at its offset in the stream.
func (m *keyMatcher) scan(r io.Reader, emit func(keyHit)) error {
	// A buffer per file would be tens of gigabytes of garbage over a package's tens of
	// thousands of small files.
	bp, _ := scanBufs.Get().(*[]byte)
	if bp == nil || cap(*bp) < scanChunk+m.maxLen+1 {
		b := make([]byte, 0, scanChunk+m.maxLen+1)
		bp = &b
	}
	defer scanBufs.Put(bp)
	const chunk = scanChunk
	buf := (*bp)[:0]
	var base int64 // offset in the stream of buf[0]
	start := 0     // the first position not yet searched
	for {
		carry := len(buf)
		buf = buf[:carry+chunk]
		n, err := io.ReadFull(r, buf[carry:])
		buf = buf[:carry+n]
		eof := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !eof {
			return err
		}
		// A position is searched once a full pattern, and the byte after it, are read.
		limit := len(buf) - m.maxLen
		if eof || limit < 0 {
			limit = len(buf)
		}
		for i := start; i < limit; i++ {
			if i+1 >= len(buf) {
				break
			}
			k := uint16(buf[i]) | uint16(buf[i+1])<<8
			if !m.has[k] {
				continue
			}
			for _, pi := range m.first[k] {
				p := &m.pats[pi]
				if !bytes.HasPrefix(buf[i:], p.b) {
					continue
				}
				if p.bounded {
					end := i + len(p.b)
					if (i > 0 && isHexDigit(buf[i-1])) || (end < len(buf) && isHexDigit(buf[end])) {
						continue
					}
				}
				emit(keyHit{p, base + int64(i)})
			}
		}
		if eof {
			return nil
		}
		// Carried over: one byte before the first unsearched position, for the
		// bounded patterns, and everything after it.
		from := max(limit-1, 0)
		copy(buf, buf[from:])
		buf = buf[:len(buf)-from]
		base += int64(from)
		start = limit - from
	}
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
