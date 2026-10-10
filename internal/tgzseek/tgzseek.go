// Package tgzseek lists and reads a .tgz from a random-access source without
// decoding it from the start, for packages too large to fetch whole.
//
// An offset in a deflate stream says nothing about the offset it decodes to
// short of decoding everything before it, so the archive is read by entering
// the stream at chosen points (inflate.Find), decoding a little, and
// collecting the tar headers found there:
//
//   - The head is decoded from the start up to the first member too costly to
//     decode through.
//   - The gzip trailer gives the decoded length mod 2^32, so a run decoded from
//     near the end to the end is anchored, and its header chain is checked
//     through to the end-of-archive blocks.
//   - In between, members are found by landings, the likeliest places first,
//     until their header spans add up exactly to the gap between the head and
//     the anchored end, which makes the listing complete, or until the fetch
//     budget is spent, which leaves it partial.
//
// Member bytes are returned exact or not at all: the decoder tracks every
// byte that depends on history it does not have, and such bytes are refused.
package tgzseek

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
)

// Tuning; variables so tests can scale them down.
var (
	// Budget is the share of the archive that opening it may fetch.
	Budget = 0.008
	// MinBudget is the budget floor, for archives small enough that a
	// fraction of them is less than one landing.
	MinBudget int64 = 8 << 20
	// WholeBelow is the stream size up to which opening may fetch all of
	// it: landings save little there, and a short budget leaves gaps.
	WholeBelow int64 = 64 << 20
	// Keep is the largest member whose bytes are kept from the walk; larger
	// ones are decoded again when read.
	Keep int64 = 16 << 20
	// WalkLimit is the most compressed bytes decoded through a member to
	// reach the header after it.
	WalkLimit int64 = 4 << 20
	// LandWalk is how much output a landing searches for a header.
	LandWalk int64 = 1 << 20
	// LandConfirm bounds the compressed bytes a landing spends confirming
	// its entry point (see inflate.Find).
	LandConfirm int64 = 1 << 20
	// TailLimit bounds how far before the end the anchored run may start.
	TailLimit int64 = 64 << 20
	// Log, when set, is told about each landing.
	Log func(format string, args ...any)
)

func logf(format string, args ...any) {
	if Log != nil {
		Log(format, args...)
	}
}

const (
	block      = 512
	headLen    = 64 << 10
	sampleLen  = 1 << 20 // output a member's compression is measured over
	checkEvery = 1 << 20 // output between checkpoints
	meterChunk = 256 << 10
	// storedOverhead bounds deflate's expansion: zlib stores what it cannot
	// compress, 5 header bytes per block of at least 16 KiB.
	storedOverhead = 5.0 / 16384
)

// Entry is one regular file in the archive.
type Entry struct {
	Name string
	Size int64
	Head []byte // up to 64 KiB of the start, fewer if not all known

	data []byte // the whole member, when kept
	run  *run
	rel  int64       // offset of the data in run's output
	cp   *checkpoint // last exact resume point at or before rel
}

// Archive is an opened .tgz.
type Archive struct {
	r       io.ReaderAt
	start   int64 // offset of the deflate stream in r
	Entries []Entry
	// Complete reports that Entries holds every member. When false, Missing
	// is the tar-stream length of what was not found.
	Complete bool
	Missing  int64
}

// run is one decode of the stream from a block start.
type run struct {
	start int64 // bit
	exact bool  // history known: the stream start
}

// checkpoint is a place to resume decoding with exact history.
type checkpoint struct {
	bit, out int64
	win      []byte
}

// item is any tar entry as walked: a member, or a directory, link, etc.,
// which only takes up room.
type item struct {
	Entry
	reg  bool
	span int64 // header blocks and padded data
	bit  int64 // compressed position, for ordering
	own  owner
}

type owner struct {
	uid, gid     int
	uname, gname string
}

// Open lists the archive at r, of size bytes.
func Open(r io.ReaderAt, size int64) (*Archive, error) {
	start, err := deflateStart(r)
	if err != nil {
		return nil, err
	}
	if size < start+8 {
		return nil, errors.New("tgzseek: truncated gzip")
	}
	var tr [8]byte
	if _, err := r.ReadAt(tr[:], size-8); err != nil {
		return nil, err
	}
	m := &meter{r: r, got: map[int64]bool{}}
	o := &opener{r: m, raw: r, start: start, end: size - 8, isize: binary.LittleEndian.Uint32(tr[4:]),
		budget: budgetFor(size)}
	if err := o.open(start * 8); err != nil {
		return nil, err
	}
	return o.archive(), nil
}

// OpenDeflate lists a tar held as the raw deflate stream at [start, end) of
// r that decodes to size bytes: a deflated zip member.
func OpenDeflate(r io.ReaderAt, start, end, size int64) (*Archive, error) {
	m := &meter{r: r, got: map[int64]bool{}}
	o := &opener{r: m, raw: r, start: start, end: end, isize: uint32(size), total: size,
		budget: budgetFor(end - start)}
	if err := o.open(start * 8); err != nil {
		return nil, err
	}
	return o.archive(), nil
}

func budgetFor(n int64) int64 {
	if n <= WholeBelow {
		return n
	}
	return max(int64(Budget*float64(n)), MinBudget)
}

// odinTrimmed drops the md5sum line Odin appends to a .tar.md5 after the
// end-of-archive blocks.
func odinTrimmed(b []byte) []byte {
	t := bytes.TrimSuffix(b, []byte("\n"))
	i := bytes.LastIndexByte(t, 0) + 1
	line := t[i:]
	if bytes.IndexByte(line, ' ') != 32 || !isHex(line[:32]) || bytes.IndexByte(line, '\n') >= 0 {
		return b
	}
	return t[:i]
}

func isHex(b []byte) bool {
	for _, c := range b {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// deflateStart parses the gzip member header.
func deflateStart(r io.ReaderAt) (int64, error) {
	h := make([]byte, 10)
	if _, err := r.ReadAt(h, 0); err != nil {
		return 0, err
	}
	if h[0] != 0x1f || h[1] != 0x8b || h[2] != 8 {
		return 0, errors.New("tgzseek: not a gzip stream")
	}
	flg, off := h[3], int64(10)
	if flg&4 != 0 { // FEXTRA
		var x [2]byte
		if _, err := r.ReadAt(x[:], off); err != nil {
			return 0, err
		}
		off += 2 + int64(binary.LittleEndian.Uint16(x[:]))
	}
	for _, f := range []byte{8, 16} { // FNAME, FCOMMENT: zero-terminated
		if flg&f == 0 {
			continue
		}
		var b [1]byte
		for {
			if _, err := r.ReadAt(b[:], off); err != nil {
				return 0, err
			}
			off++
			if b[0] == 0 {
				break
			}
		}
	}
	if flg&2 != 0 { // FHCRC
		off += 2
	}
	return off, nil
}

// meter counts the distinct chunks read, the cost of a read through a chunk
// cache such as infile's.
type meter struct {
	r   io.ReaderAt
	mu  sync.Mutex
	got map[int64]bool
}

func (m *meter) ReadAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	for c := off / meterChunk; len(p) > 0 && c <= (off+int64(len(p))-1)/meterChunk; c++ {
		m.got[c] = true
	}
	m.mu.Unlock()
	return m.r.ReadAt(p, off)
}

func (m *meter) spent() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.got)) * meterChunk
}

// validHeader checks the ustar magic and the header checksum.
func validHeader(b []byte) bool {
	if !bytes.Equal(b[257:262], []byte("ustar")) {
		return false
	}
	var sum int64
	for i, c := range b[:block] {
		if i >= 148 && i < 156 {
			c = ' '
		}
		sum += int64(c)
	}
	v, err := strconv.ParseInt(string(bytes.Trim(b[148:156], " \x00")), 8, 64)
	return err == nil && v == sum
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func pad(n int64) int64 { return (n + block - 1) / block * block }

// parseAt parses the entry whose header (or first extension header) is at the
// start of b: the regular-file header, or nil for another kind of entry, where
// its data starts, and where the next header is. ok is false when b holds no
// valid header there or ends inside the headers.
func parseAt(b []byte) (hdr *tar.Header, data, next int64, ok bool) {
	q := int64(0)
	for {
		if q+block > int64(len(b)) || !validHeader(b[q:q+block]) {
			return nil, 0, 0, false
		}
		switch b[q+156] {
		case 'L', 'K', 'x', 'g':
			size, err := strconv.ParseInt(string(bytes.Trim(b[q+124:q+136], " \x00")), 8, 64)
			if err != nil {
				return nil, 0, 0, false
			}
			if b[q+156] == 'g' { // global pax header: an entry of its own
				return nil, q + block, q + block + pad(size), true
			}
			q += block + pad(size) // the entry's own header follows
			continue
		}
		end := q + block
		h, err := tar.NewReader(bytes.NewReader(b[:end])).Next()
		if err != nil {
			return nil, 0, 0, false
		}
		if h.Typeflag != tar.TypeReg {
			return nil, end, end + pad(h.Size), true
		}
		return h, end, end + pad(h.Size), true
	}
}

func ownerOf(h *tar.Header) owner { return owner{h.Uid, h.Gid, h.Uname, h.Gname} }

func knownPrefix(u []bool) int {
	for i, v := range u {
		if v {
			return i
		}
	}
	return len(u)
}

func anyUnknown(u []bool) bool { return knownPrefix(u) < len(u) }

// archive assembles the listing: head, then what the landings found in
// stream order, then the tail.
func (o *opener) archive() *Archive {
	a := &Archive{r: o.raw, start: o.start}
	sort.SliceStable(o.middle, func(i, j int) bool { return o.middle[i].bit < o.middle[j].bit })
	for _, part := range [][]item{o.head, o.middle, o.tail.items} {
		for _, it := range part {
			if it.reg {
				a.Entries = append(a.Entries, it.Entry)
			}
		}
	}
	missing := o.missing()
	a.Complete, a.Missing = missing == 0, missing
	return a
}

func (a *Archive) String() string {
	if a.Complete {
		return fmt.Sprintf("%d members", len(a.Entries))
	}
	return fmt.Sprintf("%d members found, %d bytes of the archive not located", len(a.Entries), a.Missing)
}
