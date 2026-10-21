// Package carve presents any input as a tree to list and extract from: an
// archive's members, an OTA payload's partitions, a filesystem's files, a boot
// image's sections and its ramdisk's files, super's logical partitions, and so
// on through whatever nests. A node is read lazily — at random where its
// container allows (a stored zip member, a payload partition, a file in an
// erofs image), streamed otherwise — so a path into a multi-GB package costs
// what that path passes through.
//
// Formats are Expanders, registered in order of precedence; the neutral ones
// are here, and an OEM's own formats arrive through the vendor seam.
package carve

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// MaxBuffer bounds what is held in memory for a node that can only be
// streamed but must be read at random, or whose format is parsed from bytes.
// It is half the memory available when the program starts (see membuf.go).
var MaxBuffer = defaultMaxBuffer()

// headLen is how much of a node expanders match on.
const headLen = 64 << 10

// Node is one thing in the tree.
type Node struct {
	// Name is the node's name within its parent. It may hold "/": a file
	// deep in a filesystem is one child of the filesystem.
	Name string
	Size int64 // -1 when unknown until read

	mu      sync.Mutex // guards at, Size and head, which are filled in on first use
	at      io.ReaderAt
	stream  func() (io.ReadCloser, error)
	path    string // the input itself, for the root
	id      string // names the content for caching; "" when it cannot be
	claim   *Claim // what the container says this member digests to
	src     *source
	defl    *srcfile.Deflated
	deflFn  func() *srcfile.Deflated            // finds defl on demand
	srcFn   func() (off, length int64, ok bool) // finds src on demand (guarded by mu)
	srcPath string                              // the input srcFn's range is in

	once    sync.Once
	partial string
	kind    string
	kids    []*Node
	err     error
	head    []byte

	parent *Node // the container n is a member of, once that has listed its members (guarded by mu)

	// Modified is when the container records n was last changed, if it records one.
	Modified time.Time
}

// Open returns the root node for an input path or URL.
// It is one node per input for the process, so what is expanded once (a
// remote archive found by search) is not searched for again.
func Open(p string) (*Node, error) {
	roots.Lock()
	defer roots.Unlock()
	if n, ok := roots.m[p]; ok {
		return n, nil
	}
	f, err := infile.Open(p)
	if err != nil {
		return nil, err
	}
	n := &Node{Name: infile.Base(p), Size: f.Size(), at: f, path: p, id: infile.Identity(p)}
	roots.m[p] = n
	return n, nil
}

var roots = struct {
	sync.Mutex
	m map[string]*Node
}{m: map[string]*Node{}}

// FromReaderAt makes a node of bytes at random.
func FromReaderAt(name string, ra io.ReaderAt, size int64) *Node {
	return &Node{Name: name, Size: size, at: ra}
}

// FromBytes makes a node of bytes in memory.
func FromBytes(name string, b []byte) *Node {
	return FromReaderAt(name, bytes.NewReader(b), int64(len(b)))
}

// FromStream makes a node that can only be read in order.
func FromStream(name string, size int64, open func() (io.ReadCloser, error)) *Node {
	return &Node{Name: name, Size: size, stream: open}
}

// RandomAccess reports whether n reads at random without buffering it whole.
func (n *Node) RandomAccess() bool { at, _ := n.random(); return at != nil }

// Partial says why n's children may not be all of them, once expanded; ""
// when they are.
func (n *Node) Partial() string { return n.partial }

// OnExpand, when set, is told how long each container took to list its
// members. For profiling.
var OnExpand func(kind, name string, d time.Duration)

// deflated locates n as a raw deflate stream inside its container, or nil. It
// may cost a read, so it is asked for only once n looks like what needs it.
func (n *Node) deflated() *srcfile.Deflated {
	if n.defl == nil && n.deflFn != nil {
		n.defl = n.deflFn()
		n.deflFn = nil
	}
	return n.defl
}

// Parent is the container n is a member of, or nil for an input or for a node made
// apart from one. It is set when the container lists its members.
func (n *Node) Parent() *Node {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.parent
}

// Source says where n's bytes sit in a file read by path: the whole input for a
// root, or the range of an archive member stored in it as-is (a tar member, a
// zip member, compressed or not). ok is false for anything derived, which has
// no range of its own to fetch.
func (n *Node) Source() (path string, off, length int64, ok bool) {
	if n.src == nil && n.srcFn != nil {
		n.mu.Lock()
		if fn := n.srcFn; fn != nil {
			n.srcFn = nil
			if o, l, ok := fn(); ok {
				n.src = &source{path: n.srcPath, off: o, length: l}
			}
		}
		n.mu.Unlock()
	}
	if n.src != nil {
		return n.src.path, n.src.off, n.src.length, true
	}
	if n.path != "" {
		return n.path, 0, n.Size, n.Size >= 0
	}
	return "", 0, 0, false
}

type source struct {
	path        string
	off, length int64
}

// Claim is a digest a container states for one of its members, readable
// without reading the member: a zip directory's CRC32, an OTA manifest's
// partition SHA-256. Unverified; whoever relies on it decides when to.
type Claim struct {
	Algo string // "crc32", "sha256": names understood by vendor.HasherFor
	Sum  string // lowercase hex
	Size int64  // the size the digest covers
}

// Claim is the digest n's container states for it, or nil.
func (n *Node) Claim() *Claim { return n.claim }

func withClaim(n *Node, algo, sum string, size int64) *Node {
	n.claim = &Claim{Algo: algo, Sum: sum, Size: size}
	return n
}

// ID names n's content for caching: the root's location, size and mtime, then
// the member names down to n. "" when unknown (a directory, or an input whose
// identity could not be read).
func (n *Node) ID() string { return n.id }

// Path is the input path the root was opened from; "" below the root.
func (n *Node) Path() string { return n.path }

// Reader reads the node from its start.
func (n *Node) Reader() (io.ReadCloser, error) {
	if at, size := n.random(); at != nil {
		return io.NopCloser(io.NewSectionReader(at, 0, size)), nil
	}
	return n.stream()
}

// random is n's random-access source and size, if it has one yet. A node is
// read from more than one goroutine (a viewer reads what a comparison is
// working on), and ReaderAt fills these in on first use, so they are read and
// written under mu.
func (n *Node) random() (io.ReaderAt, int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.at, n.Size
}

// setRandom records the random-access source a streamed node was buffered into.
func (n *Node) setRandom(at io.ReaderAt, size int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.at = at
	if n.Size != size {
		n.Size = size
	}
}

// ReaderAt reads the node at random, buffering one that can only be streamed.
// One too big for memory is unpacked to a temporary file when the run asked for
// it (infile.FullDownload): a compressed archive member cannot be read by range,
// and a filesystem inside it needs random access. Streaming it fetches that
// member's bytes only, not the archive's.
func (n *Node) ReaderAt() (io.ReaderAt, error) {
	if at, _ := n.random(); at != nil {
		return at, nil
	}
	if n.Size > MaxBuffer && infile.FullDownload {
		progress("unpacking %s (%d MiB) to a temporary file in %s", n.Name, n.Size>>20, os.TempDir())
		f, err := spool(n)
		if err != nil {
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		n.setRandom(f, fi.Size())
		return f, nil
	}
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	br := bytes.NewReader(b)
	n.setRandom(br, int64(len(b)))
	return br, nil
}

// Bytes reads the whole node, up to MaxBuffer.
func (n *Node) Bytes() ([]byte, error) {
	if n.Size > MaxBuffer {
		return nil, fmt.Errorf("%s is %d bytes, more than carve.MaxBuffer to hold in memory", n.Name, n.Size)
	}
	if at, size := n.random(); at != nil {
		if br, ok := at.(*bytes.Reader); ok && br.Size() == size {
			b := make([]byte, size)
			_, err := br.ReadAt(b, 0)
			return b, err
		}
	}
	rc, err := n.Reader()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, MaxBuffer+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxBuffer {
		return nil, fmt.Errorf("%s is more than carve.MaxBuffer to hold in memory", n.Name)
	}
	return b, nil
}

// Head is up to the first 64 KiB of the node.
func (n *Node) Head() []byte {
	n.mu.Lock()
	h := n.head
	n.mu.Unlock()
	if h != nil {
		return h
	}
	buf := make([]byte, headLen)
	k := 0
	if at, _ := n.random(); at != nil {
		k, _ = at.ReadAt(buf, 0)
	} else if rc, err := n.stream(); err == nil {
		k, _ = io.ReadFull(rc, buf)
		rc.Close()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.head == nil { // another reader may have got there first
		n.head = buf[:k]
	}
	return n.head
}

// Expander turns a node of one format into its children.
type Expander struct {
	// Kind names the format, as a listing shows it ("zip", "payload", "fat").
	Kind string
	// Match decides from the node (and its head) whether the format is this
	// one, cheaply: it runs for every node a listing shows.
	Match func(n *Node, head []byte) bool
	// Expand lists the children.
	Expand func(n *Node) ([]*Node, error)
	// FS, for a filesystem, opens it for reading by path, which spares
	// listing all of a multi-GB image to read one file of it.
	FS func(n *Node) (fs.FS, error)
}

// ErrNotFS is returned by FS for a node that is not a filesystem.
var ErrNotFS = errors.New("carve: not a filesystem")

// FS opens n as a filesystem, if its format is one.
func (n *Node) FS() (fs.FS, error) {
	e, ok := Format(n)
	if !ok || e.FS == nil {
		return nil, ErrNotFS
	}
	return e.FS(n)
}

var (
	regMu     sync.Mutex
	expanders []Expander
)

// Register adds expanders after those already registered: the first whose
// Match accepts a node expands it.
func Register(es ...Expander) {
	regMu.Lock()
	defer regMu.Unlock()
	expanders = append(expanders, es...)
}

// Format returns the expander that claims n, if any.
func Format(n *Node) (Expander, bool) {
	regMu.Lock()
	es := expanders
	regMu.Unlock()
	head := n.Head()
	for _, e := range es {
		if e.Match(n, head) {
			return e, true
		}
	}
	return Expander{}, false
}

// Children expands n, once. kind is "" for a leaf.
func (n *Node) Children() (kind string, kids []*Node, err error) {
	n.once.Do(func() {
		e, ok := Format(n)
		if !ok {
			return
		}
		n.kind = e.Kind
		start := time.Now()
		n.kids, n.err = e.Expand(n)
		if OnExpand != nil {
			OnExpand(e.Kind, n.Name, time.Since(start))
		}
		for _, k := range n.kids {
			k.mu.Lock()
			if k.parent == nil {
				k.parent = n
			}
			k.mu.Unlock()
		}
		if n.id != "" {
			for _, k := range n.kids {
				if k.id == "" {
					k.id = n.id + "\x00" + k.Name
				}
			}
		}
	})
	return n.kind, n.kids, n.err
}

// ErrNotFound is returned by Walk for a path no child matches.
var ErrNotFound = errors.New("carve: no such path")

// Walk follows p ("payload.bin/modem/image/adsp.mdt") down from n. A child's
// name can itself hold slashes, so at each level the longest name that is a
// whole-segment prefix of what remains wins.
func (n *Node) Walk(p string) (*Node, error) {
	p = strings.Trim(path.Clean("/"+p), "/")
	cur := n
	var walked []string
	for p != "" {
		_, kids, err := cur.Children()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", strings.Join(append(walked, cur.Name), "/"), err)
		}
		var best *Node
		for _, k := range kids {
			name := strings.Trim(k.Name, "/")
			if (p == name || strings.HasPrefix(p, name+"/")) && (best == nil || len(name) > len(strings.Trim(best.Name, "/"))) {
				best = k
			}
		}
		if best == nil {
			return nil, fmt.Errorf("%w: %s in %s", ErrNotFound, p, cur.Name)
		}
		walked = append(walked, cur.Name)
		cur = best
		p = strings.TrimPrefix(strings.TrimPrefix(p, strings.Trim(best.Name, "/")), "/")
	}
	return cur, nil
}

// sortByName orders children for listing.
func sortByName(kids []*Node) []*Node {
	sort.SliceStable(kids, func(i, j int) bool { return kids[i].Name < kids[j].Name })
	return kids
}

// Dir makes a node that is a fixed set of children, such as a directory on
// disk, rather than a format expanded from bytes.
func Dir(name string, kids []*Node) *Node {
	n := &Node{Name: name, Size: -1, kind: "directory", kids: sortByName(kids)}
	n.once.Do(func() {})
	return n
}

// IsContainer reports whether n has children: a Dir, or bytes some format claims.
func (n *Node) IsContainer() bool {
	if n.kind == "directory" {
		return true
	}
	_, ok := Format(n)
	return ok
}

// IsDirNode reports whether n came from Dir.
func (n *Node) IsDirNode() bool { return n.kind == "directory" }

// IsContainerCached is IsContainer for a caller that must not wait on a read: known
// is false until n's head has been read (by anything), and container then means
// nothing.
func (n *Node) IsContainerCached() (container, known bool) {
	if n.kind == "directory" {
		return true, true
	}
	n.mu.Lock()
	h := n.head
	n.mu.Unlock()
	if h == nil {
		return false, false
	}
	return n.IsContainer(), true
}
