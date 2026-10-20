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

	at     io.ReaderAt
	stream func() (io.ReadCloser, error)
	path   string // the input itself, for the root
	defl   *srcfile.Deflated

	once    sync.Once
	partial string
	kind    string
	kids    []*Node
	err     error
	head    []byte
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
	n := &Node{Name: infile.Base(p), Size: f.Size(), at: f, path: p}
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
func (n *Node) RandomAccess() bool { return n.at != nil }

// Partial says why n's children may not be all of them, once expanded; ""
// when they are.
func (n *Node) Partial() string { return n.partial }

// Path is the input path the root was opened from; "" below the root.
func (n *Node) Path() string { return n.path }

// Reader reads the node from its start.
func (n *Node) Reader() (io.ReadCloser, error) {
	if n.at != nil {
		return io.NopCloser(io.NewSectionReader(n.at, 0, n.Size)), nil
	}
	return n.stream()
}

// ReaderAt reads the node at random, buffering one that can only be streamed.
// One too big for memory is unpacked to a temporary file when the run asked for
// it (infile.FullDownload): a compressed archive member cannot be read by range,
// and a filesystem inside it needs random access. Streaming it fetches that
// member's bytes only, not the archive's.
func (n *Node) ReaderAt() (io.ReaderAt, error) {
	if n.at != nil {
		return n.at, nil
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
		n.at, n.Size = f, fi.Size()
		return n.at, nil
	}
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	n.at, n.Size = bytes.NewReader(b), int64(len(b))
	return n.at, nil
}

// Bytes reads the whole node, up to MaxBuffer.
func (n *Node) Bytes() ([]byte, error) {
	if n.Size > MaxBuffer {
		return nil, fmt.Errorf("%s is %d bytes, more than carve.MaxBuffer to hold in memory", n.Name, n.Size)
	}
	if br, ok := n.at.(*bytes.Reader); ok && br.Size() == n.Size {
		b := make([]byte, n.Size)
		_, err := br.ReadAt(b, 0)
		return b, err
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
	if n.head != nil {
		return n.head
	}
	buf := make([]byte, headLen)
	k := 0
	if n.at != nil {
		k, _ = n.at.ReadAt(buf, 0)
	} else if rc, err := n.stream(); err == nil {
		k, _ = io.ReadFull(rc, buf)
		rc.Close()
	}
	n.head = buf[:k]
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
		n.kids, n.err = e.Expand(n)
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
