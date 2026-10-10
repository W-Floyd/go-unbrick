package infile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// CacheDir overrides the cache root; "" means <UserCacheDir>/go-unbrick/http.
	CacheDir string
	// Log, when set, is told about every network request.
	Log func(format string, args ...any)
	// Client carries no overall timeout: one range read may stream hundreds of MB.
	Client = &http.Client{}
	// Mirrors, when set, names other URLs that serve the same object as a
	// URL (a publisher's CDN hosts). They are tried when it fails or stalls;
	// If-Range on its strong ETag keeps a mirror from serving anything else.
	Mirrors func(u string) []string
)

// chunkSize is the cache's fetch granularity. Small enough that sniffing a zip
// member's head costs little; adjacent misses coalesce into one request, so a
// large read is still one round trip.
const chunkSize = 256 << 10

const fetchAttempts = 4

// maxReadahead caps, in chunks, how far a sequential run of misses is extended.
// Payload operations are laid out in partition order, so a lazy partition read
// walks the file forward one small miss at a time.
const maxReadahead = 32

var fetched atomic.Int64

// Fetched is the number of bytes received over the network by this process.
func Fetched() int64 { return fetched.Load() }

// One *remote per URL per process: every Open shares its validation and file
// handles, so the many independent opens a recon makes cost one probe. Mirrors
// of one object share a cache entry, and so one *remote (byDir).
var (
	remotesMu sync.Mutex
	remotes   = map[string]*remote{}
	byDir     = map[string]*remote{}
)

type meta struct {
	URL          string `json:"url"`
	Size         int64  `json:"size"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	ChunkSize    int64  `json:"chunk_size"`
}

func (m meta) modTime() time.Time {
	t, _ := http.ParseTime(m.LastModified)
	return t
}

// ifRange is the If-Range validator; a weak ETag is not allowed there.
func (m meta) ifRange() string {
	if m.ETag != "" && !strings.HasPrefix(m.ETag, "W/") {
		return m.ETag
	}
	return m.LastModified
}

// same reports whether two observations name the same remote content. With no
// validator at all, size is the only evidence available.
func (m meta) same(o meta) bool {
	if m.Size != o.Size || m.ChunkSize != o.ChunkSize || m.ETag != o.ETag {
		return false
	}
	// A strong ETag names the content; mirrors can stamp it with their own
	// Last-Modified.
	return m.strongETag() || m.LastModified == o.LastModified
}

// remote is a URL's content as a sparse cache file plus a one-byte-per-chunk
// presence map. A chunk is marked only after its bytes are written, so an
// interrupted run leaves a cache that is incomplete but never wrong.
type remote struct {
	url  string // what was probed
	meta meta
	size int64

	urls    []string        // url and its mirrors, which fetches spread over
	dropped map[string]bool // mirrors found serving something else
	dropMu  sync.Mutex

	mu   sync.Mutex
	data *os.File
	have *os.File
	got  []atomic.Bool // set by concurrent fetches, which can write a chunk twice

	// streams are the recent sequential readers. Several read at once (a
	// payload partition's operations while a filesystem's metadata), and
	// tracking only the last miss would read each as random.
	streams []stream
}

// stream is one sequential reader: the chunk just past its last fetch, and
// its readahead, which grows while its misses stay sequential.
type stream struct{ next, ahead int }

const maxStreams = 8

func openRemote(u string) (*remote, error) {
	remotesMu.Lock()
	defer remotesMu.Unlock()
	if r, ok := remotes[u]; ok {
		return r, nil
	}
	r, err := newRemote(u)
	if err != nil {
		return nil, err
	}
	remotes[u] = r
	return r, nil
}

func cacheRoot() (string, error) {
	if CacheDir != "" {
		return CacheDir, nil
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "go-unbrick", "http"), nil
}

// Known lists the URLs the cache holds an entry for, fetched in part or whole.
func Known() []string {
	root, err := cacheRoot()
	if err != nil {
		return nil
	}
	metas, _ := filepath.Glob(filepath.Join(root, "*", "meta.json"))
	var out []string
	for _, p := range metas {
		var m meta
		if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &m) == nil && m.URL != "" {
			out = append(out, m.URL)
		}
	}
	return out
}

func logf(format string, args ...any) {
	if Log != nil {
		Log(format, args...)
	}
}

// newRemote probes u — or, if it fails, each of its mirrors in turn — and
// opens or (re)creates the object's cache entry.
func newRemote(u string) (*remote, error) {
	m, err := probe(u)
	if err != nil && Mirrors != nil {
		for _, alt := range Mirrors(u) {
			mm, aerr := probe(alt)
			if aerr == nil {
				logf("%s failed (%v); using mirror %s", Base(u), err, alt)
				m, err = mm, nil
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return openEntry(m)
}

// probe asks for one byte — some CDNs answer HEAD differently from GET — to
// learn the object's size and validators. A server that ignores ranges is
// refused: the point is never to pull a whole package.
func probe(u string) (meta, error) {
	ctx, cancel := context.WithTimeout(context.Background(), IdleTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return meta{}, err
	}
	req.Header.Set("Range", "bytes=0-0")
	logf("probe %s", u)
	resp, err := Client.Do(req)
	if err != nil {
		return meta{}, stallErr(ctx, err)
	}
	defer resp.Body.Close()

	m := meta{URL: u, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), ChunkSize: chunkSize}
	switch resp.StatusCode {
	case http.StatusPartialContent, http.StatusRequestedRangeNotSatisfiable: // 416: empty object
		total, err := contentRangeTotal(resp.Header.Get("Content-Range"))
		if err != nil {
			return meta{}, fmt.Errorf("%s: %w", u, err)
		}
		m.Size = total
	case http.StatusOK:
		return meta{}, fmt.Errorf("%s: server does not support range requests; refusing to download it whole", u)
	default:
		return meta{}, fmt.Errorf("%s: %s", u, resp.Status)
	}
	return m, nil
}

// strongETag reports an ETag that names exact content, which If-Range accepts.
func (m meta) strongETag() bool { return m.ETag != "" && !strings.HasPrefix(m.ETag, "W/") }

// entryKey names m's cache entry. An object with a strong ETag is keyed by
// its path, ETag and size, so the mirrors serving it share one entry;
// otherwise by its URL.
func entryKey(m meta) string {
	k := m.URL
	if m.strongETag() {
		p := m.URL
		if pu, err := url.Parse(m.URL); err == nil {
			p = pu.Path
		}
		k = fmt.Sprintf("etag\x00%s\x00%s\x00%d", p, m.ETag, m.Size)
	}
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

// openEntry opens the cache entry for m, discarding one recorded for different
// content. Called with remotesMu held.
func openEntry(m meta) (*remote, error) {
	root, err := cacheRoot()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, entryKey(m))
	if r, ok := byDir[dir]; ok {
		return r, nil
	}
	metaPath := filepath.Join(dir, "meta.json")

	var old meta
	if b, err := os.ReadFile(metaPath); err == nil && json.Unmarshal(b, &old) == nil && old.same(m) {
		// reuse
	} else {
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		b, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(metaPath, b, 0o644); err != nil {
			return nil, err
		}
	}

	data, err := os.OpenFile(filepath.Join(dir, "data"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := data.Truncate(m.Size); err != nil { // sparse; unfetched ranges cost no disk
		data.Close()
		return nil, err
	}
	have, err := os.OpenFile(filepath.Join(dir, "chunks"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		data.Close()
		return nil, err
	}
	n := int((m.Size + chunkSize - 1) / chunkSize)
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
	r := &remote{url: m.URL, meta: m, size: m.Size, data: data, have: have, got: got,
		urls: withMirrors(m.URL), dropped: map[string]bool{}}
	byDir[dir] = r
	return r, nil
}

func (r *remote) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("infile: negative offset")
	}
	if off >= r.size {
		return 0, io.EOF
	}
	end := min(off+int64(len(p)), r.size)
	if err := r.ensure(off, end); err != nil {
		return 0, err
	}
	n, err := r.data.ReadAt(p[:end-off], off)
	if err == nil && n < len(p) {
		err = io.EOF
	}
	return n, err
}

// ensure fetches every missing chunk overlapping [off, end), one request per
// contiguous run of misses.
func (r *remote) ensure(off, end int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	last := int((end - 1) / chunkSize)
	for c := int(off / chunkSize); c <= last; c++ {
		if r.got[c].Load() {
			continue
		}
		run := c
		for run+1 <= last && !r.got[run+1].Load() {
			run++
		}
		s := r.stream(c)
		if s.next == c && c > 0 {
			s.ahead = min(max(2*s.ahead, 1), maxReadahead)
			for n := 0; n < s.ahead && run+1 < len(r.got) && !r.got[run+1].Load(); n++ {
				run++
			}
		}
		if err := r.fetch(c, run); err != nil {
			return err
		}
		s.next = run + 1
		c = run
	}
	return nil
}

// stallErr names a request the idle watchdog cancelled for what it was.
func stallErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("no data for %v: %w", IdleTimeout, err)
	}
	return err
}

func (r *remote) firstMissing(first, last int) int64 {
	for c := first; c <= last; c++ {
		if !r.got[c].Load() {
			return int64(c) * chunkSize
		}
	}
	return r.size
}

// fill writes body, which holds [at, stop) with at chunk-aligned, chunk by
// chunk, marking each as it lands.
func (r *remote) fill(body io.Reader, at, stop int64) error {
	buf := make([]byte, chunkSize)
	for at < stop {
		want := min(chunkSize, stop-at)
		n, err := io.ReadFull(body, buf[:want])
		fetched.Add(int64(n))
		if int64(n) == want {
			if _, werr := r.data.WriteAt(buf[:n], at); werr != nil {
				return werr
			}
			c := at / chunkSize
			if _, werr := r.have.WriteAt([]byte{1}, c); werr != nil {
				return werr
			}
			r.got[c].Store(true)
			at += want
			continue
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

// contentRangeTotal parses the complete length out of "bytes a-b/N" or "bytes */N".
func contentRangeTotal(h string) (int64, error) {
	i := strings.LastIndexByte(h, '/')
	if i < 0 || h[i+1:] == "*" {
		return 0, fmt.Errorf("no total length in Content-Range %q", h)
	}
	return strconv.ParseInt(h[i+1:], 10, 64)
}

func contentRangeStart(h string) (int64, error) {
	s, ok := strings.CutPrefix(h, "bytes ")
	if !ok {
		return 0, fmt.Errorf("bad Content-Range %q", h)
	}
	if i := strings.IndexByte(s, '-'); i > 0 {
		return strconv.ParseInt(s[:i], 10, 64)
	}
	return 0, fmt.Errorf("bad Content-Range %q", h)
}

// stream returns the reader a miss at chunk c continues, or starts one,
// dropping the least recent when there are maxStreams. Under mu.
func (r *remote) stream(c int) *stream {
	for i := range r.streams {
		if r.streams[i].next == c {
			// Most recent last, so the eviction below takes the stalest.
			s := r.streams[i]
			r.streams = append(append(r.streams[:i:i], r.streams[i+1:]...), s)
			return &r.streams[len(r.streams)-1]
		}
	}
	if len(r.streams) == maxStreams {
		r.streams = r.streams[1:]
	}
	r.streams = append(r.streams, stream{next: -1})
	return &r.streams[len(r.streams)-1]
}
