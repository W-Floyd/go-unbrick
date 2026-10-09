package infile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
// handles, so the many independent opens a recon makes cost one probe.
var (
	remotesMu sync.Mutex
	remotes   = map[string]*remote{}
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
	return m.Size == o.Size && m.ChunkSize == o.ChunkSize &&
		m.ETag == o.ETag && m.LastModified == o.LastModified
}

// remote is a URL's content as a sparse cache file plus a one-byte-per-chunk
// presence map. A chunk is marked only after its bytes are written, so an
// interrupted run leaves a cache that is incomplete but never wrong.
type remote struct {
	url  string
	meta meta
	size int64

	mu   sync.Mutex
	data *os.File
	have *os.File
	got  []bool

	seqNext  int // chunk just past the last fetch
	seqAhead int // current readahead, in chunks; grows while misses stay sequential
}

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

func logf(format string, args ...any) {
	if Log != nil {
		Log(format, args...)
	}
}

// newRemote probes u with a one-byte range request — some CDNs answer HEAD
// differently from GET — and opens or (re)creates its cache entry. A server that
// ignores ranges is refused: the point is never to pull a whole package.
func newRemote(u string) (*remote, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", "bytes=0-0")
	logf("probe %s", u)
	resp, err := Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	m := meta{URL: u, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), ChunkSize: chunkSize}
	switch resp.StatusCode {
	case http.StatusPartialContent, http.StatusRequestedRangeNotSatisfiable: // 416: empty object
		total, err := contentRangeTotal(resp.Header.Get("Content-Range"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		m.Size = total
	case http.StatusOK:
		return nil, fmt.Errorf("%s: server does not support range requests; refusing to download it whole", u)
	default:
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	return openEntry(m)
}

// openEntry opens the cache entry for m, discarding one recorded for different
// content.
func openEntry(m meta) (*remote, error) {
	root, err := cacheRoot()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(m.URL))
	dir := filepath.Join(root, hex.EncodeToString(sum[:]))
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
	got := make([]bool, n)
	for i, b := range bits {
		got[i] = b == 1
	}
	return &remote{url: m.URL, meta: m, size: m.Size, data: data, have: have, got: got}, nil
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
		if r.got[c] {
			continue
		}
		run := c
		for run+1 <= last && !r.got[run+1] {
			run++
		}
		if c == r.seqNext && c > 0 {
			r.seqAhead = min(max(2*r.seqAhead, 1), maxReadahead)
			for n := 0; n < r.seqAhead && run+1 < len(r.got) && !r.got[run+1]; n++ {
				run++
			}
		} else {
			r.seqAhead = 0
		}
		if err := r.fetch(c, run); err != nil {
			return err
		}
		r.seqNext = run + 1
		c = run
	}
	return nil
}

// fetch fills chunks first..last, resuming from the last whole chunk written
// when a transfer breaks off.
func (r *remote) fetch(first, last int) error {
	start := int64(first) * chunkSize
	stop := min(int64(last+1)*chunkSize, r.size)
	var lastErr error
	for attempt := 0; attempt < fetchAttempts && start < stop; attempt++ {
		req, err := http.NewRequest(http.MethodGet, r.url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, stop-1))
		if v := r.meta.ifRange(); v != "" {
			req.Header.Set("If-Range", v)
		}
		logf("GET %s bytes=%d-%d (%d KiB)", Base(r.url), start, stop-1, (stop-start)>>10)
		resp, err := Client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusPartialContent {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fmt.Errorf("%s changed since it was first read; rerun to refetch", r.url)
			}
			lastErr = fmt.Errorf("%s: %s", r.url, resp.Status)
			continue
		}
		if s, err := contentRangeStart(resp.Header.Get("Content-Range")); err != nil || s != start {
			resp.Body.Close()
			return fmt.Errorf("%s: unexpected Content-Range %q for offset %d", r.url, resp.Header.Get("Content-Range"), start)
		}
		before := start
		err = r.fill(resp.Body, start, stop)
		resp.Body.Close()
		start = r.firstMissing(first, last)
		if err == nil && start >= stop {
			return nil
		}
		lastErr = err
		if start > before {
			attempt = -1 // progress made; a break mid-stream is not a failed attempt
		}
	}
	if lastErr == nil {
		lastErr = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("fetching %s: %w", r.url, lastErr)
}

func (r *remote) firstMissing(first, last int) int64 {
	for c := first; c <= last; c++ {
		if !r.got[c] {
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
			r.got[c] = true
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
