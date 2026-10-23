// Package hashcache remembers content hashes between runs, so comparing the
// same package twice (or two packages sharing a member) reads each file once.
//
// An entry is keyed by an identity string that already encodes what makes the
// bytes change — path, size and mtime for a file, ETag for a URL, the root's
// identity plus the member's path for anything nested — so a stale entry is
// simply never asked for again. The store is an append-only JSON-lines file;
// the last record for a key wins.
package hashcache

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Path is the store's file. Empty means $UNBRICK_HASH_CACHE, else <user cache>/go-unbrick/hashes.jsonl;
// set it before first use.
var Path string

type record struct {
	Key  string `json:"k"`
	Size int64  `json:"s"`
	Sum  string `json:"h"`
	// Claimed marks a hash taken from a vendor manifest, never computed from
	// the bytes: usable when manifests are trusted, ignored when verifying.
	Claimed bool `json:"c,omitempty"`
}

var (
	mu     sync.Mutex
	loaded bool
	sums   = map[string]record{}
	// bySize indexes the last sum seen for any content of a given size, across
	// every key ever Put -- see GetBySize. Keyed on size alone, not a path or
	// name: two unrelated files of the same size do sometimes collide here,
	// but confirming one is cheap (GetBySize is only ever a hint, the caller
	// still hashes the actual bytes), and most callers were going to read
	// those bytes in full anyway for their own reasons.
	bySize = map[int64]string{}
	out    *os.File
)

func path() string {
	if Path != "" {
		return Path
	}
	if p := os.Getenv("UNBRICK_HASH_CACHE"); p != "" {
		return p
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "go-unbrick", "hashes.jsonl")
}

// load reads the store once. A missing or damaged store is an empty one: the
// cache only ever saves work.
func load() {
	if loaded {
		return
	}
	loaded = true
	p := path()
	if p == "" {
		return
	}
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var r record
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Key != "" && r.Sum != "" {
			sums[r.Key] = r
			bySize[r.Size] = r.Sum
		}
	}
}

// Get returns the digest recorded for key, if it was recorded for content of
// this size. A hash that came from a manifest is returned only with
// trustClaims. The key should name the algorithm as well as the content.
func Get(key string, size int64, trustClaims bool) (string, bool) {
	if key == "" {
		return "", false
	}
	mu.Lock()
	defer mu.Unlock()
	load()
	r, ok := sums[key]
	if !ok || (size >= 0 && r.Size != size) || (r.Claimed && !trustClaims) {
		return "", false
	}
	return r.Sum, true
}

// GetBySize returns the digest last seen for ANY content of this size,
// regardless of what key it was Put under -- a cheap hint (no bytes read to
// produce it) that an unfamiliar file might be that same content. It is only
// ever a hint: the caller still has to read and hash its own file to confirm
// before trusting the match (two unrelated files can share a size by
// coincidence).
func GetBySize(size int64) (string, bool) {
	mu.Lock()
	defer mu.Unlock()
	load()
	sum, ok := bySize[size]
	return sum, ok
}

// Put records sum for key; claimed says it came from a manifest rather than
// from the bytes. A claim never replaces a computed hash. Failing to persist
// is not an error.
func Put(key string, size int64, sum string, claimed bool) {
	if key == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	load()
	if old, ok := sums[key]; ok && claimed && !old.Claimed && old.Size == size {
		return
	}
	r := record{key, size, sum, claimed}
	if sums[key] == r {
		return
	}
	sums[key] = r
	bySize[size] = sum
	if out == nil {
		p := path()
		if p == "" || os.MkdirAll(filepath.Dir(p), 0o755) != nil {
			return
		}
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		out = f
	}
	b, _ := json.Marshal(r)
	out.Write(append(b, '\n'))
}

// Reset forgets what is loaded and closes the store; for tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	if out != nil {
		out.Close()
		out = nil
	}
	loaded = false
	sums = map[string]record{}
	bySize = map[int64]string{}
}
