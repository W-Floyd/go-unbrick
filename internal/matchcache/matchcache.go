// Package matchcache keeps the answers of upstream searches (the tag a tree is
// closest to, the commit between releases) on disk. An answer is a function of
// the tree's content and the upstream's history, which for a range between
// released tags does not change, so asking again should cost nothing.
package matchcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Cache is a directory of answers.
type Cache struct {
	Dir string
	now func() time.Time
}

// New is a cache under dir.
func New(dir string) *Cache { return &Cache{Dir: dir, now: time.Now} }

// Default is the cache under the user's cache directory.
func Default() *Cache {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	return New(filepath.Join(d, "go-unbrick", "srcmatch"))
}

// Key names a question: the parts that make the answer what it is.
func Key(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

// SetKey is a digest of a set of strings, independent of their order.
func SetKey(set map[string]bool) string {
	items := make([]string, 0, len(set))
	for s := range set {
		items = append(items, s)
	}
	sort.Strings(items)
	return Key(items...)
}

type entry struct {
	Expires time.Time       `json:"expires"`
	Value   json.RawMessage `json:"value"`
}

// Get loads the answer under key into v, if there is one that has not expired.
func (c *Cache) Get(key string, v any) bool {
	b, err := os.ReadFile(filepath.Join(c.Dir, key+".json"))
	if err != nil {
		return false
	}
	var e entry
	if json.Unmarshal(b, &e) != nil || !c.now().Before(e.Expires) {
		return false
	}
	return json.Unmarshal(e.Value, v) == nil
}

// Put stores v under key for ttl. A cache that cannot be written is not an error:
// the next question is merely asked again.
func (c *Cache) Put(key string, ttl time.Duration, v any) {
	val, err := json.Marshal(v)
	if err != nil {
		return
	}
	b, err := json.Marshal(entry{Expires: c.now().Add(ttl), Value: val})
	if err != nil || os.MkdirAll(c.Dir, 0o755) != nil {
		return
	}
	os.WriteFile(filepath.Join(c.Dir, key+".json"), b, 0o644) //nolint:errcheck // see above
}
