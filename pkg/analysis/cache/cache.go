// Package cache remembers the text output of an expensive, format-aware
// operation (a recon report, a listing, a label) keyed by what was asked and by
// which versions of go-unbrick's format recognizers were consulted to answer it
// -- so a result survives between runs the way internal/hashcache's digests do,
// but also survives exactly until go-unbrick itself learns to parse something
// differently, at which point it is never returned again, with no manual
// clearing step.
//
// This is a cache for *analysis* results: cheap to lose (always recomputed on a
// miss), never a cache of bytes read from an input, and never used for a diff
// (two-sided comparisons are not cached here -- see the package doc on when
// not to use this).
//
// # Versioning and invalidation
//
// Versions names every format recognizer or parser go-unbrick ships, each at an
// integer that goes up whenever that one's behavior changes in a way that could
// change what it reports for bytes already seen -- a header field read
// differently, a new magic recognized, a label's wording changed. Bumping it is
// the only invalidation step there is: no cache to find and delete by hand, and
// nothing to remember to do except raise the number for whatever changed.
//
// A Domain is a named, independently versioned slice of the cache: the set of
// recognizers one kind of operation could have gone through. Recon's text
// report, for instance, tries a fixed chain of recognizers on every file
// regardless of what the file turns out to be (see cmd_recon.go) -- so its
// Domain lists that whole chain, and bumping any one member's Versions entry
// invalidates every recon result that could have reached it, not just the files
// where it happened to match. The same reasoning covers nested containers
// without tracking a parent/child graph by hand: a package's cached listing
// went through the same container-opening code its members' listings did, so
// it shares their Domain and invalidates right along with them -- "child
// caches" fall out of the same mechanism, not a separate one.
//
// This is coarser than tracking exactly which recognizer touched which file:
// a Domain invalidates in one piece, not file by file. That is the deliberate
// trade for being impossible to get wrong by omission -- a forgotten
// dependency edge in a fine-grained scheme fails silently (a stale answer kept
// forever); a Domain only fails by being too eager, which costs a cache miss,
// never a wrong answer. Keep Domains small and specific (recon, listing, a
// single label kind, ...) rather than one Domain for everything, so a bump
// still only costs the results that could plausibly have used it.
package cache

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/W-Floyd/go-unbrick/pkg/analysis/recognize"
)

// Versions is the last resort for a member with no other place to keep its
// version: nothing here implements recognize.Recognizer or has registered a
// VersionFuncs entry. Prefer a Recognizer, or a package-level Version const
// wired through VersionFuncs, before adding an entry here -- a number in this
// map is disconnected from the code it is meant to track, so it is easy to
// forget to raise.
//
// Add an entry only once those don't fit; from then on, raise its number --
// never reuse, remove, or renumber one others already refer to by name --
// whenever its behavior changes for bytes it would already have been asked
// about.
var Versions = map[string]int{}

// VersionFuncs lets a package that is not a recognize.Recognizer (a plain
// parser with no Claims/Label/Report of its own: internal/dtbo, internal/ubi,
// ...) still keep its cache version as a const next to its own code, instead
// of in this package's Versions map. The host wires it up once, typically
// from the same init() that populates recognize.Default (see
// cmd_recon_registry.go): cache.VersionFuncs["dtbo"] = func() int { return
// dtbo.Version }.
var VersionFuncs = map[string]func() int{}

// Domain is a named, independently versioned slice of the cache: see the
// package doc for what one is and why operations are grouped this way instead
// of per-recognizer.
type Domain struct {
	Name    string
	Members []string // a recognize.Recognizer's Name, or a key into Versions
}

// Version is a short, stable string standing for the current version of every
// member -- equal across runs (and processes) exactly when every member's
// version is unchanged, nothing more. It is what a Store entry is stamped
// with. A member resolves against recognize.Default first (a Recognizer's own
// Version), then VersionFuncs, then Versions, so a Domain can mix recognizer
// names, VersionFuncs names and plain Versions keys freely.
func (d Domain) Version() string {
	pairs := make([]string, 0, len(d.Members))
	for _, m := range d.Members {
		v := Versions[m]
		if r, ok := recognize.Default.ByName(m); ok {
			v = r.Version()
		} else if f, ok := VersionFuncs[m]; ok {
			v = f()
		}
		pairs = append(pairs, m+"="+strconv.Itoa(v))
	}
	sort.Strings(pairs)
	sum := sha256.Sum256([]byte(strings.Join(pairs, ",")))
	return hex.EncodeToString(sum[:])[:16]
}

// Predefined Domains for this tool's own operations. A library consumer with
// its own recognizers defines its own Domain the same way: a name and the
// member names it depends on -- a recognizer's own Name() needs nothing
// further, a plain parser needs an entry added to Versions.
var (
	// Recon is a file's full text report (recon <file>): every recognizer in the
	// chain cmd_recon.go's runFileRecon tries, since it is tried on every file
	// regardless of what that file turns out to be.
	Recon = Domain{"recon", []string{
		"filetype", "motorola-artifact", "hkmc-artifact", "telechips-artifact",
		"fsg-artifact", "qcom-artifact", "mediatek-artifact", "samsung-pit",
		"androidkeys", "pemfile", "unixauth",
		"npkg", "lkrom", "dtbo", "fdt", "ubi", "ubifs", "qcdt", "bootimg",
		"blankflash", "bootelf", "secboot", "facts",
	}}
	// Listing is a container's children (ls/tree/browse/extract): the
	// neutral and vendor container Expanders that decide what a container
	// holds and how its members are named.
	Listing = Domain{"listing", []string{
		"carve-containers", "npkg", "lkrom", "ubi", "ubifs",
		"motorola-artifact", "hkmc-artifact", "telechips-artifact",
		"fsg-artifact", "qcom-artifact", "mediatek-artifact", "samsung-pit",
	}}
	// Label is the short one-line type name a listing or recon shows for a file
	// (typeLabel): the same recognizer chain as Recon, since it is the same
	// dispatch, just asked for one line instead of the full report.
	Label = Recon
)

// Store is a text-only, append-only cache file: one JSON-lines record per
// write, the last record for a key winning on load -- the same convention
// internal/hashcache uses, so a damaged or missing file is just an empty cache,
// never an error this tool's callers have to handle.
// Store is sharded on disk by (Domain, Domain.Version()): one file per
// generation, e.g. ".../recon-cache.recon.3f9a2b1c.jsonl". A generation
// becomes permanently unreachable through Get/Put the instant its domain's
// Version() moves on -- shardPath always names the *current* version, so an
// old generation's file is never even opened again, let alone scanned record
// by record to find out it's stale. That makes reclaiming the space trivial
// (Prune: delete any shard file whose version isn't the live one, by name
// alone) and keeps every file small and homogeneous, which matters if it's
// ever compressed (one coherent blob per generation, not one tiny frame per
// write or one giant file mixing every version ever seen).
type Store struct {
	path string

	mu     sync.Mutex // guards shards itself, not what's inside one
	shards map[string]*shard
}

// shard is one generation's state: the file one (Domain, Version) pair is
// stored in, loaded lazily and independently of every other shard.
type shard struct {
	mu      sync.Mutex
	loaded  bool
	entries map[string]string // key -> text
	out     *os.File
}

type record struct {
	Key  string `json:"k"`
	Text string `json:"t"`
}

// Open returns a Store backed by path, read lazily on first use. path == ""
// makes an in-memory store (nothing persists between processes) -- useful for
// a library consumer that wants the invalidation behavior without a file, and
// for tests.
func Open(path string) *Store { return &Store{path: path, shards: map[string]*shard{}} }

// Default is the store the CLI's own recon/listing/label caches use:
// $UNBRICK_RECON_CACHE, or <user cache dir>/go-unbrick/recon-cache.jsonl, read
// the first time anything asks it for something. Set DefaultPath before that
// to change where it lives; a library consumer that wants its own location (or
// no persistence) uses Open instead and ignores this entirely.
var Default = Open("")

// DefaultPath is Default's file; empty resolves it as described there. Set it
// before Default's first use (its path is fixed once that happens).
var DefaultPath string

func (s *Store) resolvePath() string {
	if s != Default {
		return s.path
	}
	if DefaultPath != "" {
		return DefaultPath
	}
	if p := os.Getenv("UNBRICK_RECON_CACHE"); p != "" {
		return p
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "go-unbrick", "recon-cache.jsonl")
}

// shardPath is the file domain's current generation is stored in: the base
// path (resolvePath) with the domain's name and current Version() inserted
// before its extension. "" when resolvePath is (an in-memory store).
func (s *Store) shardPath(domain Domain) string {
	base := s.resolvePath()
	if base == "" {
		return ""
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return fmt.Sprintf("%s.%s.%s%s", stem, domain.Name, domain.Version(), ext)
}

// shardFor is domain's shard, creating its in-memory state (not yet loaded
// from disk) the first time it's asked for.
func (s *Store) shardFor(domain Domain) (*shard, string) {
	p := s.shardPath(domain)
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.shards[p]
	if !ok {
		sh = &shard{entries: map[string]string{}}
		s.shards[p] = sh
	}
	return sh, p
}

func (sh *shard) load(path string) {
	if sh.loaded {
		return
	}
	sh.loaded = true
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 4<<20) // a cached report can run to many lines
	for sc.Scan() {
		var r record
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Key != "" {
			sh.entries[r.Key] = r.Text
		}
	}
}

// Get returns the text cached for key under domain, from the shard domain's
// current Version names -- a stale entry (the domain's members' Versions
// have moved since this was written) was stamped into a *different* shard
// file, so it is never even looked at, let alone matched against: this
// simply misses, same as one never written.
func (s *Store) Get(domain Domain, key string) (text string, ok bool) {
	if key == "" {
		return "", false
	}
	sh, p := s.shardFor(domain)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.load(p)
	text, ok = sh.entries[key]
	return text, ok
}

// Put records text for key, in domain's current shard. Failing to persist it
// is not an error: the next Get simply misses, same as a cold cache.
func (s *Store) Put(domain Domain, key, text string) {
	if key == "" {
		return
	}
	sh, p := s.shardFor(domain)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.load(p)
	if old, ok := sh.entries[key]; ok && old == text {
		return
	}
	sh.entries[key] = text
	if p == "" {
		return // in-memory store: the map above is the whole of it
	}
	if sh.out == nil {
		if os.MkdirAll(filepath.Dir(p), 0o755) != nil {
			return
		}
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		sh.out = f
	}
	b, err := json.Marshal(record{Key: key, Text: text})
	if err != nil {
		return
	}
	// Led by a newline too: a peer process killed mid-write leaves an unterminated
	// line, which would otherwise swallow this record. One write, so O_APPEND keeps
	// concurrent processes' records whole.
	b = append(append([]byte{'\n'}, b...), '\n')
	_, _ = sh.out.Write(b)
}

// Prune deletes every on-disk shard file for one of domains whose generation
// is no longer current -- the ones a Version bump already made permanently
// unreachable through Get/Put. Safe to call any time, from any process: it
// only ever removes files nothing will read from again, by comparing the
// version named in each file against domain.Version() now, never by opening
// or scanning one. Returns how many files it removed.
func (s *Store) Prune(domains ...Domain) (removed int, err error) {
	base := s.resolvePath()
	if base == "" {
		return 0, nil
	}
	dir := filepath.Dir(base)
	ext := filepath.Ext(base)
	stem := filepath.Base(strings.TrimSuffix(base, ext))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	live := make(map[string]string, len(domains)) // domain name -> current version
	for _, d := range domains {
		live[d.Name] = d.Version()
	}
	prefix := stem + "."
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ext) {
			continue
		}
		mid := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ext) // "domainName.version"
		i := strings.LastIndex(mid, ".")
		if i < 0 {
			continue
		}
		domName, ver := mid[:i], mid[i+1:]
		cur, known := live[domName]
		if !known || ver == cur {
			continue // not one of the given domains, or still current
		}
		if rmErr := os.Remove(filepath.Join(dir, name)); rmErr == nil {
			removed++
		}
	}
	return removed, nil
}

// Prune is Default's, for the common case of one process-wide cache.
func Prune(domains ...Domain) (int, error) { return Default.Prune(domains...) }

// Get and Put are Default's, for the common case of one process-wide cache
// (the CLI's own usage): Get(cache.Recon, key) reads as "the recon cache."
func Get(domain Domain, key string) (string, bool) { return Default.Get(domain, key) }
func Put(domain Domain, key, text string)          { Default.Put(domain, key, text) }
