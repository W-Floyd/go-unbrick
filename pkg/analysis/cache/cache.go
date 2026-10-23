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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Versions is every format recognizer/parser this cache's callers depend on,
// named, at its current behavior version. Add an entry the first time a
// recognizer's result is cached; from then on, raise its number -- never
// reuse, remove, or renumber one others already refer to by name -- whenever
// its behavior changes for bytes it would already have been asked about.
//
// Names are the package or check they stand for, not the Domain that uses
// them: "npkg" might gate both the "recon" and "listing" Domains at once.
var Versions = map[string]int{
	"filetype":           1, // internal/filetype.Detect: the neutral magic-byte switch
	"motorola-artifact":  1, // internal/vendor.MotorolaRecognizer
	"hkmc-artifact":      1, // internal/vendor.HKMCRecognizer
	"telechips-artifact": 1, // internal/vendor.TelechipsArtifactRecognizer
	"fsg-artifact":       1, // internal/vendor.FSGRecognizer
	"qcom-artifact":      1, // internal/vendor.QcomRecognizer
	"mediatek-artifact":  1, // internal/vendor.MediatekRecognizer
	"samsung-pit":        1, // internal/vendor.SamsungPITRecognizer
	"androidkeys":        1, // internal/androidkeys
	"pemfile":            1, // internal/pemfile
	"unixauth":           1, // internal/unixauth
	"npkg":               1, // internal/npkg
	"lkrom":              1, // internal/telechips (LKROM parsing)
	"dtbo":               1, // internal/dtbo
	"fdt":                1, // internal/fdt (bare device tree)
	"ubi":                1, // internal/ubi
	"ubifs":              1, // internal/ubifs
	"qcdt":               1, // internal/qcdt
	"bootimg":            1, // internal/bootimg
	"blankflash":         1, // internal/blankflash (SINGLE_N_LONELY)
	"bootelf":            1, // internal/bootelf
	"secboot":            1, // internal/secboot (signing identity)
	"carve-containers":   1, // internal/carve's own neutral container Expanders (zip/tar/ext4/...)
	"facts":              1, // the fact-derivation graph recon runs (internal/facts providers)
}

// Domain is a named, independently versioned slice of the cache: see the
// package doc for what one is and why operations are grouped this way instead
// of per-recognizer.
type Domain struct {
	Name    string
	Members []string // keys into Versions
}

// Version is a short, stable string standing for the current Versions of every
// member -- equal across runs (and processes) exactly when every member's
// number is unchanged, nothing more. It is what a Store entry is stamped with.
func (d Domain) Version() string {
	pairs := make([]string, 0, len(d.Members))
	for _, m := range d.Members {
		pairs = append(pairs, m+"="+strconv.Itoa(Versions[m]))
	}
	sort.Strings(pairs)
	sum := sha256.Sum256([]byte(strings.Join(pairs, ",")))
	return hex.EncodeToString(sum[:])[:16]
}

// Predefined Domains for this tool's own operations. A library consumer with
// its own recognizers defines its own Domain the same way: a name and the
// Versions keys it depends on (adding its own entries to Versions, or to a
// Store-local copy -- see Store.Versions).
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
type Store struct {
	path string

	mu      sync.Mutex
	loaded  bool
	entries map[string]record
	out     *os.File
}

type record struct {
	Key     string `json:"k"`
	Domain  string `json:"d"`
	Version string `json:"v"`
	Text    string `json:"t"`
}

// Open returns a Store backed by path, read lazily on first use. path == ""
// makes an in-memory store (nothing persists between processes) -- useful for
// a library consumer that wants the invalidation behavior without a file, and
// for tests.
func Open(path string) *Store { return &Store{path: path} }

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

func (s *Store) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	s.entries = map[string]record{}
	p := s.resolvePath()
	if p == "" {
		return
	}
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 4<<20) // a cached report can run to many lines
	for sc.Scan() {
		var r record
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Key != "" {
			s.entries[r.Key] = r
		}
	}
}

// Get returns the text cached for key under domain, if domain's version
// matches what it was stamped with -- a stale entry (the domain's members'
// Versions have moved since) is reported as a miss, same as one never written.
func (s *Store) Get(domain Domain, key string) (text string, ok bool) {
	if key == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	r, ok := s.entries[key]
	if !ok || r.Domain != domain.Name || r.Version != domain.Version() {
		return "", false
	}
	return r.Text, true
}

// Put records text for key under domain, stamped with domain's current
// version. Failing to persist it is not an error: the next Get simply misses,
// same as a cold cache.
func (s *Store) Put(domain Domain, key, text string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	r := record{Key: key, Domain: domain.Name, Version: domain.Version(), Text: text}
	if old, ok := s.entries[key]; ok && old == r {
		return
	}
	s.entries[key] = r
	p := s.resolvePath()
	if p == "" {
		return // in-memory store: the map above is the whole of it
	}
	if s.out == nil {
		if os.MkdirAll(filepath.Dir(p), 0o755) != nil {
			return
		}
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		s.out = f
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = s.out.Write(b)
}

// Get and Put are Default's, for the common case of one process-wide cache
// (the CLI's own usage): Get(cache.Recon, key) reads as "the recon cache."
func Get(domain Domain, key string) (string, bool) { return Default.Get(domain, key) }
func Put(domain Domain, key, text string)          { Default.Put(domain, key, text) }
