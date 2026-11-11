// Package zippasswords is the plain passwords a user keeps in a secrets
// directory to try against an encrypted zip member, alongside whatever a
// vendor derives for its own formats (internal/vendor's ZipPasswords).
//
// A secrets directory holds one or more *password*/*passwd*/*wordlist* files
// (found the same way internal/aeskeys finds *key*/*iv*: by the
// underscore/dash/dot-separated words in the file name), each a plain-text
// list of candidate passwords, one per line. Blank lines and lines starting
// with "#" are skipped. This never collides with aeskeys' own reading of the
// same directory: a key or IV file is hex of a fixed length, which a password
// list's content essentially never is, and vice versa.
package zippasswords

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

var nameWords = regexp.MustCompile(`[_.\-]+`)

var (
	mu     sync.RWMutex
	loaded []string
)

// Passwords is every candidate currently loaded, most-recently Load'd first.
func Passwords() []string {
	mu.RLock()
	defer mu.RUnlock()
	return loaded
}

// Count is how many candidates are loaded.
func Count() int { return len(Passwords()) }

// Set replaces the loaded candidates (a test puts back what it found).
func Set(p []string) {
	mu.Lock()
	loaded = p
	mu.Unlock()
}

// isPasswordFile says whether name (its stem, lowercased) names a password
// list by internal/aeskeys' own word-matching convention.
func isPasswordFile(stem string) bool {
	for _, w := range nameWords.Split(strings.ToLower(stem), -1) {
		switch w {
		case "password", "passwords", "passwd", "wordlist":
			return true
		}
	}
	return false
}

// Load reads every *password*/*passwd*/*wordlist* file in dir, replacing what
// was loaded. A directory with none is not an error: it simply loads nothing,
// same as one aeskeys.Load finds no keys in.
func Load(dir string) error {
	var out []string
	seen := map[string]bool{}
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		stem := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if !isPasswordFile(stem) {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			pw := strings.TrimRight(sc.Text(), "\r\n")
			if pw == "" || strings.HasPrefix(pw, "#") || seen[pw] {
				continue
			}
			seen[pw] = true
			out = append(out, pw)
		}
		return nil
	})
	if err != nil {
		return err
	}
	Set(out)
	return nil
}

// Remember adds pw to the loaded candidates, if it is new, and persists it to
// the found-password cache (cacheFile): a password a brute force paid to find
// (internal/carve.PasswordFound) is then free on every later run, with no
// --secrets directory needed to keep it.
func Remember(pw string) {
	mu.Lock()
	for _, p := range loaded {
		if p == pw {
			mu.Unlock()
			return
		}
	}
	loaded = append(loaded, pw)
	mu.Unlock()
	appendCache(pw)
}

// cacheFile is where Remember persists passwords and LoadCache reads them
// back from: the user's cache directory, not a --secrets directory, since a
// found password is not something the user supplied.
func cacheFile() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "go-unbrick", "zippasswords", "found.txt"), nil
}

// LoadCache loads every password Remember has ever persisted, on top of
// whatever is already loaded (a --secrets directory's own wordlists among
// them). A missing cache, or no cache directory at all, is not an error:
// brute force still works, it just has nothing free to start from.
func LoadCache() error {
	file, err := cacheFile()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	seen := make(map[string]bool, len(loaded))
	for _, p := range loaded {
		seen[p] = true
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		pw := strings.TrimRight(sc.Text(), "\r\n")
		if pw == "" || seen[pw] {
			continue
		}
		seen[pw] = true
		loaded = append(loaded, pw)
	}
	return nil
}

// appendCache adds pw to the found-password cache file. Failing to (no cache
// directory, a read-only one) is not an error a caller need act on: the
// password is still usable this run, Remember already added it to loaded.
func appendCache(pw string) {
	file, err := cacheFile()
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(file), 0o755) != nil {
		return
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, pw)
}

// WithVendor returns a carve.ZipPasswords-compatible function that tries
// base's passwords first (a vendor's own derivation, most likely to be
// right for its format) and every loaded password after, deduplicated.
// base is called even when nothing is loaded, so a plain vendor.ZipPasswords
// wrapped here behaves exactly as it did unwrapped.
func WithVendor(base func(zip *carve.Node, member string) []string) func(zip *carve.Node, member string) []string {
	return func(zip *carve.Node, member string) []string {
		out := base(zip, member)
		extra := Passwords()
		if len(extra) == 0 {
			return out
		}
		seen := make(map[string]bool, len(out))
		for _, p := range out {
			seen[p] = true
		}
		for _, p := range extra {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		return out
	}
}
