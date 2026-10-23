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
