package analysis

import (
	"bytes"
	"context"
	"encoding/hex"
	"path"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// KeyFile is a file a vendor says holds a key or IV (an HKMC package's iv.dat and image.dat: the secrets
// an on-device updater keeps for the next package's enc_ members), found inside an input. Where they sit
// changes from package to package.
type KeyFile struct {
	Path  string `json:"path"`  // from the input's root, through nested containers
	Name  string `json:"name"`  // the file's own name
	Size  int    `json:"size"`  // bytes
	Value string `json:"value"` // its text if one line of text, else hex (the first 64 bytes)
	// Known is the loaded secret whose key or IV this is, "" if none: a key not yet in the
	// secrets directory is new.
	Known string `json:"known,omitempty"`
}

// keyFileMax is as much of one file as is read: a key or IV is a few dozen bytes.
const keyFileMax = 4096

// IsKeyFile says whether a path (from an input's root, through nested containers) is one the vendors
// name as holding a key or IV: where a key is expected to be, as against found somewhere else.
func IsKeyFile(path string) bool {
	for _, re := range vendor.KeyFilePatterns() {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// KeyUse is an encrypted member of an input that a loaded secret opens: which key goes with which package.
type KeyUse struct {
	Path   string `json:"path"`   // from the input's root, through nested containers
	Secret string `json:"secret"` // the loaded secret's name (the file the key came from)
	// The key and IV that opened it, together: each by the file it came from and its value in hex, and how the data
	// is framed ("" for CBC under the IV, "ecb", or "prefix" when the first block is the IV).
	KeyFile string `json:"keyFile,omitempty"`
	Key     string `json:"key,omitempty"`
	IVFile  string `json:"ivFile,omitempty"`
	IV      string `json:"iv,omitempty"`
	Mode    string `json:"mode,omitempty"`
}

// KeyScan is what searching an input for keys found.
type KeyScan struct {
	Files    []KeyFile // the key files the vendors name
	Uses     []KeyUse  // encrypted members, and the loaded secret that opens each
	Unopened []string  // members named enc_ that no loaded secret opens
}

// Observe records what one entry shows of keys, for a host that walks an input itself and wants this on the way:
// a key file the vendors name is read, and an enc_ member is noted as opened by a loaded secret (with the key and
// IV together) or as opened by none. path is the entry's full path from the input's root; sub is the level the
// entry opened into, nil if it did not open. It reads a few bytes of a key file and the head of an enc_ member.
func (k *KeyScan) Observe(path string, e BrowseEntry, sub *BrowseLevel) {
	if e.Dir || e.Group != nil {
		return
	}
	if IsKeyFile(path) {
		b, _, err := ReadEntry(e, keyFileMax)
		if err == nil && len(b) > 0 {
			k.Files = append(k.Files, KeyFile{Path: path, Name: e.Name, Size: len(b), Value: describeKey(b), Known: knownKey(b, e.Name)})
		}
		return
	}
	if strings.HasPrefix(e.Name, "enc_") {
		if sub != nil {
			if use, ok := secretFor(path, e, sub); ok {
				k.Uses = append(k.Uses, use)
				return
			}
		}
		k.Unopened = append(k.Unopened, path)
	}
}

// RefreshKnown works out afresh, from the values, which loaded file each key file's content is: a key added to the
// secrets since a package was searched turns what was new into what is known, with nothing read again. It changes
// files in place.
func RefreshKnown(files []KeyFile) {
	for i, f := range files {
		b, err := hex.DecodeString(strings.TrimSuffix(strings.TrimSpace(f.Value), "…"))
		if err != nil {
			continue
		}
		files[i].Known = knownKey(b, f.Name)
	}
	resolveIVNames(files)
}

// Done settles what needs the whole scan: an IV several loaded files hold is named for the one that goes with the
// key beside it.
func (k *KeyScan) Done() { resolveIVNames(k.Files) }

// FindKeyFiles is ScanKeys' key files alone.
func FindKeyFiles(ctx context.Context, input string, depth int, skip []string, progress func(opened, found int, at string)) ([]KeyFile, error) {
	k, err := ScanKeys(ctx, input, depth, skip, progress)
	if k == nil {
		return nil, err
	}
	return k.Files, err
}

// ScanKeys looks through input (a directory, or a file carve opens), going into containers down to depth
// levels as the secrets loaded (LoadSecrets) allow, for the key files the vendors name
// (vendor.KeyFilePatterns), and for which loaded secret opens each encrypted member. An encrypted image is
// only gone into if a key opens it. skip leaves out entries whose path matches (see SkipPath); a skipped
// container is not opened. It stops, with what it has so far, when ctx ends. progress, if set, is told
// after each container is opened how many have been, how many key files are found so far, and the path of
// the container just opened.
func ScanKeys(ctx context.Context, input string, depth int, skip []string, progress func(opened, found int, at string)) (*KeyScan, error) {
	opened := 0
	top, err := OpenInput(input, nil)
	if err != nil {
		return nil, err
	}
	out := &KeyScan{}
	var walk func(l *BrowseLevel, depth int)
	walk = func(l *BrowseLevel, depth int) {
		for _, e := range l.Entries {
			if ctx.Err() != nil {
				return
			}
			if SkipPath(skip, e.Path) {
				continue
			}
			dir := e.Dir || e.Group != nil
			if !dir && IsKeyFile(e.Path) {
				out.Observe(e.Path, e, nil)
				continue
			}
			if !dir {
				// Text and images are not containers; a file on disk that is neither may be one.
				if e.Text || e.Image || (e.OSPath == "" && !e.Container) || depth <= 0 {
					if !e.Text && !e.Image {
						out.Observe(e.Path, e, nil) // an enc_ member that was not opened is noted
					}
					continue
				}
			}
			next := depth
			if !dir {
				next-- // opening a container spends a level; a directory does not
			}
			sub, err := openRaw(e, nil)
			if err != nil {
				out.Observe(e.Path, e, nil)
				continue
			}
			out.Observe(e.Path, e, sub)
			sub.setPaths(e.Path + "/")
			if !dir {
				opened++
				if progress != nil {
					progress(opened, len(out.Files), e.Path)
				}
			}
			walk(sub, next)
		}
	}
	walk(top, depth)
	out.Done()
	return out, ctx.Err()
}

// secretFor is the loaded secret that opened an enc_ member whose level is sub: it opened if its one child is the
// decrypted image, named without the prefix, and the secret is the one that decrypts the member's head.
func secretFor(path string, e BrowseEntry, sub *BrowseLevel) (KeyUse, bool) {
	if len(sub.Entries) != 1 || sub.Entries[0].Name != strings.TrimPrefix(e.Name, "enc_") {
		return KeyUse{}, false
	}
	head, _, err := ReadEntry(e, 8192)
	if err != nil || len(head) < 32 {
		return KeyUse{}, false
	}
	s, ok := aeskeys.SecretFor(head)
	if !ok {
		return KeyUse{}, false
	}
	return KeyUse{Path: path, Secret: s.Name, KeyFile: strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(s.Name, " (zero IV)"), " (ecb)"), " (prefixed IV)"),
		Key: hex.EncodeToString(s.Key), IVFile: s.IVName, IV: hex.EncodeToString(s.IV), Mode: s.Mode}, true
}

// describeKey shows a key file's content: its text if it is one line of text, else hex.
func describeKey(b []byte) string {
	if t := strings.TrimSpace(string(b)); len(t) > 0 && len(b) <= 256 && !strings.ContainsFunc(t, func(r rune) bool { return r < ' ' || r > '~' }) {
		return t
	}
	h := hex.EncodeToString(b[:min(len(b), 64)])
	if len(b) > 64 {
		h += "…"
	}
	return h
}

// keyBytes is the key or IV a file holds: the hex of a text file, else the bytes themselves.
func keyBytes(b []byte) []byte {
	if h, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(h) > 0 {
		return h
	}
	return b
}

// isIVFile says a key file holds an IV rather than a key, by its name: iv.dat beside image.dat.
func isIVFile(name string) bool { return strings.HasPrefix(strings.ToLower(name), "iv") }

func trimFraming(name string) string {
	for _, suf := range []string{" (zero IV)", " (ecb)", " (prefixed IV)"} {
		name = strings.TrimSuffix(name, suf)
	}
	return name
}

// loadedNames are the loaded files whose content is b, as an IV if iv is set and else as a key: the key's own
// file, or the IV's own, never the other's.
func loadedNames(b []byte, iv bool) []string {
	k := keyBytes(b)
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, s := range aeskeys.Secrets() {
		if iv && bytes.Equal(s.IV, k) {
			add(s.IVName)
		}
		if !iv && bytes.Equal(s.Key, k) {
			add(trimFraming(s.Name))
		}
	}
	return out
}

// knownKey names the loaded file whose content the key file's is: a key's own file, or an IV's. If several
// hold it the first is named; ScanKeys settles an IV by the key beside it.
func knownKey(b []byte, file string) string {
	if names := loadedNames(b, isIVFile(file)); len(names) > 0 {
		return names[0]
	}
	return ""
}

// resolveIVNames says, for an IV that more than one loaded file holds, which one goes with the key beside it: the
// one whose name has the most in common with that key's file (the files of one package share their prefix).
func resolveIVNames(files []KeyFile) {
	keyOf := map[string]string{} // directory -> the loaded file of the key in it
	for _, f := range files {
		if !isIVFile(f.Name) && f.Known != "" {
			keyOf[path.Dir(f.Path)] = f.Known
		}
	}
	for i, f := range files {
		if !isIVFile(f.Name) || keyOf[path.Dir(f.Path)] == "" {
			continue
		}
		b, _ := hex.DecodeString(strings.TrimSuffix(f.Value, "…"))
		best, bestScore := f.Known, -1
		for _, n := range loadedNames(b, true) {
			if sc := aeskeys.NameAffinity(keyOf[path.Dir(f.Path)], n); sc > bestScore {
				best, bestScore = n, sc
			}
		}
		files[i].Known = best
	}
}
