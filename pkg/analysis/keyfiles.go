package analysis

import (
	"bytes"
	"context"
	"encoding/hex"
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

// FindKeyFiles looks for the key files the vendors name (vendor.KeyFilePatterns) anywhere in input (a directory, or a file carve
// opens), going into containers down to depth levels, as the secrets loaded (LoadSecrets) allow:
// an encrypted image is only gone into if a key opens it. It stops, with what it has so far, when
// ctx ends. progress, if set, is told after each container is opened how many have been, how many key
// files are found so far, and the path of the container just opened.
func FindKeyFiles(ctx context.Context, input string, depth int, progress func(opened, found int, at string)) ([]KeyFile, error) {
	opened := 0
	top, err := OpenInput(input, nil)
	if err != nil {
		return nil, err
	}
	var out []KeyFile
	var walk func(l *BrowseLevel, depth int)
	walk = func(l *BrowseLevel, depth int) {
		for _, e := range l.Entries {
			if ctx.Err() != nil {
				return
			}
			dir := e.Dir || e.Group != nil
			if !dir && IsKeyFile(e.Path) {
				b, _, err := ReadEntry(e, keyFileMax)
				if err == nil && len(b) > 0 {
					name := e.Name
					out = append(out, KeyFile{Path: e.Path, Name: name, Size: len(b), Value: describeKey(b), Known: knownKey(b)})
				}
				continue
			}
			if !dir {
				// Text and images are not containers; a file on disk that is neither may be one.
				if e.Text || e.Image || (e.OSPath == "" && !e.Container) || depth <= 0 {
					continue
				}
			}
			next := depth
			if !dir {
				next-- // opening a container spends a level; a directory does not
			}
			sub, err := openRaw(e, nil)
			if err != nil {
				continue
			}
			sub.setPaths(e.Path + "/")
			if !dir {
				opened++
				if progress != nil {
					progress(opened, len(out), e.Path)
				}
			}
			walk(sub, next)
		}
	}
	walk(top, depth)
	return out, ctx.Err()
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

// knownKey names the loaded secret whose key or IV is the file's content.
func knownKey(b []byte) string {
	k := keyBytes(b)
	for _, s := range aeskeys.Secrets() {
		if bytes.Equal(s.Key, k) || bytes.Equal(s.IV, k) {
			return strings.TrimSuffix(s.Name, " (zero IV)")
		}
	}
	return ""
}
