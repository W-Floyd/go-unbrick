// Package srcdiff compares a vendor's source tree against the upstream it was
// taken from, by git blob id: a file is unchanged when its content hashes to the
// id upstream has for it, so only the files that differ are ever read from
// upstream. What is left over is the vendor's own change.
package srcdiff

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

// BlobSHA is the id git gives content of size bytes: SHA-1 over "blob <size>\0"
// and the content.
func BlobSHA(r io.Reader, size int64) (string, error) {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", size)
	n, err := io.Copy(h, r)
	if err != nil {
		return "", err
	}
	if n != size {
		return "", fmt.Errorf("read %d bytes, expected %d", n, size)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// File is one file of the tree being compared.
type File struct {
	Path string // relative to the tree's root
	Size int64
	Open func() (io.ReadCloser, error)
}

// Modified is a file present on both sides with different content.
type Modified struct {
	Path        string
	UpstreamSHA string
	// EOLOnly says the two are the same once line endings are normalised.
	EOLOnly bool
}

// Result is the comparison of a tree against its upstream.
type Result struct {
	Prefix       string // upstream path the tree's root was matched to ("" for the top)
	Identical    []string
	Modified     []Modified
	VendorOnly   []string // in the tree, not upstream
	UpstreamOnly []string // upstream, not in the tree
}

// Align finds where in upstream a tree's root sits: the directory prefix that the
// most of a sample of the tree's paths are found under. "" means the root itself.
// The paths need not be identical in content, only in name.
func Align(local []string, upstream map[string]string) string {
	if len(local) == 0 {
		return ""
	}
	// A sample spread over the tree, favouring deeper paths: they are the most
	// distinctive.
	sorted := append([]string(nil), local...)
	sort.Slice(sorted, func(i, j int) bool {
		di, dj := strings.Count(sorted[i], "/"), strings.Count(sorted[j], "/")
		if di != dj {
			return di > dj
		}
		return sorted[i] < sorted[j]
	})
	if len(sorted) > 200 {
		sorted = sorted[:200]
	}
	byBase := map[string][]string{}
	for p := range upstream {
		b := p[strings.LastIndexByte(p, '/')+1:]
		byBase[b] = append(byBase[b], p)
	}
	votes := map[string]int{}
	for _, rel := range sorted {
		b := rel[strings.LastIndexByte(rel, '/')+1:]
		for _, u := range byBase[b] {
			if u == rel {
				votes[""]++
			} else if strings.HasSuffix(u, "/"+rel) {
				votes[u[:len(u)-len(rel)]]++
			}
		}
	}
	best, n := "", 0
	for p, v := range votes {
		if v > n || (v == n && len(p) < len(best)) {
			best, n = p, v
		}
	}
	return best
}

// Compare matches the tree against upstream under prefix. eolEqual, if set, is
// asked of each differing file whether it differs only in line endings; it is
// given the file and upstream's id for it.
func Compare(local []File, upstream map[string]string, prefix string, eolEqual func(File, string) bool) (Result, error) {
	res := Result{Prefix: prefix}
	seen := map[string]bool{}
	for _, f := range local {
		up, ok := upstream[prefix+f.Path]
		if !ok {
			res.VendorOnly = append(res.VendorOnly, f.Path)
			continue
		}
		seen[prefix+f.Path] = true
		rc, err := f.Open()
		if err != nil {
			return res, fmt.Errorf("%s: %w", f.Path, err)
		}
		sha, err := BlobSHA(rc, f.Size)
		rc.Close()
		if err != nil {
			return res, fmt.Errorf("%s: %w", f.Path, err)
		}
		if sha == up {
			res.Identical = append(res.Identical, f.Path)
			continue
		}
		m := Modified{Path: f.Path, UpstreamSHA: up}
		if eolEqual != nil {
			m.EOLOnly = eolEqual(f, up)
		}
		res.Modified = append(res.Modified, m)
	}
	for p := range upstream {
		if strings.HasPrefix(p, prefix) && !seen[p] {
			res.UpstreamOnly = append(res.UpstreamOnly, strings.TrimPrefix(p, prefix))
		}
	}
	sort.Strings(res.UpstreamOnly)
	sort.Strings(res.VendorOnly)
	sort.Strings(res.Identical)
	sort.Slice(res.Modified, func(i, j int) bool { return res.Modified[i].Path < res.Modified[j].Path })
	return res, nil
}
