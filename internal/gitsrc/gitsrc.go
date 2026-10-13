// Package gitsrc makes a kernel source tree out of a git origin URL, for a
// caller that wants to read a tree it does not have on disk. It clones the
// default (or named) branch shallowly into a cache and writes out only the
// files a caller asks for, straight from the object database: the device-tree
// directories for matching a SoC, and (when the tree turns out to be the one
// to port against) the driver, binding and Kconfig files too. The cache is
// kept, so a tree is fetched once.
package gitsrc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Source is a git origin and the branch or tag to take from it.
type Source struct {
	URL string
	Ref string // "" is the remote's default branch
}

// Parse reads a --kernel-tree value as a git source: an http(s), git, ssh or
// file URL, or an scp-style "git@host:path", optionally followed by "#ref".
// ok is false for anything else, which is a path on disk.
func Parse(s string) (Source, bool) {
	url, ref, _ := strings.Cut(s, "#")
	for _, p := range []string{"http://", "https://", "git://", "ssh://", "file://", "git@"} {
		if strings.HasPrefix(url, p) {
			return Source{URL: url, Ref: ref}, true
		}
	}
	return Source{}, false
}

func (s Source) String() string {
	if s.Ref == "" {
		return s.URL
	}
	return s.URL + "#" + s.Ref
}

// Level is how much of the tree to write out.
type Level int

const (
	// DTS is the device-tree directories and their binding headers: enough to
	// rank the tree's SoC files against a stock device tree.
	DTS Level = iota
	// Full adds the driver, sound and binding sources and every Kconfig file:
	// what the rest of a port reads from its target tree.
	Full
)

func (l Level) marker() string {
	if l == Full {
		return ".unbrick-full"
	}
	return ".unbrick-dts"
}

// wanted says whether a path in the tree is written at a level.
func wanted(l Level, p string) bool {
	if strings.HasPrefix(p, "arch/arm64/boot/dts/") || strings.HasPrefix(p, "include/dt-bindings/") {
		return true
	}
	if l != Full {
		return false
	}
	if strings.HasPrefix(path.Base(p), "Kconfig") {
		return true
	}
	switch path.Ext(p) {
	case ".c", ".yaml", ".txt":
		return strings.HasPrefix(p, "drivers/") || strings.HasPrefix(p, "sound/") || strings.HasPrefix(p, "Documentation/devicetree/bindings/")
	}
	return false
}

// DefaultCache is where trees are kept: <user cache>/go-unbrick/trees.
func DefaultCache() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "go-unbrick", "trees"), nil
}

// Dir is where the source's tree is written under a cache directory.
func (s Source) Dir(cache string) string {
	sum := sha256.Sum256([]byte(s.String()))
	return filepath.Join(cache, hex.EncodeToString(sum[:])[:16])
}

// Ensure fetches the source if it is not cached and writes out what level asks
// for, returning the directory to read as a kernel tree. progress, when set,
// is told what is happening (a fetch is the slow part).
func Ensure(s Source, cache string, level Level, progress io.Writer) (string, error) {
	root := s.Dir(cache)
	repoDir, tree := filepath.Join(root, "repo.git"), filepath.Join(root, s.Label())
	if _, err := os.Stat(filepath.Join(tree, level.marker())); err == nil {
		return tree, nil
	}
	if _, err := os.Stat(repoDir); err != nil {
		if progress != nil {
			fmt.Fprintf(progress, "fetching %s (one shallow clone, cached under %s)\n", s, root)
		}
		if err := clone(s, repoDir); err != nil {
			os.RemoveAll(repoDir)
			return "", fmt.Errorf("fetching %s: %w", s, err)
		}
	}
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return "", err
	}
	head, err := repo.Head()
	if err != nil {
		return "", err
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return "", err
	}
	files, err := commit.Files()
	if err != nil {
		return "", err
	}
	if progress != nil {
		fmt.Fprintf(progress, "writing the %s files of %s (%s)\n", map[Level]string{DTS: "device-tree", Full: "driver and Kconfig"}[level], s, head.Hash().String()[:12])
	}
	err = files.ForEach(func(f *object.File) error {
		if !wanted(level, f.Name) {
			return nil
		}
		dst := filepath.Join(tree, filepath.FromSlash(f.Name))
		if _, err := os.Stat(dst); err == nil {
			return nil // written at a lower level
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		r, err := f.Reader()
		if err != nil {
			return err
		}
		defer r.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, r); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(tree, 0o755); err != nil {
		return "", err
	}
	for _, l := range []Level{DTS, Full} {
		if l <= level {
			if err := os.WriteFile(filepath.Join(tree, l.marker()), []byte(head.Hash().String()+"\n"), 0o644); err != nil {
				return "", err
			}
		}
	}
	return tree, nil
}

// clone fetches one commit of the source into a bare repository.
func clone(s Source, dir string) error {
	// The server's own progress (thousands of "Counting objects" lines) is not
	// passed on; the caller says what is happening.
	opts := &git.CloneOptions{URL: s.URL, Depth: 1, SingleBranch: true, Tags: git.NoTags}
	if s.Ref == "" {
		_, err := git.PlainClone(dir, true, opts)
		return err
	}
	// A ref is a branch, or failing that a tag.
	opts.ReferenceName = plumbing.NewBranchReferenceName(s.Ref)
	_, err := git.PlainClone(dir, true, opts)
	if err == nil {
		return nil
	}
	os.RemoveAll(dir)
	opts.ReferenceName = plumbing.NewTagReferenceName(s.Ref)
	if _, terr := git.PlainClone(dir, true, opts); terr != nil {
		return errors.Join(fmt.Errorf("as a branch: %w", err), fmt.Errorf("as a tag: %w", terr))
	}
	return nil
}

// Label is a readable directory name for the source's tree: the last two
// elements of its path and the ref ("mt6768-mainline-linux-cleanup"), so a
// report that names the tree by its directory says something.
func (s Source) Label() string {
	u := strings.TrimSuffix(s.URL, ".git")
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	u = strings.NewReplacer(":", "/", "@", "/").Replace(u)
	parts := strings.Split(strings.Trim(u, "/"), "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	l := strings.Join(parts, "-")
	if s.Ref != "" {
		l += "-" + s.Ref
	}
	var b strings.Builder
	for _, r := range strings.ToLower(l) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "tree"
	}
	return b.String()
}
