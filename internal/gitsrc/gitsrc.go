// Package gitsrc makes a kernel source tree out of a git origin URL, for a
// caller that wants to read a tree it does not have on disk. Every source is
// fetched shallowly into one shared bare repository in the cache, so the
// objects forks have in common (most of them) are stored, and downloaded, once;
// only the files a caller asks for are written out, straight from the object
// database: the device-tree directories for matching a SoC, and (when the tree
// turns out to be the one to port against) the driver, binding and Kconfig
// files too. The cache is kept, so a tree is fetched once.
//
// The fetch uses the git binary when there is one: its negotiation sends the
// server what the repository already has, which go-git's shallow fetch does not
// (a second fork cost 18 MB through git and 292 MB through go-git). Without git
// the fetch falls back to go-git, correct but with no sharing. Reading is
// always go-git.
package gitsrc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
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

func (s Source) hash() string {
	sum := sha256.Sum256([]byte(s.String()))
	return hex.EncodeToString(sum[:])[:16]
}

// Dir is where the source's tree is written under a cache directory.
func (s Source) Dir(cache string) string { return filepath.Join(cache, s.hash()) }

// repoDir is the one bare repository every source is fetched into.
func repoDir(cache string) string { return filepath.Join(cache, "kernels.git") }

// localRef is where the source's commit is kept in the shared repository.
func (s Source) localRef() string { return "refs/unbrick/" + s.hash() }

// useCLI says to fetch with the git binary when it is installed; a test turns
// it off to exercise the go-git fallback.
var useCLI = true

// Ensure fetches the source if it is not cached and writes out what level asks
// for, returning the directory to read as a kernel tree. progress, when set,
// is told what is happening (a fetch is the slow part).
func Ensure(s Source, cache string, level Level, progress io.Writer) (string, error) {
	tree := filepath.Join(s.Dir(cache), s.Label())
	if _, err := os.Stat(filepath.Join(tree, level.marker())); err == nil {
		return tree, nil
	}
	repo, err := openShared(cache)
	if err != nil {
		return "", err
	}
	ref, err := repo.Reference(plumbing.ReferenceName(s.localRef()), true)
	if err != nil {
		how := "git"
		if _, lerr := exec.LookPath("git"); lerr != nil || !useCLI {
			how = "go-git, which cannot share objects between sources"
		}
		if progress != nil {
			fmt.Fprintf(progress, "fetching %s with %s, into the shared repository %s\n", s, how, repoDir(cache))
		}
		if err := fetch(s, cache); err != nil {
			return "", fmt.Errorf("fetching %s: %w", s, err)
		}
		if repo, err = openShared(cache); err != nil {
			return "", err
		}
		if ref, err = repo.Reference(plumbing.ReferenceName(s.localRef()), true); err != nil {
			return "", fmt.Errorf("fetching %s: %w", s, err)
		}
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return "", err
	}
	files, err := commit.Files()
	if err != nil {
		return "", err
	}
	if progress != nil {
		fmt.Fprintf(progress, "writing the %s files of %s (%s)\n", map[Level]string{DTS: "device-tree", Full: "driver and Kconfig"}[level], s, ref.Hash().String()[:12])
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
			if err := os.WriteFile(filepath.Join(tree, l.marker()), []byte(ref.Hash().String()+"\n"), 0o644); err != nil {
				return "", err
			}
		}
	}
	return tree, nil
}

// openShared opens the shared bare repository, creating it first if need be.
func openShared(cache string) (*git.Repository, error) {
	dir := repoDir(cache)
	if r, err := git.PlainOpen(dir); err == nil {
		return r, nil
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return nil, err
	}
	return git.PlainInit(dir, true)
}

// fetch brings one commit of the source into the shared repository under its
// local ref.
func fetch(s Source, cache string) error {
	var srcs []string // what to ask the remote for, in order
	if s.Ref == "" {
		srcs = []string{"HEAD"}
	} else {
		srcs = []string{"refs/heads/" + s.Ref, "refs/tags/" + s.Ref}
	}
	var errs []error
	for _, src := range srcs {
		var err error
		if _, lerr := exec.LookPath("git"); lerr == nil && useCLI {
			err = fetchCLI(s, cache, src)
		} else {
			err = fetchGoGit(s, cache, src)
		}
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", src, err))
	}
	return errors.Join(errs...)
}

// fetchCLI is a shallow fetch by the git binary. It sends the server what the
// repository already has, so a source that mostly matches one already fetched
// costs the difference.
func fetchCLI(s Source, cache, src string) error {
	cmd := exec.Command("git", "--git-dir", repoDir(cache), "fetch", "--quiet", "--depth", "1", "--no-tags", s.URL, "+"+src+":"+s.localRef())
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0") // fail, do not ask for a password
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git fetch: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// fetchGoGit is the same fetch through go-git: it works with no git installed,
// but does not tell the server what is already here, so it downloads a full
// snapshot every time.
func fetchGoGit(s Source, cache, src string) error {
	repo, err := git.PlainOpen(repoDir(cache))
	if err != nil {
		return err
	}
	name := "src-" + s.hash()
	if _, err := repo.Remote(name); err != nil {
		if _, err := repo.CreateRemote(&config.RemoteConfig{Name: name, URLs: []string{s.URL}}); err != nil {
			return err
		}
	}
	// A server resolves "HEAD" itself; go-git wants a ref name.
	if src == "HEAD" {
		return fetchDefaultBranch(repo, name, s)
	}
	err = repo.Fetch(&git.FetchOptions{RemoteName: name, Depth: 1, Tags: git.NoTags,
		RefSpecs: []config.RefSpec{config.RefSpec("+" + src + ":" + s.localRef())}})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return err
	}
	return nil
}

// fetchDefaultBranch asks the remote what its HEAD points at, then fetches that.
func fetchDefaultBranch(repo *git.Repository, name string, s Source) error {
	rem, err := repo.Remote(name)
	if err != nil {
		return err
	}
	refs, err := rem.List(&git.ListOptions{})
	if err != nil {
		return err
	}
	var head string
	for _, r := range refs {
		if r.Name() == plumbing.HEAD && r.Type() == plumbing.SymbolicReference {
			head = r.Target().String()
		}
	}
	if head == "" {
		return errors.New("the remote has no HEAD")
	}
	err = repo.Fetch(&git.FetchOptions{RemoteName: name, Depth: 1, Tags: git.NoTags,
		RefSpecs: []config.RefSpec{config.RefSpec("+" + head + ":" + s.localRef())}})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return err
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
