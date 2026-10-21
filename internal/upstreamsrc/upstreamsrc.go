// Package upstreamsrc reads a tree out of a git origin without checking it out:
// the file list with git's blob ids, and the content of the files asked for. It
// keeps one bare repository per origin in the cache, fetched as a partial clone
// (commits and trees, blobs on demand), so comparing a vendor's tree against
// upstream costs the tree listing and the few blobs that differ, not a download of
// the project. It needs the git binary.
package upstreamsrc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/matchcache"
	"github.com/W-Floyd/go-unbrick/internal/progress"
)

// Snapshot is one commit's tree.
type Snapshot struct {
	URL    string
	Ref    string
	Commit string            // the full commit id Ref resolved to
	Files  map[string]string // path to git blob id, regular files only
	// Symlinks are the paths that are links upstream: an archive may store one as a
	// file of its target or drop it, so they are not compared.
	Symlinks map[string]bool
	dir      string
	sizes    map[string]int64 // blob sizes learned by Sizes
}

var (
	fullSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	shortSHA = regexp.MustCompile(`^[0-9a-f]{7,39}$`)
)

// Open resolves ref ("" is the remote's HEAD; a branch, tag, or commit id, full or
// abbreviated) at url and lists its tree. progress, if set, is told what is being
// fetched.
func Open(url, ref, cache string, progress io.Writer) (*Snapshot, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, errors.New("upstream comparison needs the git binary")
	}
	sum := sha256.Sum256([]byte(url))
	s := &Snapshot{URL: url, Ref: ref, dir: filepath.Join(cache, "upstreams", hex.EncodeToString(sum[:8])+".git")}
	if err := s.init(); err != nil {
		return nil, err
	}
	say := func(f string, a ...any) {
		if progress != nil {
			fmt.Fprintf(progress, f+"\n", a...)
		}
	}
	commit, err := s.resolve(ref, say)
	if err != nil {
		return nil, err
	}
	s.Commit = commit
	if !s.has(commit) {
		say("fetching %s at %s", url, commit[:12])
		err := s.gitProgress("fetching "+shortURL(url), "fetch", "--depth", "1", "--filter=blob:none", "origin", commit)
		if err != nil && ref != "" && !fullSHA.MatchString(ref) {
			// A server that will not send a commit by id is asked for the name.
			err = s.gitProgress("fetching "+shortURL(url), "fetch", "--depth", "1", "--filter=blob:none", "origin",
				"+refs/tags/"+ref+":refs/tags/"+ref, "+refs/heads/"+ref+":refs/heads/"+ref)
			if err != nil {
				err = s.gitProgress("fetching "+shortURL(url), "fetch", "--depth", "1", "--filter=blob:none", "origin", "+refs/tags/"+ref+":refs/tags/"+ref)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", commit[:12], err)
		}
	}
	if err := s.listTree(commit); err != nil {
		return nil, err
	}
	return s, nil
}

// listTree reads the files of a commit held in the repository.
func (s *Snapshot) listTree(commit string) error {
	out, err := s.git("ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return err
	}
	s.Files, s.Symlinks = map[string]string{}, map[string]bool{}
	for _, rec := range bytes.Split(out, []byte{0}) {
		meta, path, ok := bytes.Cut(rec, []byte{'\t'})
		if !ok {
			continue
		}
		f := strings.Fields(string(meta)) // mode type sha
		switch {
		case len(f) == 3 && f[0] == "120000":
			s.Symlinks[string(path)] = true
		case len(f) == 3 && f[1] == "blob":
			s.Files[string(path)] = f[2]
		}
	}
	return nil
}

// Tag is a remote tag and the commit it names.
type Tag struct {
	Name   string
	Commit string
}

// ListTags lists url's tags, an annotated tag as the commit it points to.
func ListTags(url string) ([]Tag, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, errors.New("upstream comparison needs the git binary")
	}
	cmd := exec.Command("git", "ls-remote", "--tags", url)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-remote %s: %w", url, err)
	}
	commits := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !fullSHA.MatchString(f[0]) {
			continue
		}
		name := strings.TrimPrefix(f[1], "refs/tags/")
		if peeled, ok := strings.CutSuffix(name, "^{}"); ok {
			commits[peeled] = f[0] // the commit, over the tag object's own id
		} else if _, seen := commits[name]; !seen {
			commits[name] = f[0]
		}
	}
	tags := make([]Tag, 0, len(commits))
	for n, c := range commits {
		tags = append(tags, Tag{n, c})
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].Name < tags[j].Name })
	return tags, nil
}

// Repo is an origin's cached repository, for reading several commits of it.
type Repo struct{ s *Snapshot }

// OpenRepo makes the origin's repository ready, fetching nothing.
func OpenRepo(url, cache string) (*Repo, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, errors.New("upstream comparison needs the git binary")
	}
	sum := sha256.Sum256([]byte(url))
	s := &Snapshot{URL: url, dir: filepath.Join(cache, "upstreams", hex.EncodeToString(sum[:8])+".git")}
	if err := s.init(); err != nil {
		return nil, err
	}
	return &Repo{s}, nil
}

// Fetch brings in the trees of commits (one shallow fetch for all of them, so
// what they share is sent once), skipping those already held.
//
// A server that will not send a commit by id (many do not) is asked for the tags
// by name instead.
func (r *Repo) Fetch(label string, tags []Tag) error {
	var need []Tag
	for _, t := range tags {
		if !r.s.has(t.Commit) {
			need = append(need, t)
		}
	}
	for len(need) > 0 {
		chunk := need[:min(len(need), 40)]
		need = need[len(chunk):]
		byID := []string{"fetch", "--depth", "1", "--filter=blob:none", "origin"}
		byName := append([]string(nil), byID...)
		named := false
		for _, t := range chunk {
			byID = append(byID, t.Commit)
			if t.Name != "" { // a bare commit has no name to fall back on
				byName = append(byName, "+refs/tags/"+t.Name+":refs/tags/"+t.Name)
				named = true
			}
		}
		if err := r.s.gitProgress(label, byID...); err != nil {
			if !named {
				return err
			}
			if err2 := r.s.gitProgress(label, byName...); err2 != nil {
				return fmt.Errorf("%v; by name: %w", err, err2)
			}
		}
	}
	return nil
}

// Blobs is the set of blob ids in a commit's tree, which must have been fetched.
func (r *Repo) Blobs(commit string) (map[string]bool, error) {
	t := &Snapshot{URL: r.s.URL, dir: r.s.dir}
	if err := t.listTree(commit); err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(t.Files))
	for _, sha := range t.Files {
		set[sha] = true
	}
	return set, nil
}

// Blob is the content of a file by blob id, fetched from origin if not held.
func (s *Snapshot) Blob(sha string) ([]byte, error) { return s.git("cat-file", "blob", sha) }

func (s *Snapshot) init() error {
	if _, err := os.Stat(filepath.Join(s.dir, "HEAD")); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.dir), 0o755); err != nil {
		return err
	}
	if out, err := exec.Command("git", "init", "--bare", "-q", s.dir).CombinedOutput(); err != nil {
		return fmt.Errorf("git init: %v: %s", err, bytes.TrimSpace(out))
	}
	_, err := s.git("remote", "add", "origin", s.URL)
	return err
}

func (s *Snapshot) has(commit string) bool {
	_, err := s.git("cat-file", "-e", commit+"^{commit}")
	return err == nil
}

// resolve turns ref into a full commit id, asking the remote for names and, for an
// abbreviated id (which a remote cannot expand), fetching its commit history
// without trees or blobs to expand it here.
func (s *Snapshot) resolve(ref string, say func(string, ...any)) (string, error) {
	switch {
	case fullSHA.MatchString(ref):
		return ref, nil
	case ref == "":
		return s.lsRemote("HEAD")
	}
	// A tag already resolved, whose commit is held, costs no round trip.
	mc := matchcache.Default()
	key := matchcache.Key("tagcommit", s.URL, ref)
	var known struct{ Commit string }
	if mc.Get(key, &known) && fullSHA.MatchString(known.Commit) && s.has(known.Commit) {
		return known.Commit, nil
	}
	if c, found, err := s.lsRemoteRef("refs/tags/"+ref+"^{}", "refs/tags/"+ref, "refs/heads/"+ref); err == nil {
		if strings.HasPrefix(found, "refs/tags/") {
			mc.Put(key, tagTTL, struct{ Commit string }{c})
		}
		return c, nil
	}
	if shortSHA.MatchString(ref) {
		say("expanding %s (fetching %s history)", ref, s.URL)
		if err := s.gitProgress("expanding "+ref+" in "+shortURL(s.URL), "fetch", "--filter=tree:0", "--no-tags", "origin", "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"); err != nil {
			return "", fmt.Errorf("fetch %s: %w", s.URL, err)
		}
		out, err := s.git("rev-parse", "--verify", "-q", ref+"^{commit}")
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	return "", fmt.Errorf("%s: no branch, tag or commit %q", s.URL, ref)
}

// lsRemote is the first of patterns the remote has, as a commit id (a peeled tag
// preferred, being listed first).
func (s *Snapshot) lsRemote(patterns ...string) (string, error) {
	c, _, err := s.lsRemoteRef(patterns...)
	return c, err
}

// lsRemoteRef is lsRemote that also says which ref it found.
func (s *Snapshot) lsRemoteRef(patterns ...string) (commit, ref string, err error) {
	out, err := s.git(append([]string{"ls-remote", "origin"}, patterns...)...)
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) == 2 && fullSHA.MatchString(f[0]) {
			return f[0], f[1], nil
		}
	}
	return "", "", fmt.Errorf("%s: not found", strings.Join(patterns, ", "))
}

// tagTTL is how long a tag's commit is remembered: a tag is a release, and does not
// move. (A branch does, so a branch is always asked for.)
const tagTTL = 30 * 24 * time.Hour

// gitPhase picks the phase and percent out of a git progress line
// ("Receiving objects:  63% (1234/1960), 5.2 MiB | 2.1 MiB/s").
var gitPhase = regexp.MustCompile(`(Enumerating objects|Counting objects|Compressing objects|Receiving objects|Resolving deltas):\s+(\d+)%`)

// shortURL is an origin without its scheme and .git, for a label.
func shortURL(u string) string {
	u = strings.TrimSuffix(u, ".git")
	if _, rest, ok := strings.Cut(u, "://"); ok {
		return rest
	}
	return u
}

// gitProgress runs a git command that reports progress, and passes each phase it
// reports (receiving objects, resolving deltas) to the shared tracker as a task of
// its own, so a waiting front end can show percent and time left.
func (s *Snapshot) gitProgress(label string, args ...string) error {
	return s.gitProgressWith(nil, label, args...)
}

// gitProgressWith is gitProgress with configuration for the command, as -c
// key=value pairs placed before the subcommand.
func (s *Snapshot) gitProgressWith(cfg []string, label string, args ...string) error {
	pre := []string{"--git-dir", s.dir}
	for _, c := range cfg {
		pre = append(pre, "-c", c)
	}
	cmd := exec.Command("git", append(append(pre, args[0], "--progress"), args[1:]...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var (
		task  *progress.Task
		phase string
		last  int64
		tail  []byte
	)
	end := func() {
		if task != nil {
			task.End()
			task = nil
		}
	}
	defer end()
	buf := make([]byte, 4096)
	var line []byte
	handle := func(l []byte) {
		if m := gitPhase.FindSubmatch(l); m != nil {
			if p := string(m[1]); p != phase {
				end()
				phase, last = p, 0
				task = progress.Begin(label+": "+strings.ToLower(p), 100)
			}
			pct, _ := strconv.ParseInt(string(m[2]), 10, 64)
			if task != nil && pct > last {
				task.Add(pct - last)
				last = pct
			}
			return
		}
		if tail = append(tail, l...); len(tail) > 2048 {
			tail = tail[len(tail)-2048:]
		}
	}
	for {
		n, rerr := stderr.Read(buf)
		for _, b := range buf[:n] {
			if b == '\r' || b == '\n' {
				handle(line)
				line = line[:0]
			} else {
				line = append(line, b)
			}
		}
		if rerr != nil {
			break
		}
	}
	handle(line)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(string(tail)))
	}
	return nil
}

// gitTimeout bounds a git command that is not a long fetch: a stalled server must
// not leave the whole run waiting with nothing on screen.
const gitTimeout = 3 * time.Minute

func (s *Snapshot) git(args ...string) ([]byte, error) {
	return s.gitEnv(nil, args...)
}

func (s *Snapshot) gitEnv(env []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"--git-dir", s.dir}, args...)...)
	cmd.Env = append(append(os.Environ(), "GIT_TERMINAL_PROMPT=0"), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("git %s: timed out after %s", args[0], gitTimeout)
		}
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Prefetch brings in the blobs shas name, in batches, from origin. It stops at the
// first batch the server will not send (many will not send an object by id),
// leaving the blobs unfetched; Blob would then fetch them one at a time, which is
// BlobLocal's reason to exist.
//
// Blobs already held are not asked for, and the fetch skips negotiation: it tells
// the server what the repository has so that less is sent, which for a blob sent
// by id saves nothing, and against a repository holding a long history costs
// tens of seconds, and can end with some of the blobs not sent at all.
func (s *Snapshot) Prefetch(label string, shas []string) error {
	shas = s.missing(shas)
	for len(shas) > 0 {
		chunk := shas[:min(len(shas), 100)]
		shas = shas[len(chunk):]
		err := s.gitProgressWith([]string{"fetch.negotiationAlgorithm=noop"}, label,
			append([]string{"fetch", "--no-tags", "origin"}, chunk...)...)
		if err != nil {
			return err
		}
	}
	return nil
}

// missing is the blobs among shas that the repository does not hold.
func (s *Snapshot) missing(shas []string) []string {
	if len(shas) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "--git-dir", s.dir, "cat-file", "--batch-check")
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0")
	cmd.Stdin = strings.NewReader(strings.Join(shas, "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		return shas // cannot tell: ask for all
	}
	var miss []string
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == "missing" {
			miss = append(miss, f[0])
		}
	}
	return miss
}

// BlobLocal is the content of a blob already held, without ever fetching it: ok is
// false for one that is not. A partial clone's Blob fetches each missing object
// from origin on its own, a round trip apiece; this is for the many-file checks
// where that would not finish.
func (s *Snapshot) BlobLocal(sha string) (b []byte, ok bool) {
	out, err := s.gitEnv([]string{"GIT_NO_LAZY_FETCH=1"}, "cat-file", "blob", sha)
	return out, err == nil
}

// Sizes fetches the blobs shas name (in batches, from origin) and returns each
// one's size. A server that will not send a blob by id leaves them to be fetched
// one at a time as they are measured.
func (s *Snapshot) Sizes(shas []string) (map[string]int64, error) {
	for len(shas) > 0 {
		chunk := shas[:min(len(shas), 100)]
		shas = shas[len(chunk):]
		s.Prefetch("fetching changed files", chunk) //nolint:errcheck // best effort; see above
		cmd := exec.Command("git", "--git-dir", s.dir, "cat-file", "--batch-check=%(objectname) %(objectsize)")
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		cmd.Stdin = strings.NewReader(strings.Join(chunk, "\n") + "\n")
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git cat-file: %w", err)
		}
		if s.sizes == nil {
			s.sizes = map[string]int64{}
		}
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) == 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				s.sizes[f[0]] = n
			}
		}
	}
	return s.sizes, nil
}

// History fetches the commits after tag from up to tag to (history only: no trees,
// no blobs) and lists them along the first parent, oldest first. A vendor's
// snapshot is usually of some commit between two releases, and this is the
// range to look for it in. It needs a server that can cut history at a tag
// (git's shallow-exclude); an error says if it cannot.
func (r *Repo) History(label, from, to string) ([]string, error) {
	err := r.s.gitProgress(label, "fetch", "--filter=tree:0", "--no-tags", "--shallow-exclude="+from,
		"origin", "+refs/tags/"+to+":refs/tags/"+to)
	if err != nil {
		return nil, err
	}
	out, err := r.s.git("rev-list", "--first-parent", "--reverse", "refs/tags/"+to)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// Describe is a held commit's date and subject.
func (r *Repo) Describe(commit string) (date, subject string) {
	out, err := r.s.git("show", "-s", "--format=%cs%n%s", commit)
	if err != nil {
		return "", ""
	}
	date, subject, _ = strings.Cut(strings.TrimSpace(string(out)), "\n")
	return date, subject
}

// Has says the repository already holds commit.
func (r *Repo) Has(commit string) bool { return r.s.has(commit) }

// BlobsLocal is the content of each blob among shas that the repository holds,
// read through one git process and without fetching anything.
func (s *Snapshot) BlobsLocal(shas []string) map[string][]byte {
	out := map[string][]byte{}
	if len(shas) == 0 {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "--git-dir", s.dir, "cat-file", "--batch")
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0")
	cmd.Stdin = strings.NewReader(strings.Join(shas, "\n") + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		return out
	}
	r := bufio.NewReader(stdout)
	for {
		header, err := r.ReadString('\n')
		if err != nil {
			break
		}
		f := strings.Fields(header) // "<sha> <type> <size>", or "<sha> missing"
		if len(f) != 3 {
			continue
		}
		n, err := strconv.Atoi(f[2])
		if err != nil {
			break
		}
		body := make([]byte, n+1) // the content, and the newline git adds after it
		if _, err := io.ReadFull(r, body); err != nil {
			break
		}
		if f[1] == "blob" {
			out[f[0]] = body[:n]
		}
	}
	cmd.Wait() //nolint:errcheck // what was read is what there is
	return out
}
