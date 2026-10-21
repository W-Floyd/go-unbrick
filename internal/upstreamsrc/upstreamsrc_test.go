package upstreamsrc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestOpen(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	run(t, origin, "init", "-q", "-b", "main")
	run(t, origin, "config", "uploadpack.allowFilter", "true")
	run(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	if err := os.MkdirAll(filepath.Join(origin, "lm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "lm", "a.cc"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, origin, "add", ".")
	run(t, origin, "commit", "-q", "-m", "one")
	run(t, origin, "tag", "v1")
	commit := run(t, origin, "rev-parse", "HEAD")
	cache := t.TempDir()

	for _, ref := range []string{"", "v1", "main", commit, commit[:8]} {
		s, err := Open("file://"+origin, ref, cache, nil)
		if err != nil {
			t.Fatalf("ref %q: %v", ref, err)
		}
		if s.Commit != commit || s.Files["lm/a.cc"] != "ce013625030ba8dba906f756967f9e9ca394464a" {
			t.Errorf("ref %q: %+v", ref, s)
		}
		b, err := s.Blob(s.Files["lm/a.cc"])
		if err != nil || string(b) != "hello\n" {
			t.Errorf("ref %q blob: %q %v", ref, b, err)
		}
	}
	if _, err := Open("file://"+origin, "nonesuch", cache, nil); err == nil {
		t.Error("missing ref resolved")
	}
}

func TestTagsAndRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	run(t, origin, "init", "-q", "-b", "main")
	run(t, origin, "config", "uploadpack.allowFilter", "true")
	run(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(origin, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.c", "one\n")
	run(t, origin, "add", ".")
	run(t, origin, "commit", "-q", "-m", "one")
	run(t, origin, "tag", "v1")
	c1 := run(t, origin, "rev-parse", "HEAD")
	write("a.c", "two\n")
	write("b.c", "b\n")
	run(t, origin, "add", ".")
	run(t, origin, "commit", "-q", "-m", "two")
	run(t, origin, "tag", "-a", "-m", "release two", "v2")
	c2 := run(t, origin, "rev-parse", "HEAD")

	tags, err := ListTags("file://" + origin)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0] != (Tag{"v1", c1}) || tags[1] != (Tag{"v2", c2}) {
		t.Fatalf("tags %+v (an annotated tag must give its commit)", tags)
	}
	r, err := OpenRepo("file://"+origin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Fetch("test", tags); err != nil {
		t.Fatal(err)
	}
	b1, err := r.Blobs(c1)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := r.Blobs(c2)
	if len(b1) != 1 || len(b2) != 2 {
		t.Errorf("blobs %d %d", len(b1), len(b2))
	}
	if err := r.Fetch("test", tags); err != nil { // already held: no fetch
		t.Fatal(err)
	}
}

func TestSizes(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	run(t, origin, "init", "-q", "-b", "main")
	run(t, origin, "config", "uploadpack.allowFilter", "true")
	run(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	if err := os.WriteFile(filepath.Join(origin, "a.c"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, origin, "add", ".")
	run(t, origin, "commit", "-q", "-m", "one")
	s, err := Open("file://"+origin, "main", t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sha := s.Files["a.c"]
	got, err := s.Sizes([]string{sha})
	if err != nil || got[sha] != 6 {
		t.Errorf("sizes %v %v", got, err)
	}
}

func TestHistoryBetweenTags(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	run(t, origin, "init", "-q", "-b", "main")
	run(t, origin, "config", "uploadpack.allowFilter", "true")
	run(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	var commits []string
	for i, body := range []string{"one\n", "two\n", "three\n", "four\n"} {
		if err := os.WriteFile(filepath.Join(origin, "a.c"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, origin, "add", ".")
		run(t, origin, "commit", "-q", "-m", "c"+body)
		commits = append(commits, run(t, origin, "rev-parse", "HEAD"))
		switch i {
		case 0:
			run(t, origin, "tag", "v1")
		case 3:
			run(t, origin, "tag", "v2")
		}
	}
	r, err := OpenRepo("file://"+origin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.History("test", "v1", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != commits[1] || got[2] != commits[3] {
		t.Fatalf("history %v want %v", got, commits[1:])
	}
	if err := r.Fetch("test", []Tag{{Commit: got[1]}}); err != nil {
		t.Fatal(err)
	}
	if date, subject := r.Describe(got[1]); date == "" || subject != "cthree" {
		t.Errorf("describe %q %q", date, subject)
	}
}

func TestPrefetchAndBlobLocal(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	run(t, origin, "init", "-q", "-b", "main")
	run(t, origin, "config", "uploadpack.allowFilter", "true")
	run(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	if err := os.WriteFile(filepath.Join(origin, "a.c"), []byte("hello\r\nworld\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, origin, "add", ".")
	run(t, origin, "commit", "-q", "-m", "one")
	s, err := Open("file://"+origin, "main", t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sha := s.Files["a.c"]
	// The tree is held; the blob is not, and asking for it must not go to origin.
	if _, ok := s.BlobLocal(sha); ok {
		t.Fatal("a blob nobody fetched was there")
	}
	if err := s.Prefetch("test", []string{sha}); err != nil {
		t.Fatal(err)
	}
	if b, ok := s.BlobLocal(sha); !ok || string(b) != "hello\r\nworld\r\n" {
		t.Errorf("after prefetch: %q %v", b, ok)
	}
}

func TestPrefetchSkipsBlobsAlreadyHeld(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	run(t, origin, "init", "-q", "-b", "main")
	run(t, origin, "config", "uploadpack.allowFilter", "true")
	run(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	if err := os.WriteFile(filepath.Join(origin, "a.c"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, origin, "add", ".")
	run(t, origin, "commit", "-q", "-m", "one")
	s, err := Open("file://"+origin, "main", t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sha := s.Files["a.c"]
	if m := s.missing([]string{sha}); len(m) != 1 {
		t.Fatalf("missing before: %v", m)
	}
	if err := s.Prefetch("test", []string{sha}); err != nil {
		t.Fatal(err)
	}
	if m := s.missing([]string{sha}); len(m) != 0 {
		t.Fatalf("missing after: %v", m)
	}
	// With origin gone, a blob already held is no reason to fail: nothing is asked.
	if _, err := s.git("remote", "set-url", "origin", "file:///nonexistent/repo"); err != nil {
		t.Fatal(err)
	}
	if err := s.Prefetch("test", []string{sha}); err != nil {
		t.Errorf("fetched a blob it already held: %v", err)
	}
}

func TestBlobsLocalAndTagCache(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	run(t, origin, "init", "-q", "-b", "main")
	run(t, origin, "config", "uploadpack.allowFilter", "true")
	run(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(origin, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.c", "alpha\r\nbeta\r\n")
	write("b.c", "no trailing newline")
	write("empty.c", "")
	run(t, origin, "add", ".")
	run(t, origin, "commit", "-q", "-m", "one")
	run(t, origin, "tag", "v1")
	cache := t.TempDir()
	s, err := Open("file://"+origin, "v1", cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	var shas []string
	for _, p := range []string{"a.c", "b.c", "empty.c"} {
		shas = append(shas, s.Files[p])
	}
	if got := s.BlobsLocal(shas); len(got) != 0 {
		t.Fatalf("blobs before they were fetched: %d", len(got))
	}
	if err := s.Prefetch("test", shas); err != nil {
		t.Fatal(err)
	}
	got := s.BlobsLocal(append(shas, "0000000000000000000000000000000000000000"))
	if string(got[s.Files["a.c"]]) != "alpha\r\nbeta\r\n" || string(got[s.Files["b.c"]]) != "no trailing newline" {
		t.Errorf("content: %q", got)
	}
	if b, ok := got[s.Files["empty.c"]]; !ok || len(b) != 0 {
		t.Errorf("empty blob: %q %v", b, ok)
	}

	// A tag resolved once is known the second time without asking the remote: with
	// the remote gone, opening it still works.
	home := t.TempDir() // matchcache.Default follows the user cache dir, which follows HOME (macOS) or XDG_CACHE_HOME
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	if _, err := Open("file://"+origin, "v1", cache, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(origin); err != nil {
		t.Fatal(err)
	}
	if _, err := Open("file://"+origin, "v1", cache, nil); err != nil {
		t.Errorf("a resolved tag cost a round trip to a remote that is gone: %v", err)
	}
}
