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
