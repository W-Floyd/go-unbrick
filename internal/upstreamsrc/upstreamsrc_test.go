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
