package gitsrc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]Source{
		"https://github.com/mt6768-mainline/linux":         {URL: "https://github.com/mt6768-mainline/linux"},
		"https://github.com/mt6768-mainline/linux#cleanup": {URL: "https://github.com/mt6768-mainline/linux", Ref: "cleanup"},
		"git@github.com:mt6768-mainline/linux.git#6.18":    {URL: "git@github.com:mt6768-mainline/linux.git", Ref: "6.18"},
		"file:///srv/linux":                                {URL: "file:///srv/linux"},
		"ssh://git@example.org/linux.git":                  {URL: "ssh://git@example.org/linux.git"},
	} {
		got, ok := Parse(in)
		if !ok || got != want {
			t.Errorf("Parse(%q) = %+v %v, want %+v", in, got, ok, want)
		}
	}
	for _, in := range []string{"/home/me/linux", "../linux", "linux", "C:\\src\\linux", ""} {
		if _, ok := Parse(in); ok {
			t.Errorf("Parse(%q) took a path for a URL", in)
		}
	}
}

func TestWantedLevels(t *testing.T) {
	cases := []struct {
		path      string
		dts, full bool
	}{
		{"arch/arm64/boot/dts/mediatek/mt6768.dtsi", true, true},
		{"include/dt-bindings/clock/mediatek,mt6768-clock.h", true, true},
		{"drivers/gpu/drm/panel/panel-himax-hx83102.c", false, true},
		{"Documentation/devicetree/bindings/display/panel/himax,hx83102.yaml", false, true},
		{"sound/soc/codecs/x.c", false, true},
		{"Kconfig", false, true},
		{"arch/Kconfig", false, true},
		{"drivers/net/ethernet/Kconfig", false, true},
		{"drivers/net/ethernet/big.o", false, false},
		{"fs/ext4/inode.c", false, false},
		{"README", false, false},
	}
	for _, c := range cases {
		if got := wanted(DTS, c.path); got != c.dts {
			t.Errorf("DTS wants %s = %v", c.path, got)
		}
		if got := wanted(Full, c.path); got != c.full {
			t.Errorf("Full wants %s = %v", c.path, got)
		}
	}
}

// A repository on disk, cloned over file://, by commit with go-git itself.
func makeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	for p, text := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := wt.Commit("one", &git.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@example.org", When: time.Unix(0, 0)}}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEnsureFetchesOnceAndWritesOnlyWhatALevelAsksFor(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is needed for go-git's file transport")
	}
	src := makeRepo(t, map[string]string{
		"arch/arm64/boot/dts/mediatek/mt6768.dtsi": "/ { soc { i2c@11007000 {}; }; };\n",
		"drivers/media/i2c/gc08a3.c":               "int x;\n",
		"Kconfig":                                  "config FOO\n\tbool\n",
		"fs/other.c":                               "int y;\n",
	})
	cache := t.TempDir()
	s := Source{URL: "file://" + src}

	tree, err := Ensure(s, cache, DTS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tree, "arch/arm64/boot/dts/mediatek/mt6768.dtsi")); err != nil {
		t.Errorf("the dts file was not written: %v", err)
	}
	for _, p := range []string{"drivers/media/i2c/gc08a3.c", "Kconfig", "fs/other.c"} {
		if _, err := os.Stat(filepath.Join(tree, p)); err == nil {
			t.Errorf("%s written at the DTS level", p)
		}
	}

	// The source is gone: a second ask is served from the cache.
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}
	again, err := Ensure(s, cache, DTS, nil)
	if err != nil || again != tree {
		t.Fatalf("cached ask: %q %v", again, err)
	}
	// And more can be written from the repository already fetched.
	full, err := Ensure(s, cache, Full, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"drivers/media/i2c/gc08a3.c", "Kconfig", "arch/arm64/boot/dts/mediatek/mt6768.dtsi"} {
		if _, err := os.Stat(filepath.Join(full, p)); err != nil {
			t.Errorf("%s missing at the Full level: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(full, "fs/other.c")); err == nil {
		t.Error("an unrelated source was written")
	}
	if got := s.Dir(cache); !strings.HasPrefix(full, got) {
		t.Errorf("tree %q is not under %q", full, got)
	}
}

func TestEnsureReportsAnUnreachableSource(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is needed for go-git's file transport")
	}
	cache := t.TempDir()
	_, err := Ensure(Source{URL: "file://" + filepath.Join(t.TempDir(), "no-such-repo")}, cache, DTS, nil)
	if err == nil || !strings.Contains(err.Error(), "fetching") {
		t.Errorf("err = %v", err)
	}
	// The shared repository stays (empty); no tree directory is left behind.
	ents, _ := os.ReadDir(cache)
	for _, e := range ents {
		if e.Name() != "kernels.git" {
			t.Errorf("a failed fetch left %s in the cache", e.Name())
		}
	}
}

// commitFiles makes a git repository with the git binary (a second one can start
// as a copy of the first), so a test controls what two sources share.
func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func objectCount(t *testing.T, repo string) int {
	t.Helper()
	out, err := exec.Command("git", "--git-dir", repo, "rev-list", "--objects", "--all").Output()
	if err != nil {
		t.Fatal(err)
	}
	return len(strings.Split(strings.TrimSpace(string(out)), "\n"))
}

// A fork that is mostly its upstream costs a few objects, not a second
// snapshot, when both are fetched into the one shared repository by git.
func TestSourcesShareObjectsInOneRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	upstream := t.TempDir()
	gitIn(t, upstream, "init", "-q", "-b", "main")
	for i := 0; i < 60; i++ {
		p := filepath.Join(upstream, "arch/arm64/boot/dts/x", string(rune('a'+i%26))+string(rune('a'+i/26))+".dtsi")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Repeat("node@"+string(rune('a'+i%26))+" {};\n", 20)+string(rune('0'+i%10))), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, upstream, "add", "-A")
	gitIn(t, upstream, "commit", "-q", "-m", "base")
	fork := t.TempDir()
	if out, err := exec.Command("git", "clone", "-q", upstream, fork).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(fork, "arch/arm64/boot/dts/x/new.dtsi"), []byte("/ { added {}; };\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, fork, "add", "-A")
	gitIn(t, fork, "commit", "-q", "-m", "fork")

	cache := t.TempDir()
	if _, err := Ensure(Source{URL: "file://" + upstream}, cache, DTS, nil); err != nil {
		t.Fatal(err)
	}
	alone := objectCount(t, repoDir(cache))
	tree, err := Ensure(Source{URL: "file://" + fork}, cache, DTS, nil)
	if err != nil {
		t.Fatal(err)
	}
	both := objectCount(t, repoDir(cache))
	if both-alone > 8 {
		t.Errorf("the fork added %d objects to the %d already there: it should cost its own commit, tree and new file", both-alone, alone)
	}
	if _, err := os.Stat(filepath.Join(tree, "arch/arm64/boot/dts/x/new.dtsi")); err != nil {
		t.Errorf("the fork's own file is missing: %v", err)
	}
}

// With the git binary off the fetch falls back to go-git: the same trees, no
// sharing.
func TestFetchFallsBackToGoGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is needed for go-git's file transport")
	}
	src := makeRepo(t, map[string]string{
		"arch/arm64/boot/dts/mediatek/mt6768.dtsi": "/ { soc { i2c@11007000 {}; }; };\n",
	})
	old := useCLI
	useCLI = false
	t.Cleanup(func() { useCLI = old })
	tree, err := Ensure(Source{URL: "file://" + src}, t.TempDir(), DTS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tree, "arch/arm64/boot/dts/mediatek/mt6768.dtsi")); err != nil {
		t.Errorf("go-git fetch: %v", err)
	}
}

func TestLabel(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/mt6768-mainline/linux#cleanup": "mt6768-mainline-linux-cleanup",
		"git@github.com:torvalds/linux.git":                "torvalds-linux",
		"https://example.org/a/b/c/linux.git#v6.18":        "c-linux-v6.18",
		"file:///srv/linux":                                "srv-linux",
	} {
		s, _ := Parse(in)
		if got := s.Label(); got != want {
			t.Errorf("Label(%q) = %q, want %q", in, got, want)
		}
	}
}
