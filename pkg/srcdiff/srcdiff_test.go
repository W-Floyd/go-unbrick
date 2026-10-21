package srcdiff

import (
	"archive/zip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/gitsrc"
	"github.com/W-Floyd/go-unbrick/internal/upstreamsrc"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

func git(t *testing.T, dir string, args ...string) string {
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

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte(body))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestIdentifyFindsAProjectAndItsVersion(t *testing.T) {
	z := filepath.Join(t.TempDir(), "OSA.zip")
	writeZip(t, z, map[string]string{
		"0109_X_kernel.lk/2/u-boot/Makefile": "VERSION = 2023\nPATCHLEVEL = 01\nSUBLEVEL =\n",
		"0109_X_kernel.lk/2/u-boot/a.c":      "int a;\n",
		"0109_X_kernel.lk/2/u-boot/b.c":      "int b;\n",
		"README":                             "x\n",
	})
	got, err := Identify(z, "../../catalog")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Project != "u-boot" || got[0].Version != "2023.01" || got[0].Ref != "v2023.01" ||
		got[0].Root != "0109_X_kernel.lk/2/u-boot" || got[0].Upstream() != got[0].Repo+"#v2023.01" {
		t.Errorf("candidates = %+v", got)
	}
	if _, err := Identify(filepath.Join(t.TempDir(), "nope.zip"), "../../catalog"); err == nil {
		t.Error("a missing file was identified")
	}
}

func TestOnlyTheNetworkMayBeFetched(t *testing.T) {
	for _, bad := range []string{"file:///etc", "ssh://host/x", "git@host:x/y.git", "/tmp/repo", "relative/path", ""} {
		if _, err := Compare("x.zip", "root", bad, Options{}); err == nil || !strings.Contains(err.Error(), "URL") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// A release's tree is compared with its upstream by blob id; what differs can be diffed.
func TestCompareAndDiff(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	git(t, origin, "init", "-q", "-b", "main")
	git(t, origin, "config", "uploadpack.allowFilter", "true")
	git(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	up := map[string]string{"lib/a.c": "int a;\n", "lib/b.c": "int b;\nint b2;\n", "lib/crlf.c": "x\ny\n", "lib/gone.c": "upstream only\n"}
	for name, body := range up {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(origin, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(origin, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, origin, "add", ".")
	git(t, origin, "commit", "-q", "-m", "one")
	git(t, origin, "tag", "v1")

	z := filepath.Join(t.TempDir(), "OSA.zip")
	writeZip(t, z, map[string]string{
		"0001_X_lib/a.c":    "int a;\n",               // identical
		"0001_X_lib/b.c":    "int b;\nint changed;\n", // modified
		"0001_X_lib/crlf.c": "x\r\ny\r\n",             // only line endings
		"0001_X_lib/new.c":  "vendor's own\n",         // vendor-only
		"other/readme":      "not in the tree\n",
	})
	c, err := compare(z, "0001_X_lib", gitsrc.Source{URL: "file://" + origin, Ref: "v1"}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := c.Report
	if r.Identical != 1 || len(r.Modified) != 2 || len(r.VendorOnly) != 1 || r.VendorOnly[0] != "new.c" || r.UpstreamOnly != 1 || r.Aligned != "lib/" || r.Ref != "v1" || len(r.Commit) != 40 {
		t.Fatalf("report = %+v", r)
	}
	by := map[string]FileChange{}
	for _, m := range r.Modified {
		by[m.Path] = m
	}
	if m := by["b.c"]; m.EOLOnly || !m.Counted || m.Added != 1 || m.Removed != 1 {
		t.Errorf("b.c: %+v", m)
	}
	if m := by["crlf.c"]; !m.EOLOnly {
		t.Errorf("crlf.c: %+v", m)
	}

	cfg, ch, err := c.Diff()
	if err != nil {
		t.Fatal(err)
	}
	if ch.Shown != 2 || ch.EOLOnly != 1 {
		t.Errorf("changes = %+v", ch)
	}
	run := analysis.Start(cfg)
	select {
	case <-run.Done():
	case <-time.After(20 * time.Second):
		t.Fatal("the diff did not finish")
	}
	lv, err := run.LevelAt(nil)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, e := range run.Entries(lv, false) {
		kinds[e.Name] = e.Kind.String()
	}
	if kinds["b.c"] != "changed" || kinds["new.c"] != "added" || len(kinds) != 2 {
		t.Errorf("diff entries = %v", kinds)
	}
	c.Close()
	rootsMu.Lock()
	left := len(roots)
	rootsMu.Unlock()
	if left != 0 {
		t.Errorf("%d roots left registered", left)
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.zip")
	writeZip(t, p, files)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A newer release is a zip of zips: a project is a member, named for it.
func TestNestedProjectsAreFoundAndCompared(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	inner := map[string]string{
		"e2fsprogs/lib/a.c": "int a;\n", "e2fsprogs/lib/b.c": "int b;\nint vendor;\n", "e2fsprogs/lib/new.c": "added\n",
	}
	release := filepath.Join(t.TempDir(), "OSA.zip")
	writeZip(t, release, map[string]string{"x": "y"}) // replaced below: a zip needs real members
	os.Remove(release)
	f, err := os.Create(release)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range map[string][]byte{
		"platform.external.e2fsprogs_src_opened_code.zip":            zipOf(t, inner),
		"platform.external.e2fsprogs_src_opened_code_Dependency.zip": zipOf(t, map[string]string{"d": "d"}),
		"mobis.qnx.something_src_opened_code.zip":                    zipOf(t, map[string]string{"s": "s"}),
		"notes.txt": []byte("not a project\n"),
	} {
		fw, _ := w.Create(name)
		fw.Write(body)
	}
	w.Close()
	f.Close()

	got, err := Identify(release, "../../catalog")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Project != "e2fsprogs" || !got[0].Nested || got[0].Root != "platform.external.e2fsprogs_src_opened_code.zip" {
		t.Fatalf("candidates = %+v", got)
	}

	origin := t.TempDir()
	git(t, origin, "init", "-q", "-b", "main")
	git(t, origin, "config", "uploadpack.allowFilter", "true")
	git(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	for name, body := range map[string]string{"lib/a.c": "int a;\n", "lib/b.c": "int b;\n"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(origin, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(origin, name), []byte(body), 0o644)
	}
	git(t, origin, "add", ".")
	git(t, origin, "commit", "-q", "-m", "one")
	c, err := compare(release, got[0].Root, gitsrc.Source{URL: "file://" + origin}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := c.Report
	// The zip's own folder is not part of the paths: lib/a.c is lib/a.c upstream.
	if r.Identical != 1 || len(r.Modified) != 1 || r.Modified[0].Path != "lib/b.c" || len(r.VendorOnly) != 1 || r.VendorOnly[0] != "lib/new.c" {
		t.Errorf("report = %+v", r)
	}
	if _, _, err := c.Diff(); err != nil {
		t.Errorf("diff of a nested tree: %v", err)
	}
}

// The tag a tree has no version for is the one whose files it holds.
func TestTheClosestTagIsFound(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	origin := t.TempDir()
	git(t, origin, "init", "-q", "-b", "main")
	git(t, origin, "config", "uploadpack.allowFilter", "true")
	git(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	release := func(tag string, files map[string]string) {
		for name, body := range files {
			os.WriteFile(filepath.Join(origin, name), []byte(body), 0o644)
		}
		git(t, origin, "add", "-A")
		git(t, origin, "commit", "-q", "-m", tag)
		git(t, origin, "tag", tag)
	}
	release("v1.0", map[string]string{"a.c": "a1\n", "b.c": "b1\n", "c.c": "c1\n"})
	release("v1.1", map[string]string{"a.c": "a2\n", "b.c": "b2\n", "c.c": "c2\n"})
	release("v1.2", map[string]string{"a.c": "a3\n", "b.c": "b3\n", "c.c": "c3\n"})

	z := filepath.Join(t.TempDir(), "OSA.zip")
	writeZip(t, z, map[string]string{"proj/a.c": "a2\n", "proj/b.c": "b2\n", "proj/c.c": "c2\n", "proj/own.c": "mine\n"})
	files, _, closeIn, err := treeFiles(z, "proj")
	if err != nil {
		t.Fatal(err)
	}
	defer closeIn()
	local, n, err := sampleBlobs(files)
	if err != nil || n != 4 {
		t.Fatalf("sample: %d %v", n, err)
	}
	tags, err := upstreamsrc.ListTags("file://" + origin)
	if err != nil {
		t.Fatal(err)
	}
	vt := versionedTags(nil, tags)
	if len(vt) != 3 || vt[0].Name != "v1.0" || vt[2].Name != "v1.2" {
		t.Fatalf("versioned tags = %+v", vt)
	}
	repo, err := upstreamsrc.OpenRepo("file://"+origin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scores := map[int]int{}
	b, err := searchBest(len(vt), scorer(repo, local, "t", func(i int) upstreamsrc.Tag { return vt[i].Tag }, scores), scores)
	if err != nil {
		t.Fatal(err)
	}
	if vt[b].Name != "v1.1" || scores[b] != 3 {
		t.Errorf("best = %s (%d of %d): %v", vt[b].Name, scores[b], n, scores)
	}
}
