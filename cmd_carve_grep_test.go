package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGrepFixture lays out a small directory: a binary file holding a non-printable
// run around the needle (so a printable-strings-only search would miss it), a plain
// text file without the needle, and a nested subdirectory holding another match.
func writeGrepFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel string, b []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("mixed.bin", append(append([]byte("hello\x00\x01\x02"), []byte("secretvalue")...), 0xfe, 0xfd))
	write("plain.txt", []byte("nothing of interest here"))
	write("sub/deep.txt", []byte("xsecretvaluex"))
	return dir
}

func runTree(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newTreeCmd()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs(args)
	return captureStdout(func() error { return cmd.Execute() })
}

func runExtract(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newExtractCmd()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs(args)
	return captureStdout(func() error { return cmd.Execute() })
}

func TestTreeGrepFindsBinaryAndTextMatches(t *testing.T) {
	dir := writeGrepFixture(t)
	out, err := runTree(t, dir, "-g", "secretvalue")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mixed.bin", "deep.txt"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "plain.txt") {
		t.Errorf("plain.txt (no match) should not appear:\n%s", out)
	}
}

func TestTreeGrepAndMatchAreCombinedWithAnd(t *testing.T) {
	dir := writeGrepFixture(t)
	out, err := runTree(t, dir, "-m", "^sub/", "-g", "secretvalue")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "deep.txt") {
		t.Errorf("sub/deep.txt matches both filters, should appear:\n%s", out)
	}
	if strings.Contains(out, "mixed.bin") {
		t.Errorf("mixed.bin matches content but not path, should not appear:\n%s", out)
	}
}

func TestTreeGrepNoMatchIsEmptyNotACrash(t *testing.T) {
	dir := writeGrepFixture(t)
	out, err := runTree(t, dir, "-g", "nothing-matches-this")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "mixed.bin") || strings.Contains(out, "deep.txt") {
		t.Errorf("nothing should match:\n%s", out)
	}
}

func TestTreeGrepOnNestedDirectoriesDoesNotCrash(t *testing.T) {
	// A directory on disk puts its subdirectories through treeItem.file, not
	// treeItem.dir (see items()/buildTreeDir): matches() must special-case
	// IsDirNode() before trying to read a directory's "content".
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b", "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "b", "c", "f.txt"), []byte("xsecretvaluex"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runTree(t, dir, "-g", "secretvalue")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "f.txt") {
		t.Errorf("should have found the match through nested directories:\n%s", out)
	}
}

func TestExtractGrepWritesOnlyMatchingEntries(t *testing.T) {
	dir := writeGrepFixture(t)
	outDir := filepath.Join(t.TempDir(), "x")
	if _, err := runExtract(t, "-r", dir, "-g", "secretvalue", "-o", outDir); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mixed.bin", filepath.Join("sub", "deep.txt")} {
		if _, err := os.Stat(filepath.Join(outDir, want)); err != nil {
			t.Errorf("expected %s to be written: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "plain.txt")); err == nil {
		t.Error("plain.txt should not have been written")
	}
}

func TestExtractGrepNeedsRecursive(t *testing.T) {
	dir := writeGrepFixture(t)
	_, err := runExtract(t, filepath.Join(dir, "plain.txt"), "-g", "x")
	if err == nil || !strings.Contains(err.Error(), "--grep needs -r") {
		t.Errorf("expected a --grep-needs--r error, got: %v", err)
	}
}
