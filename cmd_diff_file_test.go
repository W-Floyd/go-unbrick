package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runDiff runs `unbrick diff args…` and returns what it printed.
func runDiff(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newDiffCmd()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs(args)
	return captureStdout(func() error { return cmd.Execute() })
}

func TestDiffTwoTextFiles(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a.txt"), filepath.Join(d, "b.txt")
	os.WriteFile(a, []byte("alpha\nbeta\ngamma\n"), 0o644)
	os.WriteFile(b, []byte("alpha\nBETA CHANGED\ngamma\n"), 0o644)
	// Two files that are not signed images used to fail: "cannot read ELF identifier".
	out, err := runDiff(t, a, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"a.txt vs b.txt", "1 removed, 1 added", "- beta", "+ BETA CHANGED", "@@ -1,3 +1,3 @@"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape codes on a pipe:\n%q", out)
	}
}

func TestDiffAFileInsideDirectoriesAndArchives(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{"sub/deep/x.txt": []byte("one\ntwo\n"), "sub/other.txt": []byte("same\n")})
	writeTree(t, b, map[string][]byte{"sub/deep/x.txt": []byte("one\nTWO!\n"), "sub/other.txt": []byte("same\n")})

	out, err := runDiff(t, a, b, "--path", "sub/deep/x.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "- two") || !strings.Contains(out, "+ TWO!") || !strings.Contains(out, "sub/deep/x.txt") {
		t.Errorf("a file inside two directories:\n%s", out)
	}
	if strings.Contains(out, "other.txt") {
		t.Errorf("the whole tree was compared, not the one file:\n%s", out)
	}

	// Inside a tar, as ls and extract take a path; the two archives may have different names.
	ta := writeTar(t, "old.tar", map[string]string{"etc/conf": "mode=1\nname=x\n", "etc/keep": "k"})
	tb := writeTar(t, "new.tar", map[string]string{"etc/conf": "mode=2\nname=x\n", "etc/keep": "k"})
	out, err = runDiff(t, ta, tb, "--path", "etc/conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "- mode=1") || !strings.Contains(out, "+ mode=2") || !strings.Contains(out, "old.tar vs new.tar") {
		t.Errorf("a file inside two tars:\n%s", out)
	}

	// A directory against an archive.
	out, err = runDiff(t, a, tb, "--path", "sub/deep/x.txt")
	if err == nil {
		t.Errorf("a path that is in only one input was not reported:\n%s", out)
	} else if !strings.Contains(err.Error(), "no such path: sub/deep/x.txt") || !strings.Contains(err.Error(), "new.tar") {
		t.Errorf("the error should name the path and the input it is missing from: %v", err)
	}
}

func TestDiffAFileErrors(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	writeTree(t, a, map[string][]byte{"sub/x.txt": []byte("one\n")})
	writeTree(t, b, map[string][]byte{"sub/x.txt": []byte("two\n")})

	if _, err := runDiff(t, a, b, "--path", "sub/missing.txt"); err == nil || !strings.Contains(err.Error(), "no such path") {
		t.Errorf("a missing member: %v", err)
	}
	if _, err := runDiff(t, a, b, "--path", "sub"); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("a directory named as the file: %v", err)
	}
	if _, err := runDiff(t, a, b, "--path", "sub/x.txt", "--view", "nonsense"); err == nil || !strings.Contains(err.Error(), "--view") {
		t.Errorf("a bad view: %v", err)
	}
	// Without --path, directories are still compared whole.
	out, err := runDiff(t, a, b)
	if err != nil || !strings.Contains(out, "1 changed") {
		t.Errorf("directories without --path: %v\n%s", err, out)
	}
}

func TestDiffAFileIdenticalAndContext(t *testing.T) {
	d := t.TempDir()
	same1, same2 := filepath.Join(d, "s1.txt"), filepath.Join(d, "s2.txt")
	os.WriteFile(same1, []byte("same\n"), 0o644)
	os.WriteFile(same2, []byte("same\n"), 0o644)
	if out, err := runDiff(t, same1, same2); err != nil || !strings.Contains(out, "identical") {
		t.Errorf("identical files: %v\n%s", err, out)
	}

	var x, y strings.Builder
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&x, "line %d\n", i)
		if i == 15 {
			fmt.Fprintf(&y, "line fifteen\n")
		} else {
			fmt.Fprintf(&y, "line %d\n", i)
		}
	}
	fa, fb := filepath.Join(d, "x.txt"), filepath.Join(d, "y.txt")
	os.WriteFile(fa, []byte(x.String()), 0o644)
	os.WriteFile(fb, []byte(y.String()), 0o644)

	out, _ := runDiff(t, fa, fb)
	if !strings.Contains(out, "line 12") || !strings.Contains(out, "line 18") || strings.Contains(out, "line 11") {
		t.Errorf("the default is three lines of context:\n%s", out)
	}
	out, _ = runDiff(t, fa, fb, "-U", "0")
	if strings.Contains(out, "line 14") || strings.Contains(out, "line 16") || !strings.Contains(out, "+ line fifteen") {
		t.Errorf("-U 0 shows only the change:\n%s", out)
	}
	out, _ = runDiff(t, fa, fb, "--context", "6")
	if !strings.Contains(out, "line 9") || strings.Contains(out, "line 8") {
		t.Errorf("--context 6:\n%s", out)
	}
}

func TestDiffAFileBinary(t *testing.T) {
	r := rand.New(rand.NewSource(9))
	body := noStrings(r, 40<<10)
	mk := func(version string, flip bool) []byte {
		b := append([]byte(nil), body...)
		if flip {
			b[777] ^= 0xff
		}
		return append(append(b, 0x01), append([]byte("version="+version), 0)...)
	}
	d := t.TempDir()
	only1, only2 := filepath.Join(d, "p1.bin"), filepath.Join(d, "p2.bin")
	os.WriteFile(only1, mk("1.0.0", false), 0o644)
	os.WriteFile(only2, mk("1.0.1", false), 0o644)
	both := filepath.Join(d, "p3.bin")
	os.WriteFile(both, mk("1.0.1", true), 0o644)

	out, err := runDiff(t, only1, only2)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Only strings differ", "Overlap", "shared", "unique", "- version=1.0.0", "+ version=1.0.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("binary diff lacks %q:\n%s", want, out)
		}
	}
	if out, _ = runDiff(t, only1, both); !strings.Contains(out, "Not only strings") {
		t.Errorf("a non-string byte also differs:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Error("escape codes on a pipe")
	}

	// The other views.
	out, _ = runDiff(t, only1, only2, "--view", "strings")
	if !strings.Contains(out, "Strings (6+ chars): 1 removed, 1 added") || strings.Contains(out, "content-defined chunks") {
		t.Errorf("--view strings:\n%s", out)
	}
	out, _ = runDiff(t, only1, only2, "--view", "overlap")
	// Small and alike, so measured byte for byte: the one changed byte is the only unique one.
	if !strings.Contains(out, "Overlap") || !strings.Contains(out, "measured byte for byte") ||
		!strings.Contains(out, "unique          1 B") || strings.Contains(out, "- version=1.0.0") {
		t.Errorf("--view overlap:\n%s", out)
	}
}

// Long lines on a pipe are whole: nothing is wrapped or cut for a terminal that
// is not there.
func TestDiffAFileKeepsLongLinesWholeOnAPipe(t *testing.T) {
	long := strings.Repeat("word ", 400) // 2000 columns
	d := t.TempDir()
	a, b := filepath.Join(d, "a.txt"), filepath.Join(d, "b.txt")
	os.WriteFile(a, []byte("head\n"+long+"one\n"), 0o644)
	os.WriteFile(b, []byte("head\n"+long+"two\n"), 0o644)
	out, err := runDiff(t, a, b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "↳") || strings.Contains(out, "…") {
		t.Errorf("a line was wrapped or cut on a pipe:\n%.300s", out)
	}
	if !strings.Contains(out, strings.TrimSpace(long)) {
		t.Error("the long line is not there whole")
	}
}
