package srcfile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// solidArchive makes a solid 7z of a few files with a real 7-Zip, skipping the test
// where there is none.
func solidArchive(t *testing.T) (path string, want map[string][]byte) {
	t.Helper()
	bin := ""
	for _, b := range []string{"7zz", "7z", "7zr", "7za"} {
		if p, err := exec.LookPath(b); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		t.Skip("no 7-Zip to make a solid archive with")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	want = map[string][]byte{}
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("sub/f%d.txt", i)
		body := bytes.Repeat([]byte(fmt.Sprintf("file %d line\n", i)), 500+i)
		os.WriteFile(filepath.Join(src, name), body, 0o644)
		want[name] = body
	}
	path = filepath.Join(dir, "a.7z")
	cmd := exec.Command(bin, "a", "-t7z", "-ms=on", "-bso0", "-bsp0", path, "sub")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("7-Zip could not make the archive: %v %s", err, out)
	}
	return path, want
}

// useSpoolDir points the spool cache at a fresh directory and forgets what the
// process knows of earlier spools.
func useSpoolDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldDir, oldNative := spoolDir, nativeSevenZip
	spoolDir = func() string { return dir }
	t.Cleanup(func() { spoolDir, nativeSevenZip = oldDir, oldNative })
	forgetSpools()
	return dir
}

func forgetSpools() {
	spools.Range(func(k, _ any) bool { spools.Delete(k); return true })
}

func readAll(t *testing.T, path string) map[string][]byte {
	t.Helper()
	es, closer, err := Entries(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	got := map[string][]byte{}
	for _, e := range es {
		rc, err := e.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		got[e.Name] = b
	}
	return got
}

func sameContent(t *testing.T, got, want map[string][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d members, want %d", len(got), len(want))
	}
	for n, w := range want {
		if !bytes.Equal(got[n], w) {
			t.Errorf("%s: content differs", n)
		}
	}
}

func TestSolidSevenZipNativeAndKept(t *testing.T) {
	path, want := solidArchive(t)
	dir := useSpoolDir(t)
	sameContent(t, readAll(t, path), want)
	bins, _ := filepath.Glob(filepath.Join(dir, "*.bin"))
	if len(bins) != 1 {
		t.Fatalf("kept spools: %v", bins)
	}
	first, _ := os.Stat(bins[0])

	// A new process (the in-memory table forgotten) finds the kept spool and does
	// not decode again: it is the same file.
	forgetSpools()
	nativeSevenZip = func() string { t.Error("decoded again"); return "" }
	sameContent(t, readAll(t, path), want)
	again, _ := os.Stat(bins[0])
	if !os.SameFile(first, again) {
		t.Error("the spool was rebuilt")
	}
}

func TestSolidSevenZipWithoutNative(t *testing.T) {
	path, want := solidArchive(t)
	useSpoolDir(t)
	nativeSevenZip = func() string { return "" }
	sameContent(t, readAll(t, path), want)
}

// A 7-Zip that writes something other than the archive's content is not trusted: the
// Go decoder runs instead and the answer is still right.
func TestSolidSevenZipBadNativeFallsBack(t *testing.T) {
	path, want := solidArchive(t)
	useSpoolDir(t)
	bad := filepath.Join(t.TempDir(), "7zz")
	os.WriteFile(bad, []byte("#!/bin/sh\nprintf 'not the content'\n"), 0o755)
	nativeSevenZip = func() string { return bad }
	sameContent(t, readAll(t, path), want)
}

func TestEvictSpoolsRemovesTheLeastRecentlyUsed(t *testing.T) {
	dir := t.TempDir()
	old := spoolCacheMax
	spoolCacheMax = 100
	defer func() { spoolCacheMax = old }()
	write := func(name string, size int, age time.Duration) {
		p := filepath.Join(dir, name)
		os.WriteFile(p, make([]byte, size), 0o644)
		when := time.Now().Add(-age)
		os.Chtimes(p, when, when)
	}
	write("a.bin", 60, 3*time.Hour)
	write("b.bin", 60, 2*time.Hour)
	write("stale.tmp-1", 10, 48*time.Hour)
	write("fresh.tmp-2", 10, time.Minute)
	evictSpools(dir, 10) // 120 + 10 > 100: the oldest goes, and then it fits
	exists := func(n string) bool { _, err := os.Stat(filepath.Join(dir, n)); return err == nil }
	if exists("a.bin") || !exists("b.bin") {
		t.Errorf("a.bin %v b.bin %v", exists("a.bin"), exists("b.bin"))
	}
	if exists("stale.tmp-1") || !exists("fresh.tmp-2") {
		t.Error("temporary files: the stale one goes, a fresh one (maybe being written) stays")
	}
}
