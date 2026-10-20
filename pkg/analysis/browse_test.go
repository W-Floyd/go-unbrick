package analysis

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func browseFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	put := func(name string, data []byte) {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("notes.txt", []byte("hello\n"))
	put("data.json", []byte(`{"a":1,"b":[2,3]}`))
	put(".hidden", []byte("x"))
	put("sub/inner.txt", []byte("inner\n"))
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "m.txt", Mode: 0o644, Size: 3})
	tw.Write([]byte("abc"))
	tw.Close()
	put("pkg.tar", buf.Bytes())
	return dir
}

func entryNames(l *BrowseLevel) string {
	var n []string
	for _, e := range l.Entries {
		n = append(n, e.Name)
	}
	return strings.Join(n, " ")
}

func TestListDirAndOpen(t *testing.T) {
	dir := browseFixture(t)
	l, err := ListDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := entryNames(l); got != "data.json notes.txt pkg.tar sub" {
		t.Fatalf("level: %s", got)
	}
	by := map[string]BrowseEntry{}
	for _, e := range l.Entries {
		by[e.Name] = e
	}
	if e := by["sub"]; !e.Dir || !e.Openable || e.Size != -1 {
		t.Errorf("sub: %+v", e)
	}
	if e := by["notes.txt"]; !e.Text || e.Openable || e.Size != 6 {
		t.Errorf("notes.txt: %+v", e)
	}
	if e := by["pkg.tar"]; e.Text || !e.Openable {
		t.Errorf("pkg.tar: %+v", e)
	}
	// Into a directory, into a file that is a container, and a refusal.
	sub, err := Open(by["sub"], nil)
	if err != nil || entryNames(sub) != "inner.txt" {
		t.Fatalf("sub: %v %v", err, sub)
	}
	pkg, err := Open(by["pkg.tar"], nil)
	if err != nil || entryNames(pkg) != "m.txt" || pkg.Node == nil {
		t.Fatalf("pkg.tar: %v", err)
	}
	if e := pkg.Entries[0]; !e.Text || e.Container {
		t.Errorf("m.txt: %+v", e)
	}
	if _, err := Open(pkg.Entries[0], nil); !errors.Is(err, ErrNotContainer) {
		t.Errorf("opening a plain member: %v", err)
	}
	// Refresh lists again.
	if again, err := sub.Refresh(nil); err != nil || entryNames(again) != "inner.txt" {
		t.Errorf("refresh: %v", err)
	}
}

func TestBrowserLevelsByPathAndReading(t *testing.T) {
	dir := browseFixture(t)
	b, err := NewBrowser(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := b.LevelAt([]string{"pkg.tar"})
	if err != nil || entryNames(l) != "m.txt" {
		t.Fatalf("%v", err)
	}
	if l2, _ := b.LevelAt([]string{"pkg.tar"}); l2 != l {
		t.Error("a level was listed twice")
	}
	if _, err := b.LevelAt([]string{"nope"}); err != ErrNoSuchEntry {
		t.Errorf("%v", err)
	}
	e, _ := l.Find("m.txt")
	data, trunc, err := ReadEntry(e, 2)
	if err != nil || string(data) != "ab" || !trunc {
		t.Errorf("read: %q %v %v", data, trunc, err)
	}
	if data, trunc, _ := ReadEntry(e, 100); string(data) != "abc" || trunc {
		t.Errorf("read all: %q %v", data, trunc)
	}
	if pretty, ok := PrettyPrint("data.json", []byte(`{"a":1}`)); !ok || !strings.Contains(string(pretty), "\n  \"a\": 1") {
		t.Errorf("pretty: %q", pretty)
	}
	if _, ok := PrettyPrint("notes.txt", []byte("hello")); ok {
		t.Error("plain text pretty-printed")
	}
	// A tar (not a directory) is a valid input too.
	tb, err := NewBrowser(filepath.Join(dir, "pkg.tar"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := tb.LevelAt(nil); entryNames(l) != "m.txt" {
		t.Errorf("tar input: %s", entryNames(l))
	}
}

func TestSkipFilterHook(t *testing.T) {
	old := SkipFilter
	t.Cleanup(func() { SkipFilter = old })
	SkipFilter = func(paths, skip []string) []string {
		var out []string
		for _, p := range paths {
			if !strings.HasSuffix(p, "notes.txt") {
				out = append(out, p)
			}
		}
		return out
	}
	l, err := ListDir(browseFixture(t), []string{"x"})
	if err != nil || strings.Contains(entryNames(l), "notes.txt") {
		t.Errorf("%v %s", err, entryNames(l))
	}
}
