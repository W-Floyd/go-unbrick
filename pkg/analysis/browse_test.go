package analysis

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

func TestSkipIsARegexOnTheFullPath(t *testing.T) {
	dir := browseFixture(t)
	top, err := OpenInput(dir, []string{`(^|/)notes\.txt$`})
	if err != nil || strings.Contains(entryNames(top), "notes.txt") || !strings.Contains(entryNames(top), "data.json") {
		t.Errorf("%v %s", err, entryNames(top))
	}
	// A path from the input's root: "sub/inner.txt" is skipped by its directory, not its name.
	sub, ok := top.Find("sub")
	if !ok {
		t.Fatalf("no sub in %s", entryNames(top))
	}
	for skip, hidden := range map[string]bool{`^sub/inner`: true, `^inner`: false, `sub/.*\.txt$`: true} {
		l, err := Open(sub, []string{skip})
		if err != nil || strings.Contains(entryNames(l), "inner.txt") != !hidden {
			t.Errorf("skip %q: %v %s", skip, err, entryNames(l))
		}
	}
	if !SkipPath([]string{"", `a/b`}, "x/a/b/c") || SkipPath([]string{"", `[`}, "x") {
		t.Error("SkipPath: empty and invalid patterns match nothing, others search the path")
	}
}

func TestBrowseGrepFindsContentIncludingInsideAContainer(t *testing.T) {
	old := BrowseGrep
	t.Cleanup(func() { BrowseGrep = old })
	BrowseGrep = regexp.MustCompile("abc")
	BrowseDepth = 3

	top, err := OpenInput(browseFixture(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	// "abc" is pkg.tar's one member's content, not any top-level file's own
	// bytes: the archive must be opened to find it, and only it (plus dirs
	// that hold it) should be kept.
	if names := entryNames(top); names != "pkg.tar" {
		t.Errorf("top level: %q", names)
	}
	inner, err := Open(mustFind(t, top, "pkg.tar"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if names := entryNames(inner); names != "m.txt" {
		t.Errorf("inside pkg.tar: %q", names)
	}
}

func TestBrowseGrepAndMatchAreCombinedWithAnd(t *testing.T) {
	old, oldM := BrowseGrep, BrowseMatch
	t.Cleanup(func() { BrowseGrep, BrowseMatch = old, oldM })
	BrowseDepth = 3

	dir := browseFixture(t)
	BrowseGrep, BrowseMatch = regexp.MustCompile("hello|inner"), nil
	top, err := OpenInput(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if names := entryNames(top); names != "notes.txt sub" {
		t.Errorf("content-only: %q", names)
	}
	BrowseMatch = regexp.MustCompile(`^sub/`)
	top, err = OpenInput(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if names := entryNames(top); names != "sub" {
		t.Errorf("content+path AND: %q (notes.txt matches content but not path)", names)
	}
}

func mustFind(t *testing.T, l *BrowseLevel, name string) BrowseEntry {
	t.Helper()
	e, ok := l.Find(name)
	if !ok {
		t.Fatalf("no %q in %s", name, entryNames(l))
	}
	return e
}

func TestBrowserSetFiltersReopensAndClearsCache(t *testing.T) {
	old := BrowseMatch
	t.Cleanup(func() { BrowseMatch = old })

	dir := browseFixture(t)
	b, err := NewBrowser(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	top, err := b.LevelAt(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entryNames(top), "notes.txt") {
		t.Fatalf("expected the unfiltered listing, got %q", entryNames(top))
	}

	re := regexp.MustCompile(`^sub/`)
	if err := b.SetFilters(re, nil, 3); err != nil {
		t.Fatal(err)
	}
	top, err = b.LevelAt(nil)
	if err != nil {
		t.Fatal(err)
	}
	if names := entryNames(top); names != "sub" {
		t.Errorf("after SetFilters: %q", names)
	}

	// Clearing filters must restore the full listing, not reuse anything cached
	// under the narrower one.
	if err := b.SetFilters(nil, nil, 3); err != nil {
		t.Fatal(err)
	}
	top, err = b.LevelAt(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entryNames(top), "notes.txt") {
		t.Errorf("after clearing filters: %q", entryNames(top))
	}
}

// A Browser's OnOpen hears about an entry the moment LevelAt opens it, with its path and children, and never
// again for the same entry: a second LevelAt of the same path is answered from the cache.
func TestBrowserOnOpen(t *testing.T) {
	dir := browseFixture(t)
	b, err := NewBrowser(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	b.OnOpen = func(e BrowseEntry, sub *BrowseLevel) {
		ok := "ok"
		if sub == nil {
			ok = "fail"
		}
		seen = append(seen, e.Path+":"+ok)
	}
	if _, err := b.LevelAt([]string{"sub"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.LevelAt([]string{"pkg.tar"}); err != nil {
		t.Fatal(err)
	}
	if want := "sub:ok|pkg.tar:ok"; strings.Join(seen, "|") != want {
		t.Errorf("seen = %q, want %q", seen, want)
	}
	// The same entries again: nothing new, both are cached.
	if _, err := b.LevelAt([]string{"sub"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.LevelAt([]string{"pkg.tar"}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Errorf("a cached level fired OnOpen again: %v", seen)
	}
	// An entry with nowhere to go (a tar member, not a container): OnOpen still hears about it, told it failed.
	if _, err := b.LevelAt([]string{"pkg.tar", "m.txt"}); err == nil {
		t.Fatal("a plain tar member should not open")
	}
	if len(seen) != 3 || seen[2] != "pkg.tar/m.txt:fail" {
		t.Errorf("a failed open: %v", seen)
	}
}

// LevelAt already under way must not race a concurrent SetFilters reopening the input and discarding the
// cache: a Browser is shared by every request a browse page serves, and SetFilters (the caller's job to not
// call twice at once: it also writes the process-global BrowseMatch/BrowseGrep/BrowseDepth) can land while
// others are already reading levels. Under -race this failed before LevelAt stopped holding the address of a
// field SetFilters replaces in place.
func TestBrowserLevelAtDuringSetFiltersIsSafe(t *testing.T) {
	old := BrowseMatch
	t.Cleanup(func() { BrowseMatch = old })
	dir := browseFixture(t)
	b, err := NewBrowser(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.LevelAt(nil); err != nil { // warm the cache SetFilters will discard
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					b.LevelAt(nil)
					b.LevelAt([]string{"sub"})
				}
			}
		}()
	}
	re := regexp.MustCompile(`^sub/`)
	if err := b.SetFilters(re, nil, 3); err != nil {
		t.Fatal(err)
	}
	close(stop)
	wg.Wait()
}
