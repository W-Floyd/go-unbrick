package zippasswords

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFindsFilesByNameConvention(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "passwords.txt", "hunter2\nswordfish\n")
	writeFile(t, dir, "2024-ev6_wordlist.txt", "letmein\n")
	writeFile(t, dir, "notes.txt", "ignored\n") // no matching word in the name
	Set(nil)
	if err := Load(dir); err != nil {
		t.Fatal(err)
	}
	got := Passwords()
	want := map[string]bool{"hunter2": true, "swordfish": true, "letmein": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want exactly %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected password %q (from notes.txt?)", p)
		}
	}
}

func TestLoadSkipsBlankLinesAndComments(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "passwd.txt", "\n# a comment\nreal-password\n\n")
	Set(nil)
	if err := Load(dir); err != nil {
		t.Fatal(err)
	}
	if got := Passwords(); len(got) != 1 || got[0] != "real-password" {
		t.Errorf("got %v, want [real-password]", got)
	}
}

func TestLoadDedupesAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "password-1.txt", "shared\nonly-in-1\n")
	writeFile(t, dir, "password-2.txt", "shared\nonly-in-2\n")
	Set(nil)
	if err := Load(dir); err != nil {
		t.Fatal(err)
	}
	if n := Count(); n != 3 {
		t.Errorf("Count() = %d, want 3 (shared, only-in-1, only-in-2)", n)
	}
}

func TestLoadOnDirWithNoPasswordFilesLoadsNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "key1.bin", "deadbeef")
	Set(nil)
	if err := Load(dir); err != nil {
		t.Fatal(err)
	}
	if n := Count(); n != 0 {
		t.Errorf("Count() = %d, want 0", n)
	}
}

func TestWithVendorTriesVendorFirstThenLoaded(t *testing.T) {
	Set([]string{"from-list", "shared"})
	base := func(zip *carve.Node, member string) []string { return []string{"from-vendor", "shared"} }
	got := WithVendor(base)(nil, "member.bin")
	want := []string{"from-vendor", "shared", "from-list"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
			break
		}
	}
}

func TestWithVendorWithNothingLoadedActsLikeBase(t *testing.T) {
	Set(nil)
	base := func(zip *carve.Node, member string) []string { return []string{"only-vendor"} }
	got := WithVendor(base)(nil, "member.bin")
	if len(got) != 1 || got[0] != "only-vendor" {
		t.Errorf("got %v, want [only-vendor]", got)
	}
}
