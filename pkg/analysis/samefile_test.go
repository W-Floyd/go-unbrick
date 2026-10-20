package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// Two paths to one inode are the same bytes with no read: the files are made
// unreadable after their nodes exist, so a read would fail.
func TestSameFileNeedsNoRead(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	dir := t.TempDir()
	orig := filepath.Join(dir, "a.bin")
	link := filepath.Join(dir, "b.bin")
	copyp := filepath.Join(dir, "c.bin")
	body := make([]byte, 4096)
	for _, p := range []string{orig, copyp} {
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(orig, link); err != nil {
		t.Skip("no hard links here:", err)
	}
	d, err := dirNode(dir)
	if err != nil {
		t.Fatal(err)
	}
	get := func(name string) *carve.Node {
		n, err := d.Walk(name)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	a, b, c := get("a.bin"), get("b.bin"), get("c.bin")
	for _, p := range []string{orig, copyp} {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
	}
	if same, err := sameBytes(a, b); err != nil || !same {
		t.Errorf("a hard link: same=%v err=%v", same, err)
	}
	if same, err := sameBytes(a, a); err != nil || !same {
		t.Errorf("a file against itself: same=%v err=%v", same, err)
	}
	if sameFile(a, c) {
		t.Error("a separate copy was taken for the same file")
	}
}
