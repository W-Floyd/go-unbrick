package analysis

import (
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

func TestListNodeFoldsSlashNamesIntoDirectories(t *testing.T) {
	root := carve.Dir("pkg", []*carve.Node{
		carve.FromBytes("a/b/x.txt", []byte("x")),
		carve.FromBytes("a/y.txt", []byte("y")),
		carve.FromBytes("a/b/z.txt", []byte("z")),
		carve.FromBytes("top.txt", []byte("t")),
	})
	l, err := ListNode(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 2 || l.Entries[0].Name != "a" || !l.Entries[0].Dir || l.Entries[1].Name != "top.txt" {
		t.Fatalf("root: %+v", l.Entries)
	}
	a, err := Open(l.Entries[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 2 || a.Entries[0].Name != "b" || a.Entries[1].Name != "y.txt" {
		t.Fatalf("a: %+v", a.Entries)
	}
	b, err := a.Refresh(nil)
	if err != nil || len(b.Entries) != 2 {
		t.Fatalf("refresh: %v %+v", err, b)
	}
	sub, _ := Open(a.Entries[0], nil)
	if len(sub.Entries) != 2 || sub.Entries[0].Name != "x.txt" {
		t.Fatalf("a/b: %+v", sub.Entries)
	}
}
