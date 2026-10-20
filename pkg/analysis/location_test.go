package analysis

import (
	"reflect"
	"testing"
)

func TestLocationRoundTrip(t *testing.T) {
	for _, l := range []Location{
		{},
		{Path: []string{"sub/"}, Entry: "x.txt"},
		{Path: []string{"a b/", "pkg.tar/", "in&out/"}, Entry: "enc_boot.img", View: ViewHex, NoWords: true},
		{Entry: "100% = 1+1", View: ViewStrings},
	} {
		frag := l.Fragment()
		got := ParseLocation("#" + frag)
		if got.Path == nil {
			got.Path = l.Path
		}
		if !reflect.DeepEqual(got, l) && !(len(got.Path) == 0 && len(l.Path) == 0 && got.Entry == l.Entry && got.View == l.View && got.NoWords == l.NoWords) {
			t.Errorf("%+v -> %q -> %+v", l, frag, got)
		}
	}
	if got := (Location{Path: []string{"a/", "b/"}, Entry: "e", View: ViewHex, NoWords: true}).Fragment(); got != "p=a%2F&p=b%2F&sel=e&view=hex&words=0" {
		t.Errorf("the text form the page keeps in its URL: %q", got)
	}
	// What is not understood is left out, not an error.
	if l := ParseLocation("?view=bogus&sel=x&junk=1"); l.View != "" || l.Entry != "x" {
		t.Errorf("%+v", l)
	}
}

func TestLocate(t *testing.T) {
	r := NewFakeRun([]FakeLine{
		{Kind: Changed, Path: "top.txt"},
		{Kind: Changed, Path: "sub/a.txt"},
		{Kind: Added, Path: "sub/deep/b.txt"},
	}, true)
	l, e, err := r.Locate(Location{Path: []string{"sub/", "deep/"}, Entry: "b.txt"})
	if err != nil || e.Kind != Added || names(r.Entries(l, false)) != "b.txt" {
		t.Fatalf("%v %+v %v", err, e, names(r.Entries(l, false)))
	}
	// The same level again is the one already opened.
	if l2, _ := r.LevelAt([]string{"sub/", "deep/"}); l2 != l {
		t.Error("a level was opened twice")
	}
	if _, _, err := r.Locate(Location{Path: []string{"nope/"}}); err != ErrNoSuchEntry {
		t.Errorf("a level that is not there: %v", err)
	}
	if _, _, err := r.Locate(Location{Entry: "nope"}); err != ErrNoSuchEntry {
		t.Errorf("an entry that is not there: %v", err)
	}
	if lv, e, err := r.Locate(Location{}); err != nil || lv != r.Root() || e.Name != "" {
		t.Errorf("the top: %v", err)
	}
}
