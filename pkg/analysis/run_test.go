package analysis

import (
	"strings"
	"testing"
)

func names(es []Entry) string {
	var n []string
	for _, e := range es {
		n = append(n, e.Name)
	}
	return strings.Join(n, " | ")
}

// A level lists its directories (made from the paths) first, then its lines in
// the order found; a container with something inside, or still being compared,
// can be gone into; dropped lines are not there; a rename is one name, not a path.
func TestSnapshotLevel(t *testing.T) {
	inner := &treeDiffTally{lines: []*diffLine{{kind: '~', path: "pkg.tar/m.bin"}}}
	running := &diffLine{kind: '~', path: "pkg.tar", subT: inner} // its inside is being compared
	done := &diffLine{kind: '~', path: "cont.zip", sub: []*diffLine{{kind: '+', path: "cont.zip/in.bin"}}}
	root := &treeDiffTally{lines: []*diffLine{
		{kind: '~', path: "top.txt"},
		{kind: '+', path: "sub/new.txt"},
		{kind: '~', path: "sub/deep/x.txt"},
		{kind: '-', path: "sub/old.txt"},
		{kind: '~', path: "gone.txt", drop: true},
		running,
		done,
		{kind: '>', path: "old/a -> new/a"},
		{text: "      (oops)"},
	}}
	r := newRun()
	r.setRoot(root)
	top := r.Root()

	got := r.Entries(top, false)
	if want := "sub/ | top.txt | pkg.tar/ | cont.zip/ | old/a -> new/a | (oops)"; names(got) != want {
		t.Errorf("root level:\n got %s\nwant %s", names(got), want)
	}
	byName := map[string]Entry{}
	for _, e := range got {
		byName[e.Name] = e
	}
	if e := byName["sub/"]; e.Kind != Dir || !e.HasKids || e.Summary != "1 changed, 1 added, 1 removed" {
		t.Errorf("sub/: %+v", e)
	}
	if e := byName["pkg.tar/"]; !e.Pending || !e.HasKids {
		t.Errorf("pkg.tar/ should be pending and enterable: %+v", e)
	}
	if e := byName["cont.zip/"]; e.Pending || !e.HasKids {
		t.Errorf("cont.zip/ should be enterable and not pending: %+v", e)
	}
	if e := byName["top.txt"]; e.HasKids || e.Pending {
		t.Errorf("top.txt has nothing inside: %+v", e)
	}
	if e := byName["(oops)"]; e.Kind != Note || e.Text != "      (oops)" {
		t.Errorf("a note: %+v", e)
	}

	// ".." heads every level but the first.
	if up := r.Entries(top, true); up[0].Name != ".." || up[0].Kind != Up || len(up) != len(got)+1 {
		t.Errorf("with up: %s", names(up))
	}

	// Into a directory: its own names, and the directories below it.
	sub, err := r.Open(top, byName["sub/"])
	if err != nil {
		t.Fatal(err)
	}
	if want := "deep/ | new.txt | old.txt"; names(r.Entries(sub, false)) != want {
		t.Errorf("sub/: %s, want %s", names(r.Entries(sub, false)), want)
	}
	deep, _ := r.Open(sub, r.Entries(sub, false)[0])
	if got := r.Entries(deep, false); names(got) != "x.txt" || got[0].Kind != Changed {
		t.Errorf("sub/deep/: %s", names(got))
	}

	// Into a container: what was found inside it, live while it is still running.
	in, err := r.Open(top, byName["pkg.tar/"])
	if err != nil {
		t.Fatal(err)
	}
	if names(r.Entries(in, false)) != "m.bin" {
		t.Errorf("pkg.tar: %s", names(r.Entries(in, false)))
	}
	live(func() { inner.lines = append(inner.lines, &diffLine{kind: '+', path: "pkg.tar/n.bin"}) }) // found since
	if names(r.Entries(in, false)) != "m.bin | n.bin" {
		t.Errorf("pkg.tar after more was found: %s", names(r.Entries(in, false)))
	}
	live(func() { running.subT, running.sub = nil, inner.lines }) // finished: same level, now from sub
	if names(r.Entries(in, false)) != "m.bin | n.bin" {
		t.Errorf("pkg.tar once finished: %s", names(r.Entries(in, false)))
	}

	if got := newRun().Entries(top, false); len(got) != 0 {
		t.Errorf("before there is anything: %s", names(got))
	}
	// A plain file has nowhere to go.
	if _, err := r.Open(top, byName["top.txt"]); err != ErrNothingInside {
		t.Errorf("opening a plain file: %v", err)
	}
}

func TestFakeRun(t *testing.T) {
	r := NewFakeRun([]FakeLine{{Kind: Changed, Path: "a.txt"}, {Kind: Changed, Path: "p.tar", Pending: true, Kids: []FakeLine{{Kind: Added, Path: "p.tar/x"}}}}, false)
	es := r.Entries(r.Root(), false)
	if names(es) != "a.txt | p.tar/" || !es[1].Pending || r.Finished() {
		t.Fatalf("%s %+v", names(es), es)
	}
	r.FakeFinish()
	es = r.Entries(r.Root(), false)
	if es[1].Pending || !es[1].HasKids || !r.Finished() {
		t.Errorf("finished: %+v", es[1])
	}
}
