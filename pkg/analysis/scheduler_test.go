package analysis

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tarOf(t *testing.T, members ...any) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i+1 < len(members); i += 2 {
		var data []byte
		switch v := members[i+1].(type) {
		case string:
			data = []byte(v)
		case []byte:
			data = v
		}
		tw.WriteHeader(&tar.Header{Name: members[i].(string), Mode: 0o644, Size: int64(len(data)), ModTime: time.Unix(1_700_000_000, 0)})
		tw.Write(data)
	}
	tw.Close()
	return buf.Bytes()
}

// nested returns the bytes of a tar holding a tar holding a tar holding x.txt,
// the innermost differing between old and new.
func nested(t *testing.T, content string) []byte {
	inner := tarOf(t, "x.txt", content)
	mid := tarOf(t, "in.tar", inner, "m.txt", "same")
	return tarOf(t, "mid.tar", mid, "o.txt", "same")
}

func nestedDirs(t *testing.T) (a, b string) {
	a, b = t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(a, "pkg_v1.tar"), nested(t, "old"), 0o644)
	os.WriteFile(filepath.Join(b, "pkg_v2.tar"), nested(t, "new!"), 0o644)
	return a, b
}

// compared walks the tree and says how many pairs have had their members looked at.
func comparedCount(r *Run) (n int) {
	root, _, _ := r.get()
	liveMu.Lock()
	defer liveMu.Unlock()
	var walk func([]*diffLine)
	walk = func(ls []*diffLine) {
		for _, l := range ls {
			if l.compared {
				n++
			}
			walk(l.sub)
		}
	}
	walk(root.lines)
	return n
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Without AutoDeepen nothing goes deeper on its own, and a focus does nothing.
func TestNoAutoDeepenLeavesWhatTheDepthLeftOut(t *testing.T) {
	a, b := nestedDirs(t)
	r := Start(Config{A: a, B: b, Depth: 1})
	<-r.Done()
	e := r.Entries(r.Root(), false)[0]
	r.Focus(e)
	time.Sleep(300 * time.Millisecond)
	if e := r.Entries(r.Root(), false)[0]; e.Compared || e.Pending {
		t.Errorf("went deeper unasked: %+v", e)
	}
}

// Focusing a pair the first pass stopped at compares it at once; the background
// then goes on, each path as far as AutoDeepen levels, and no further.
func TestFocusExpandsAndTheBackgroundGoesAsFarAsAutoDeepen(t *testing.T) {
	a, b := nestedDirs(t)
	r := Start(Config{A: a, B: b, Depth: 1, AutoDeepen: 2})
	defer r.Close()
	<-r.Done()
	r.Focus(r.Entries(r.Root(), false)[0])
	// outer (level 0) and mid (level 1) are within 2 levels; in.tar (level 2) is not.
	waitFor(t, "two levels", func() bool { return comparedCount(r) == 2 && !r.Working() })
	time.Sleep(300 * time.Millisecond) // and it stays there
	if n := comparedCount(r); n != 2 {
		t.Errorf("the background went past AutoDeepen: %d pairs compared", n)
	}
	// Explicitly asking still goes on: Deepen ignores the background's limit.
	if n, err := r.Deepen(); err != nil || n != 1 {
		t.Fatalf("deepen: %d %v", n, err)
	}
	waitFor(t, "the third level", func() bool { return comparedCount(r) == 3 && !r.Working() })
}

// Without a limit the background compares everything it can, nearest the focus
// first, and then idles.
func TestUnlimitedAutoDeepenComparesEverything(t *testing.T) {
	a, b := nestedDirs(t)
	r := Start(Config{A: a, B: b, Depth: 1, AutoDeepen: -1})
	defer r.Close()
	waitFor(t, "all three levels", func() bool { return r.Finished() && comparedCount(r) == 3 && !r.Working() })
	if s := r.Summary(); s == "" {
		t.Error("no summary")
	}
}

func TestChainDistanceIsStepsThroughTheCommonAncestor(t *testing.T) {
	root, x, y, z := &diffLine{}, &diffLine{}, &diffLine{}, &diffLine{}
	// root > x > (the candidates' parent chains)
	if d := chainDist([]*diffLine{root, x}, true, []*diffLine{root, x}); d != 0 {
		t.Errorf("same place: %d", d)
	}
	if d := chainDist([]*diffLine{root, x, y}, true, []*diffLine{root, x}); d != 1 {
		t.Errorf("one below the focus: %d", d)
	}
	if d := chainDist([]*diffLine{root, y}, true, []*diffLine{root, z}); d != 2 {
		t.Errorf("siblings: %d", d)
	}
	if d := chainDist([]*diffLine{root, x, y}, false, nil); d != 3 {
		t.Errorf("no focus is depth: %d", d)
	}
}
