package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// A member that reads at random is recon'd in place, as a virtual input, with no
// copy written to disk.
func TestReconOfARandomAccessMemberWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("a.txt")
	w.Write([]byte("hello"))
	zw.Close()
	node := carve.FromBytes("inner.zip", buf.Bytes())
	if !node.RandomAccess() {
		t.Fatal("the fixture does not read at random")
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // a spool would land here
	out := stripANSI(runReconJob(reconJob{name: "inner.zip", node: node}))
	if !strings.Contains(out, "Type:  zip") || strings.Contains(out, "[!]") {
		t.Errorf("recon of the member:\n%s", out)
	}
	if !strings.Contains(out, "a.txt") {
		t.Errorf("recon did not list the member's contents:\n%s", out)
	}
	if entries, _ := readDirNames(tmp); len(entries) != 0 {
		t.Errorf("something was written to disk: %v", entries)
	}
	// And the virtual path is forgotten afterwards.
	if _, err := infile.Open("virtual:1/inner.zip"); err == nil {
		t.Error("the virtual input outlived the job")
	}
}

func readDirNames(dir string) ([]string, error) {
	des, err := infile.ReadDir(dir)
	var out []string
	for _, d := range des {
		out = append(out, d.Name())
	}
	return out, err
}

// drain runs the queue's side of a job without the recon: claim the next job and
// finish it, as run does, returning its name.
func drain(q *reconQueue) string {
	job := q.next()
	q.mu.Lock()
	q.inflightKey, q.inflightName = "", ""
	q.mu.Unlock()
	q.cond.Broadcast()
	return job.name
}

// What the crawl queues runs only when nothing else is waiting, and anything the
// user navigates to is promoted out of it.
func TestCrawlJobsRunBehindEverythingElse(t *testing.T) {
	q := newReconQueue()
	q.enqueueLow(reconJob{key: "k:low1", name: "low1"})
	q.enqueueLow(reconJob{key: "k:low2", name: "low2"})
	q.enqueue(reconJob{key: "k:fg", name: "fg"})
	if got := drain(q); got != "fg" {
		t.Errorf("first: %s, want the foreground job", got)
	}
	// Navigating to a crawled entry promotes it ahead of the rest of the crawl.
	q.enqueue(reconJob{key: "k:low2", name: "low2"})
	if got := drain(q); got != "low2" {
		t.Errorf("second: %s, want the promoted one", got)
	}
	if got := drain(q); got != "low1" {
		t.Errorf("third: %s", got)
	}
	// Highlighting one the crawl queued is a bump.
	q.enqueueLow(reconJob{key: "k:a", name: "a"})
	q.enqueueLow(reconJob{key: "k:b", name: "b"})
	q.bump("k:b")
	if got := drain(q); got != "b" {
		t.Errorf("bumped: %s", got)
	}
	// Done work is not queued again.
	q.enqueueLow(reconJob{key: "k:b", name: "b"})
	q.enqueue(reconJob{key: "k:b", name: "b"})
	if got := drain(q); got != "a" {
		t.Errorf("a finished job came back: %s", got)
	}
}

// With the crawl on, the queue lists what it was shown and queues the contents,
// to any depth, one listing at a time and only when idle.
func TestCrawlListsDownTheWholeTree(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"top.txt": "t", "a/mid.txt": "m", "a/b/deep.txt": "d", "a/b/c/deepest.txt": "e"} {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	q := newReconQueue()
	q.crawlOn = true
	root, err := analysis.ListDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range root.Entries {
		q.addCrawl(e)
	}
	go q.crawl()
	// (The entries on screen are queued by the frame itself; the crawl finds what is inside.
	// A directory has no recon of its own.)
	want := map[string]bool{"mid.txt": true, "deep.txt": true, "deepest.txt": true}
	got := map[string]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for len(got) < len(want) {
			got[drain(q)] = true
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("the crawl stopped part-way: %v", got)
	}
	for n := range want {
		if !got[n] {
			t.Errorf("never reconned %s (got %v)", n, got)
		}
	}
	// With it off, nothing is noted.
	off := newReconQueue()
	off.addCrawl(root.Entries[0])
	if len(off.crawlTodo) != 0 {
		t.Error("an entry was noted with the crawl off")
	}
}
