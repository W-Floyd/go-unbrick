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

// A file that is one pattern from end to end is said to be, by recon and by its
// label, not "unknown".
func TestReconSaysWhenAFileIsAFill(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	zeros := write("zeros.bin", make([]byte, 700000))
	out := stripANSI(runReconJob(reconJob{osPath: zeros, name: "zeros.bin"}))
	if !strings.Contains(out, "Fill: every byte is 0x00 (zeros)") {
		t.Errorf("zeros:\n%s", out)
	}
	word := write("word.bin", bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 50000))
	if out := stripANSI(runReconJob(reconJob{osPath: word, name: "word.bin"})); !strings.Contains(out, "4-byte pattern repeated: de ad be ef") {
		t.Errorf("word:\n%s", out)
	}
	tiny := write("tiny.bin", bytes.Repeat([]byte{0xff}, 64))
	if out := stripANSI(runReconJob(reconJob{osPath: tiny, name: "tiny.bin"})); !strings.Contains(out, "Fill: every byte is 0xff") {
		t.Errorf("a short file of one byte:\n%s", out)
	}
	// Changes after a long fill: said, and recon goes on.
	mostly := make([]byte, 1<<20)
	mostly[900000] = 9
	if out := stripANSI(runReconJob(reconJob{osPath: write("mostly.bin", mostly), name: "mostly.bin"})); !strings.Contains(out, "Leading fill:") || strings.Contains(out, "Fill: every") {
		t.Errorf("a fill that ends:\n%s", out)
	}
	// And a file that is not one.
	if out := stripANSI(runReconJob(reconJob{osPath: write("text.txt", []byte("hello\n")), name: "text.txt"})); strings.Contains(out, "Fill") {
		t.Errorf("text called a fill:\n%s", out)
	}
	if got := typeLabel("x.bin", make([]byte, 8192)); got != "fill 0x00" {
		t.Errorf("label of a blank start: %q", got)
	}
	if got := typeLabel("x.bin", bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 2048)); got != "fill deadbeef" {
		t.Errorf("label of a pattern: %q", got)
	}
}

// Entering an entry lists it off the UI's goroutine: nothing blocks, the frame
// appears when the listing is ready, and a request the user has moved on from is
// dropped.
func TestDescendListsInTheBackground(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "inner.txt"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(dir, "other"), 0o755)
	m, err := newBrowseModel(dir, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	selectNamed := func(name string) {
		for i, it := range m.list.Items() {
			if e, ok := it.(browseEntry); ok && e.name == name {
				m.list.Select(i)
				return
			}
		}
		t.Fatalf("no entry %q", name)
	}
	selectNamed("sub")
	cmd := m.descend()
	if cmd == nil || m.opening != "sub" || len(m.frames) != 1 {
		t.Fatalf("descend must return a command and leave the frame alone: cmd=%v opening=%q frames=%d", cmd != nil, m.opening, len(m.frames))
	}
	msg := cmd().(openedMsg)
	m.opened(msg)
	if len(m.frames) != 2 || m.opening != "" || m.frames[1].title != "sub" {
		t.Errorf("after the listing: %d frames, opening %q", len(m.frames), m.opening)
	}
	// A request answered after the user has gone back up is dropped.
	m.ascend()
	selectNamed("other")
	stale := m.descend()
	m.ascend() // moved on before it finished
	m.opened(stale().(openedMsg))
	if len(m.frames) != 1 {
		t.Errorf("a stale answer was taken in: %d frames", len(m.frames))
	}
}

// Kernels are told by header (AArch64 Image, ARM zImage) or, for the raw ARM Image
// that has none, by its name and the version banner inside it.
func TestReconReportsKernels(t *testing.T) {
	banner := []byte("Linux version 4.14.202-tcc (b@host) (gcc version 4.9.x) #155 SMP PREEMPT Wed Jan 7 17:20:56 KST 2026\n")
	arm64 := make([]byte, 0x40)
	copy(arm64, "MZ")
	copy(arm64[0x38:], "ARM\x64")
	arm64 = append(arm64, banner...)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	img := write("kernel.out", arm64)
	out := stripANSI(runReconJob(reconJob{osPath: img, name: "kernel.out"}))
	if !strings.Contains(out, "Type:  arm64-image") || !strings.Contains(out, "Kernel: Linux 4.14.202-tcc") || !strings.Contains(out, "Form: AArch64 Image") {
		t.Errorf("arm64 image:\n%s", out)
	}
	raw := write("Image", append(bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, 500), banner...))
	if out := stripANSI(runReconJob(reconJob{osPath: raw, name: "Image"})); !strings.Contains(out, "Kernel: Linux 4.14.202-tcc") || !strings.Contains(out, "raw kernel image") {
		t.Errorf("raw image:\n%s", out)
	}
	// The name alone is not enough: without a banner it is not reported as a kernel.
	notKernel := write("vmlinux", bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, 500))
	if out := stripANSI(runReconJob(reconJob{osPath: notKernel, name: "vmlinux"})); strings.Contains(out, "Kernel:") {
		t.Errorf("a file named like a kernel, with no banner:\n%s", out)
	}
	if got := typeLabel("x", arm64[:0x40]); got != "ARM64 Linux kernel" {
		t.Errorf("label %q", got)
	}
	if got := typeLabel("Image", bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, 100)); got != "Linux kernel image" {
		t.Errorf("label %q", got)
	}
}

// Recon of a member in place reads through infile, never the file system: an ELF
// (read by readImage) was reported as "no such file or directory".
func TestReconOfAnELFMemberInPlace(t *testing.T) {
	elf := make([]byte, 64)
	copy(elf, "\x7fELF")
	elf[4], elf[5], elf[6] = 2, 1, 1 // 64-bit, little-endian, version 1
	elf[16] = 2                      // executable
	elf[18] = 0xb7                   // AArch64
	elf[20] = 1
	elf[52], elf[54], elf[56] = 64, 0x38, 0 // header and program-header sizes, no segments
	node := carve.FromBytes("modem/vzw_3apn/appsboot.mbn", elf)
	out := stripANSI(runReconJob(reconJob{name: "appsboot.mbn", node: node}))
	if strings.Contains(out, "no such file") || strings.Contains(out, "[!]") {
		t.Errorf("recon of an ELF member failed:\n%s", out)
	}
	if !strings.Contains(out, "Type:  elf") {
		t.Errorf("not recognised as an ELF:\n%s", out)
	}
}
