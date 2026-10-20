package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/hashcache"
)

func writeTar(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for n, c := range files {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c))})
		tw.Write([]byte(c))
	}
	tw.Close()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiffContainers(t *testing.T) {
	a := writeTar(t, "a.tar", map[string]string{
		"same.txt": "same", "size.txt": "short", "bytes.txt": "abcd", "gone.txt": "x", "d.joined": "1",
	})
	b := writeTar(t, "b.tar", map[string]string{
		"same.txt": "same", "size.txt": "longer", "bytes.txt": "abce", "new.txt": "y", "d.joined": "2",
	})
	var ok bool
	out, err := captureStdout(func() error {
		var err error
		ok, err = diffContainers(a, b, 3, false)
		return err
	})
	if !ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	for _, want := range []string{"~ size.txt", "~ bytes.txt", "- gone.txt", "+ new.txt", "2 changed, 1 added, 1 removed, 1 unchanged"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "same.txt") || strings.Contains(out, ".joined") {
		t.Errorf("listed an unchanged or derived member:\n%s", out)
	}
}

func TestDiffContainersFallsBackForNonContainers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.bin")
	os.WriteFile(p, []byte("plain bytes, not a container"), 0o644)
	if ok, _ := diffContainers(p, p, 3, false); ok {
		t.Error("treated a plain file as a container")
	}
}

func TestDiffContainersRenames(t *testing.T) {
	a := writeTar(t, "a.tar", map[string]string{"old.bin": "payload-1", "keep.txt": "k", "x.txt": "gone"})
	b := writeTar(t, "b.tar", map[string]string{"new.bin": "payload-1", "keep.txt": "k", "y.txt": "fresh"})
	out, err := captureStdout(func() error { _, err := diffContainers(a, b, 3, false); return err })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"> old.bin -> new.bin", "- x.txt", "+ y.txt", "1 added, 1 removed, 1 renamed, 1 unchanged"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "+ new.bin") || strings.Contains(out, "- old.bin") {
		t.Errorf("rename also listed as add/remove:\n%s", out)
	}
}

func TestDiffDirectoriesMoves(t *testing.T) {
	write := func(root string, files map[string]string) string {
		for n, c := range files {
			p := filepath.Join(root, n)
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte(c), 0o644)
		}
		return root
	}
	a := write(t.TempDir(), map[string]string{"d1/m.img": "image-bytes", "same": "s", "edit": "1", "d1/only": "o"})
	b := write(t.TempDir(), map[string]string{"d2/n.img": "image-bytes", "same": "s", "edit": "22"})
	out, err := captureStdout(func() error { _, err := diffContainers(a, b, 3, false); return err })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"> d1/m.img -> d2/n.img", "- d1/only", "~ edit", "1 changed, 0 added, 1 removed, 1 renamed, 1 unchanged"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDiffTrustsManifests(t *testing.T) {
	ver := func(rows ...string) string {
		return "+|1|BUILD|kia|COLL|2|0\n" + strings.Join(rows, "\n") + "\n"
	}
	write := func(files map[string]string) string {
		root := t.TempDir()
		for n, c := range files {
			os.WriteFile(filepath.Join(root, n), []byte(c), 0o644)
		}
		return root
	}
	// Same claimed CRC and size, different bytes: only a read could tell.
	a := write(map[string]string{
		"x.ver":    ver("COLL|same.bin|1|111|4|0", "COLL|edit.bin|1|222|4|0", "COLL|old.bin|1|333|4|0"),
		"same.bin": "aaaa", "edit.bin": "bbbb", "old.bin": "cccc",
	})
	b := write(map[string]string{
		"x.ver":    ver("COLL|same.bin|1|111|4|0", "COLL|edit.bin|1|999|4|0", "COLL|new.bin|1|333|4|0"),
		"same.bin": "zzzz", "edit.bin": "bbbb", "new.bin": "yyyy",
	})
	run := func(trust bool) string {
		diffTrust = trust
		defer func() { diffTrust = true }()
		out, err := captureStdout(func() error { _, err := diffContainers(a, b, 3, false); return err })
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := run(true)
	for _, want := range []string{"~ edit.bin", "> old.bin -> new.bin", "compared by stated hash"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "~ same.bin") {
		t.Errorf("manifest says same.bin is unchanged:\n%s", out)
	}
	out = run(false)
	if !strings.Contains(out, "~ same.bin") || strings.Contains(out, "> old.bin") {
		t.Errorf("--verify should read the bytes:\n%s", out)
	}
}

func TestDigestCachedAcrossRuns(t *testing.T) {
	hashcache.Reset()
	p := writeTar(t, "a.tar", map[string]string{"m.bin": "hello"})
	root, err := carveRoot(p)
	if err != nil {
		t.Fatal(err)
	}
	_, kids, _ := root.Children()
	if kids[0].ID() == "" || !strings.Contains(kids[0].ID(), "m.bin") {
		t.Fatalf("member id %q", kids[0].ID())
	}
	want, err := digest(kids[0])
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := hashcache.Get(cacheKey(kids[0], "sha256"), kids[0].Size, false); !ok || got != want {
		t.Fatalf("not cached: %q %v", got, ok)
	}
	// A later run finds it without reading: poison the stored value.
	hashcache.Put(cacheKey(kids[0], "sha256"), kids[0].Size, "cached", false)
	if got, _ := digest(kids[0]); got != "cached" {
		t.Fatalf("digest read the member instead of the cache: %q", got)
	}
}

func TestDiffOneSidedManifest(t *testing.T) {
	crc := func(s string) string { return fmt.Sprintf("%d", int32(crc32.ChecksumIEEE([]byte(s)))) }
	write := func(files map[string]string) string {
		root := t.TempDir()
		for n, c := range files {
			os.WriteFile(filepath.Join(root, n), []byte(c), 0o644)
		}
		return root
	}
	// Only a has a .ver; b's files are hashed with its CRC32 to compare.
	a := write(map[string]string{
		"x.ver":    "+|1|B|kia|C|2|0\nC|same.bin|1|" + crc("aaaa") + "|4|0\nC|diff.bin|1|" + crc("bbbb") + "|4|0\nC|x.ver.keep|1|0|0|0\n",
		"same.bin": "aaaa", "diff.bin": "bbbb",
	})
	b := write(map[string]string{"same.bin": "aaaa", "diff.bin": "bbbc"})
	out, err := captureStdout(func() error { _, err := diffContainers(a, b, 3, false); return err })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "~ diff.bin") || strings.Contains(out, "same.bin") {
		t.Errorf("wrong verdicts:\n%s", out)
	}
	if !strings.Contains(out, "compared by stated hash") {
		t.Errorf("manifest not used:\n%s", out)
	}
}

func TestDiffSimilarContainerDescends(t *testing.T) {
	root := func(name string, files map[string]string) string {
		d := t.TempDir()
		p := writeTar(t, name, files)
		bs, _ := os.ReadFile(p)
		os.WriteFile(filepath.Join(d, name), bs, 0o644)
		return d
	}
	ra := root("pkg_V1.tar", map[string]string{"boot.img": "boot-bytes", "modem.bin": "modem-v1", "same.txt": "s"})
	rb := root("pkg_V2.tar", map[string]string{"boot.img": "boot-bytes", "modem.bin": "modem-v2!", "same.txt": "s"})
	out, err := captureStdout(func() error { _, err := diffContainers(ra, rb, 3, false); return err })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"≈ pkg_V1.tar -> pkg_V2.tar", "~ modem.bin", "1 renamed and changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "- pkg_V1.tar") || strings.Contains(out, "+ pkg_V2.tar") {
		t.Errorf("similar pair also listed as add/remove:\n%s", out)
	}
}

func TestDiffSimilarPlainFile(t *testing.T) {
	body := make([]byte, 256<<10)
	for i := range body {
		body[i] = byte(i * 31 >> 3)
	}
	edited := append([]byte(nil), body...)
	for i := 100000; i < 100100; i++ { // one small edit; most sampled blocks match
		edited[i] ^= 0xff
	}
	other := make([]byte, len(body)) // unrelated, same size and type
	write := func(name string, b []byte) string {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, name), b, 0o644)
		return d
	}
	ra, rb := write("system_a.img", body), write("renamed_thing.img", edited)
	out, _ := captureStdout(func() error { _, err := diffContainers(ra, rb, 3, false); return err })
	if !strings.Contains(out, "≈ system_a.img -> renamed_thing.img") {
		t.Errorf("similar file not paired:\n%s", out)
	}
	rc := write("renamed_thing.img", other)
	out, _ = captureStdout(func() error { _, err := diffContainers(ra, rc, 3, false); return err })
	if strings.Contains(out, "≈") {
		t.Errorf("unrelated file paired:\n%s", out)
	}
}

func TestDiffContainersCompareInside(t *testing.T) {
	root := func(name string, files map[string]string) string {
		d := t.TempDir()
		bs, _ := os.ReadFile(writeTar(t, name, files))
		os.WriteFile(filepath.Join(d, name), bs, 0o644)
		return d
	}
	members := map[string]string{"a.bin": "alpha", "b.bin": "beta"}
	// Same name, same members: unchanged, however the tar happens to be laid out.
	ra, rb := root("pkg.tar", members), root("pkg.tar", members)
	out, _ := captureStdout(func() error { _, err := diffContainers(ra, rb, 3, false); return err })
	if !strings.Contains(out, "0 changed, 0 added, 0 removed, 1 unchanged") {
		t.Errorf("identical tars:\n%s", out)
	}
	// Renamed, nothing different inside: a plain rename, not "renamed and changed".
	rc := root("pkg_copy.tar", members)
	out, _ = captureStdout(func() error { _, err := diffContainers(ra, rc, 3, false); return err })
	if !strings.Contains(out, "> pkg.tar -> pkg_copy.tar") || strings.Contains(out, "renamed and changed") {
		t.Errorf("renamed tar:\n%s", out)
	}
	// Same name, one member differs: changed, with the member under it.
	rd := root("pkg.tar", map[string]string{"a.bin": "alpha", "b.bin": "BETA!"})
	out, _ = captureStdout(func() error { _, err := diffContainers(ra, rd, 3, false); return err })
	if !strings.Contains(out, "~ pkg.tar") || !strings.Contains(out, "~ pkg.tar/b.bin") {
		t.Errorf("changed member not shown:\n%s", out)
	}
}

func TestSameBytesReadsAsLittleAsItCan(t *testing.T) {
	const size = 8 << 20
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i * 13 >> 5)
	}
	node := func(b []byte) *carve.Node {
		p := filepath.Join(t.TempDir(), "f.bin")
		os.WriteFile(p, b, 0o644)
		n, err := carve.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	flip := func(at int) []byte {
		c := append([]byte(nil), body...)
		c[at] ^= 0xff
		return c
	}
	read := func(a, b *carve.Node) (bool, int64) {
		hashcache.Reset()
		dprog.bytes = 0
		same, err := sameBytes(a, b)
		if err != nil {
			t.Fatal(err)
		}
		return same, dprog.bytes
	}

	if same, n := read(node(body), node(flip(10))); same || n != 0 {
		t.Errorf("differs at start: same=%v read=%d, want a probe only", same, n)
	}
	if same, n := read(node(body), node(flip(size-1))); same || n != 0 {
		t.Errorf("differs at end: same=%v read=%d, want a probe only", same, n)
	}
	if same, n := read(node(body), node(flip(size/2))); same || n >= 2*size {
		t.Errorf("differs mid-file: same=%v read=%d of %d each, want it to stop early", same, n, 2*size)
	}
	if same, n := read(node(body[:size-1]), node(body)); same || n != 0 {
		t.Errorf("different sizes: same=%v read=%d", same, n)
	}
	a, b := node(body), node(body)
	if same, n := read(a, b); !same || n != 2*size {
		t.Errorf("equal: same=%v read=%d", same, n)
	}
	// Equal files were read once; their digests now answer without reading.
	dprog.bytes = 0
	if same, _ := sameBytes(a, b); !same || dprog.bytes != 0 {
		t.Errorf("second compare read %d bytes", dprog.bytes)
	}
}

func writeZip(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range files {
		w, _ := zw.Create(n) // deflated
		w.Write([]byte(c))
	}
	zw.Close()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, name), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

// A zip states each member's CRC32 in its directory, so members compare
// without being inflated: the bytes read are the directory's, not the members'.
func TestDiffZipMemberCRC(t *testing.T) {
	big := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB, deflates well
	ra := writeZip(t, "a.zip", map[string]string{"same.bin": big, "edit.bin": big, "small.txt": "x"})
	rb := writeZip(t, "a.zip", map[string]string{"same.bin": big, "edit.bin": big[:len(big)-1] + "!", "small.txt": "x"})
	dprog.bytes = 0
	out, err := captureStdout(func() error { _, err := diffContainers(ra, rb, 3, false); return err })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "~ a.zip/edit.bin") || strings.Contains(out, "same.bin") {
		t.Errorf("wrong verdicts:\n%s", out)
	}
	if dprog.bytes != 0 {
		t.Errorf("read %d bytes of members; the zip directory's CRC32s should settle them", dprog.bytes)
	}
	if !strings.Contains(out, "compared by stated hash") {
		t.Errorf("no stated hashes used:\n%s", out)
	}
	// --verify ignores the directory's word and reads.
	diffTrust = false
	defer func() { diffTrust = true }()
	hashcache.Reset()
	dprog.bytes = 0
	captureStdout(func() error { _, err := diffContainers(ra, rb, 3, false); return err })
	if dprog.bytes == 0 {
		t.Error("--verify read nothing")
	}
}

// A manifest inside a container covers that container's members: the nested
// comparison reads it, so members it names are settled without being opened.
func TestDiffNestedManifest(t *testing.T) {
	ver := "+|1|B|kia|C|1|0\nC|big.bin|1|777|8|0\n"
	root := func(content string) string {
		d := t.TempDir()
		bs, _ := os.ReadFile(writeTar(t, "pkg.tar", map[string]string{"x.ver": ver, "big.bin": content}))
		os.WriteFile(filepath.Join(d, "pkg.tar"), bs, 0o644)
		return d
	}
	// Same claimed CRC and size, different bytes, inside the tar.
	ra, rb := root("aaaaaaaa"), root("bbbbbbbb")
	run := func(trust bool) (string, int64) {
		diffTrust = trust
		defer func() { diffTrust = true }()
		hashcache.Reset()
		dprog.bytes = 0
		out, _ := captureStdout(func() error { _, err := diffContainers(ra, rb, 3, false); return err })
		return out, dprog.bytes
	}
	out, read := run(true)
	// Only the manifest itself is read, on both sides; big.bin never is.
	if strings.Contains(out, "big.bin") || read != 2*int64(len(ver)) {
		t.Errorf("manifest inside the tar ignored (read %d):\n%s", read, out)
	}
	out, _ = run(false)
	if !strings.Contains(out, "~ pkg.tar/big.bin") {
		t.Errorf("--verify should find the difference:\n%s", out)
	}
}

// Stated hashes that differ settle that a container's bytes differ; its
// members are still compared, and when they all match the report says so.
func TestDiffClaimedDifferentButMembersIdentical(t *testing.T) {
	tarPath := writeTar(t, "pkg.tar", map[string]string{"a.bin": "alpha"})
	bs, _ := os.ReadFile(tarPath)
	root := func(crc int) string {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "pkg.tar"), bs, 0o644)
		ver := fmt.Sprintf("+|1|B|kia|C|1|0\nC|pkg.tar|1|%d|%d|0\n", crc, len(bs))
		os.WriteFile(filepath.Join(d, "x.ver"), []byte(ver), 0o644)
		return d
	}
	ra, rb := root(111), root(222)
	out, _ := captureStdout(func() error { _, err := diffContainers(ra, rb, 3, false); return err })
	if !strings.Contains(out, "~ pkg.tar") || !strings.Contains(out, "members identical; container bytes differ") {
		t.Errorf("unexplained change:\n%s", out)
	}
}

// A file named by two manifests in different algorithms (a .ver's CRC32 and an
// update.info's SHA-224) is settled on whichever both sides share, every time,
// not on whichever manifest happened to be read last.
func TestDiffManifestsInTwoAlgorithms(t *testing.T) {
	tarPath := writeTar(t, "pkg.tar", map[string]string{"a.bin": "alpha"})
	bs, _ := os.ReadFile(tarPath)
	sha := strings.Repeat("ab", 28)
	root := func() string {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "pkg.tar"), bs, 0o644)
		ver := fmt.Sprintf("+|1|B|kia|C|1|0\nC|pkg.tar|1|555|%d|0\n", len(bs))
		os.WriteFile(filepath.Join(d, "c.ver"), []byte(ver), 0o644)
		os.WriteFile(filepath.Join(d, "update.info"), []byte("./\n: pkg.tar:"+sha+"\n"), 0o644)
		return d
	}
	opened := 0
	carve.OnExpand = func(kind, name string, _ time.Duration) {
		if name == "pkg.tar" {
			opened++
		}
	}
	t.Cleanup(func() { carve.OnExpand = nil })
	for i := 0; i < 25; i++ { // map order differs run to run
		out, _ := captureStdout(func() error { _, err := diffContainers(root(), root(), 3, false); return err })
		if !strings.Contains(out, "0 changed, 0 added, 0 removed, 3 unchanged") {
			t.Fatalf("run %d:\n%s", i, out)
		}
	}
	if opened != 0 {
		t.Errorf("opened pkg.tar %d times; its stated hashes agree on both sides", opened)
	}
}
