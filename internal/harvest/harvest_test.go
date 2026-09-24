package harvest

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-unbrick/internal/blankflash"
)

func TestRepairMagic(t *testing.T) {
	elf := []byte("\x7fELE\x02\x01\x01\x00")
	if off, b, ok := repairMagic(elf); !ok || off != 3 || b != 'F' {
		t.Fatalf("neutered ELF: %d %q %v", off, b, ok)
	}
	if _, _, ok := repairMagic([]byte("\x7fELE\x09\x01\x01\x00")); ok {
		t.Fatal("repaired an ELF with a nonsense class byte")
	}
	mbn := []byte("\xd1\xdc\x4b\x87\x34\x10\xd7\x73")
	if off, b, ok := repairMagic(mbn); !ok || off != 3 || b != 0x84 {
		t.Fatalf("neutered MBN: %d %x %v", off, b, ok)
	}
	if _, _, ok := repairMagic([]byte("\x7fELF\x02\x01\x01\x00")); ok {
		t.Fatal("repaired an intact ELF")
	}
}

func TestParseRepo(t *testing.T) {
	for _, c := range []struct{ in, str, clone, blob, cache string }{
		{"thantoeaungat/firehose", "thantoeaungat/firehose", "https://github.com/thantoeaungat/firehose.git",
			"https://github.com/thantoeaungat/firehose/blob/HEAD/a.mbn", "thantoeaungat__firehose"},
		{"https://github.com/o/r.git", "o/r", "https://github.com/o/r.git", "https://github.com/o/r/blob/HEAD/a.mbn", "o__r"},
		{"gitlab.com/grp/sub/proj", "gitlab.com/grp/sub/proj", "https://gitlab.com/grp/sub/proj.git",
			"https://gitlab.com/grp/sub/proj/-/blob/HEAD/a.mbn", "gitlab.com__grp__sub__proj"},
		{"https://codeberg.org/u/r/", "codeberg.org/u/r", "https://codeberg.org/u/r.git", "https://codeberg.org/u/r", "codeberg.org__u__r"},
	} {
		r := parseRepo(c.in)
		if r.String() != c.str || r.cloneURL() != c.clone || r.blobURL("a.mbn") != c.blob || r.cacheName() != c.cache {
			t.Errorf("%s: %s %s %s %s", c.in, r.String(), r.cloneURL(), r.blobURL("a.mbn"), r.cacheName())
		}
	}
}

func TestResolveArchiveURL(t *testing.T) {
	for _, c := range []struct{ in, url, stem string }{
		{"https://drive.google.com/file/d/AbC_1-x/view", "https://drive.usercontent.google.com/download?id=AbC_1-x&export=download&confirm=t", "gdrive_AbC_1-x"},
		{"https://www.mediafire.com/file/abc123/x.zip/file", "https://www.mediafire.com/file/abc123/x.zip/file", "mediafire_abc123"},
		{"https://mega.nz/file/XyZ#key", "https://mega.nz/file/XyZ#key", "mega_XyZ"},
		{"https://androidfilehost.com/?fid=1234567890", "https://androidfilehost.com/?fid=1234567890", "afh_1234567890"},
		{"https://cloud.disroot.org/s/HzxB6YM2wRFPpWT/download", "https://cloud.disroot.org/s/HzxB6YM2wRFPpWT/download", "download"},
	} {
		if u, s := resolveArchiveURL(c.in); u != c.url || s != c.stem {
			t.Errorf("%s: got (%s, %s)", c.in, u, s)
		}
	}
}

func TestParseTemblastSpans(t *testing.T) {
	page := `<html><table>
<tr><th>Signer</th><th>SHA256</th><th>SHA384</th><th>MD5</th><th>Type</th><th>Ver</th><th>Site</th><th>Path</th></tr>
<tr><td rowspan="2">Xiaomi</td><td>aa</td><td>bb</td><td>0123456789abcdef</td><td>ELF</td><td>3</td><td>G</td>
<td><a href="https://github.com/o/r/blob/master/dir/a%20b.mbn">a b.mbn</a></td></tr>
<tr><td>cc</td><td>dd</td><td class="bad">fedcba9876543210</td><td colspan="2">MBN</td><td>Z</td><td>x.bin</td></tr>
</table></html>`
	es := parseTemblast(strings.NewReader(page))
	if len(es) != 2 {
		t.Fatalf("rows: %d", len(es))
	}
	if e := es[0]; e.Signer != "Xiaomi" || e.FileMD5 != "0123456789abcdef" || e.Repo != "o/r" || e.RepoPath != "dir/a b.mbn" || e.IsBad {
		t.Fatalf("row 1: %+v", e)
	}
	if e := es[1]; e.Signer != "Xiaomi" || e.SHA256 != "cc" || e.Type != "MBN" || e.Ver != "MBN" || e.Site != "Z" || !e.IsBad {
		t.Fatalf("row 2 (rowspan signer, colspan type): %+v", e)
	}
}

func TestExpandSingleimages(t *testing.T) {
	dir := t.TempDir()
	blob, err := blankflash.Build([]blankflash.Record{
		{Name: "tz.mbn", Data: []byte("boot chain")},
		{Name: "programmer.mbn", Data: []byte("\x7fELF the loader")},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "singleimage.bin")
	if err := os.WriteFile(p, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	if n := expandSingleimages(dir); n != 1 {
		t.Fatalf("carved %d", n)
	}
	got, _ := os.ReadFile(p + ".programmer.elf")
	if string(got) != "\x7fELF the loader" {
		t.Fatalf("sidecar: %q", got)
	}
	if n := expandSingleimages(dir); n != 0 {
		t.Fatalf("not idempotent: carved %d again", n)
	}
}

func TestExtractZipRefusesTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range []string{"ok/loader.mbn", "../evil.mbn", "/abs.mbn"} {
		w, _ := zw.Create(n)
		io.WriteString(w, n)
	}
	zw.Close()
	dir := t.TempDir()
	src := filepath.Join(dir, "a.zip")
	os.WriteFile(src, buf.Bytes(), 0o644)
	out := filepath.Join(dir, "out")
	if err := extractZip(src, out, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "ok", "loader.mbn")); err != nil {
		t.Fatal("safe member missing")
	}
	if _, err := os.Stat(filepath.Join(dir, "evil.mbn")); err == nil {
		t.Fatal("traversal member escaped the target")
	}
}
