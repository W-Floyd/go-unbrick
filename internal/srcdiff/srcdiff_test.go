package srcdiff

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func file(path, content string) File {
	return File{Path: path, Size: int64(len(content)), Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(content)), nil
	}}
}

func sha(t *testing.T, content string) string {
	t.Helper()
	s, err := BlobSHA(strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBlobSHA(t *testing.T) {
	// `printf 'hello\n' | git hash-object --stdin`
	if got := sha(t, "hello\n"); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Errorf("got %s", got)
	}
	if _, err := BlobSHA(strings.NewReader("abc"), 5); err == nil {
		t.Error("short read accepted")
	}
}

func TestCompare(t *testing.T) {
	up := map[string]string{
		"sub/a.c": sha(t, "a\n"), "sub/b.c": sha(t, "b\n"), "sub/c.c": sha(t, "c\n"), "sub/only.c": sha(t, "x\n"),
	}
	local := []File{file("a.c", "a\n"), file("b.c", "B\n"), file("c.c", "c\r\n"), file("new.c", "n\n")}
	eol := func(f File, _ string) bool { return f.Path == "c.c" }
	res, err := Compare(local, up, "sub/", eol)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Identical, []string{"a.c"}) {
		t.Errorf("identical %v", res.Identical)
	}
	if len(res.Modified) != 2 || res.Modified[0].Path != "b.c" || res.Modified[0].EOLOnly || !res.Modified[1].EOLOnly {
		t.Errorf("modified %+v", res.Modified)
	}
	if !reflect.DeepEqual(res.VendorOnly, []string{"new.c"}) || !reflect.DeepEqual(res.UpstreamOnly, []string{"only.c"}) {
		t.Errorf("vendor %v upstream %v", res.VendorOnly, res.UpstreamOnly)
	}
}

func TestAlign(t *testing.T) {
	up := map[string]string{"x/lm/a.cc": "1", "x/util/b.hh": "2", "other/lm/a.cc": "3", "README": "4"}
	if got := Align([]string{"lm/a.cc", "util/b.hh"}, up); got != "x/" {
		t.Errorf("got %q", got)
	}
	if got := Align([]string{"README"}, up); got != "" {
		t.Errorf("root: %q", got)
	}
	if got := Align(nil, up); got != "" {
		t.Errorf("empty: %q", got)
	}
}
