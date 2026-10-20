package analysis

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"
)

type member struct {
	name, body string
	mtime      time.Time
	uid        int
	mode       int64
}

func mkTar(t *testing.T, ms ...member) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, m := range ms {
		mode := m.mode
		if mode == 0 {
			mode = 0o644
		}
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: mode, Uid: m.uid, Size: int64(len(m.body)), ModTime: m.mtime}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(m.body))
	}
	tw.Close()
	return b.Bytes()
}

var (
	t1 = time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	t2 = time.Date(2027, 1, 15, 8, 0, 0, 0, time.UTC)
)

func TestTarMetaReadsHeaders(t *testing.T) {
	data := mkTar(t, member{"a.bin", "alpha", t1, 1000, 0o755}, member{"d/b.bin", "bravo", t2, 0, 0})
	es, err := TarMeta(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(es) != 2 {
		t.Fatalf("%d entries, %v", len(es), err)
	}
	a := es[0]
	if a.Name != "a.bin" || a.Fields["mtime"] != "2023-11-14 22:13:20" || a.Fields["mode"] != "0755" || a.Fields["uid"] != "1000" || a.Fields["size"] != "5" {
		t.Errorf("a.bin: %+v", a)
	}
	if es[1].Fields["mtime"] != "2027-01-15 08:00:00" || es[1].Fields["uid"] != "0" {
		t.Errorf("d/b.bin: %+v", es[1])
	}
}

// The same members packed at different times: the tars differ, and what differs
// is the times, in every header.
func TestSameMembersDifferentTimesIsAllTimes(t *testing.T) {
	var as, bs []member
	for _, n := range []string{"a", "b", "c", "d"} {
		as = append(as, member{n, "body " + n, t1, 0, 0})
		bs = append(bs, member{n, "body " + n, t2, 0, 0})
	}
	x, y := mkTar(t, as...), mkTar(t, bs...)
	if bytes.Equal(x, y) {
		t.Fatal("the test tars are the same bytes")
	}
	ea, _ := TarMeta(bytes.NewReader(x), int64(len(x)))
	eb, _ := TarMeta(bytes.NewReader(y), int64(len(y)))
	r := CompareMeta(ea, eb)
	if r.Identical() || r.Members != 4 || len(r.OnlyA)+len(r.OnlyB) != 0 {
		t.Fatalf("%+v", r)
	}
	if len(r.ByField) != 1 || r.ByField["mtime"] != 4 {
		t.Errorf("only the times differ, in every member: %v", r.ByField)
	}
	if d := r.Diffs[0]; d.Name != "a" || d.Field != "mtime" || d.A != "2023-11-14 22:13:20" || d.B != "2027-01-15 08:00:00" {
		t.Errorf("first difference: %+v", d)
	}
	if got := r.Summary(); got != "mtime of 4 of 4 members" {
		t.Errorf("summary %q", got)
	}
}

func TestCompareMetaOwnersModesAndMembersOnOneSide(t *testing.T) {
	a := mkTar(t, member{"keep", "k", t1, 0, 0}, member{"owner", "o", t1, 1000, 0}, member{"mode", "m", t1, 0, 0o644}, member{"gone", "g", t1, 0, 0})
	b := mkTar(t, member{"keep", "k", t1, 0, 0}, member{"owner", "o", t1, 0, 0}, member{"mode", "m", t1, 0, 0o755}, member{"new", "n", t1, 0, 0})
	ea, _ := TarMeta(bytes.NewReader(a), int64(len(a)))
	eb, _ := TarMeta(bytes.NewReader(b), int64(len(b)))
	r := CompareMeta(ea, eb)
	if r.Members != 3 || strings.Join(r.OnlyA, ",") != "gone" || strings.Join(r.OnlyB, ",") != "new" {
		t.Errorf("members %d, only in a %v, only in b %v", r.Members, r.OnlyA, r.OnlyB)
	}
	got := map[string]string{}
	for _, d := range r.Diffs {
		got[d.Name+"/"+d.Field] = d.A + ">" + d.B
	}
	if got["owner/uid"] != "1000>0" || got["mode/mode"] != "0644>0755" || len(got) != 2 {
		t.Errorf("differences: %v", got)
	}
	// The same archive twice is identical.
	if r := CompareMeta(ea, ea); !r.Identical() || r.Members != 4 {
		t.Errorf("an archive against itself: %+v", r)
	}
	// A name that repeats is paired in order.
	dup := []MetaEntry{{"x", map[string]string{"mtime": "1"}}, {"x", map[string]string{"mtime": "2"}}}
	dup2 := []MetaEntry{{"x", map[string]string{"mtime": "1"}}, {"x", map[string]string{"mtime": "3"}}}
	if r := CompareMeta(dup, dup2); len(r.Diffs) != 1 || r.Diffs[0].A != "2" || r.Diffs[0].B != "3" {
		t.Errorf("repeated names: %+v", r.Diffs)
	}
}

func mkZip(t *testing.T, mtime time.Time, names ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, n := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: mtime})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("body of " + n))
	}
	zw.Close()
	return b.Bytes()
}

func TestZipMetaTimes(t *testing.T) {
	x, y := mkZip(t, t1, "a", "b"), mkZip(t, t2, "a", "b")
	ea, err := ZipMeta(bytes.NewReader(x), int64(len(x)))
	if err != nil || len(ea) != 2 {
		t.Fatalf("%d entries, %v", len(ea), err)
	}
	eb, _ := ZipMeta(bytes.NewReader(y), int64(len(y)))
	r := CompareMeta(ea, eb)
	if r.ByField["mtime"] != 2 || len(r.ByField) != 1 {
		t.Errorf("%v", r.ByField)
	}
	if _, err := ZipMeta(bytes.NewReader([]byte("not a zip")), 9); err == nil {
		t.Error("a non-zip was read")
	}
}
