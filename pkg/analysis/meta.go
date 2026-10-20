package analysis

import (
	"archive/tar"
	"archive/zip"
	"fmt"
	"io"
	"sort"
	"strings"
)

// What an archive records about each member besides its contents: a tar's
// header (times, owners, modes), a zip's entry (time, method, attributes). Two
// archives of the same files differ in these when they were packed at different
// times or by different users, though every member is the same.

// MetaEntry is one member's recorded details, as named fields.
type MetaEntry struct {
	Name   string
	Fields map[string]string
}

// MaxMembers bounds how many members' details are read from one archive.
const MaxMembers = 200000

const timeLayout = "2006-01-02 15:04:05"

// TarMeta reads the header of every member of a tar. It seeks from header to
// header, so the cost is a read per member, not the archive.
func TarMeta(r io.ReaderAt, size int64) ([]MetaEntry, error) {
	tr := tar.NewReader(io.NewSectionReader(r, 0, size))
	var out []MetaEntry
	for len(out) < MaxMembers {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		f := map[string]string{
			"mtime": h.ModTime.UTC().Format(timeLayout),
			"mode":  fmt.Sprintf("%04o", h.Mode&0o7777),
			"uid":   fmt.Sprint(h.Uid),
			"gid":   fmt.Sprint(h.Gid),
			"type":  string(rune(h.Typeflag)),
			"size":  fmt.Sprint(h.Size),
		}
		if h.Uname != "" || h.Gname != "" {
			f["owner"] = h.Uname + ":" + h.Gname
		}
		if h.Linkname != "" {
			f["link"] = h.Linkname
		}
		if !h.AccessTime.IsZero() {
			f["atime"] = h.AccessTime.UTC().Format(timeLayout)
		}
		if !h.ChangeTime.IsZero() {
			f["ctime"] = h.ChangeTime.UTC().Format(timeLayout)
		}
		out = append(out, MetaEntry{Name: h.Name, Fields: f})
	}
	return out, nil
}

// ZipMeta reads every entry of a zip's directory.
func ZipMeta(r io.ReaderAt, size int64) ([]MetaEntry, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	var out []MetaEntry
	for _, f := range zr.File {
		if len(out) >= MaxMembers {
			break
		}
		fields := map[string]string{
			"mtime":  f.Modified.UTC().Format(timeLayout),
			"method": fmt.Sprint(f.Method),
			"mode":   fmt.Sprintf("%04o", f.Mode().Perm()),
			"size":   fmt.Sprint(f.UncompressedSize64),
		}
		if f.Comment != "" {
			fields["comment"] = f.Comment
		}
		out = append(out, MetaEntry{Name: f.Name, Fields: fields})
	}
	return out, nil
}

// MetaDiff is one recorded detail of one member that differs.
type MetaDiff struct {
	Name  string `json:"name"`
	Field string `json:"field"`
	A     string `json:"a"`
	B     string `json:"b"`
}

// MetaReport is how the recorded details of two archives compare.
type MetaReport struct {
	Members int            `json:"members"` // members present in both
	Diffs   []MetaDiff     `json:"diffs"`   // details that differ, in member order
	ByField map[string]int `json:"byField"` // members whose detail differs, by detail
	OnlyA   []string       `json:"onlyA"`   // members one archive records and the other does not
	OnlyB   []string       `json:"onlyB"`
}

// Identical says every member is in both and every detail the same.
func (r MetaReport) Identical() bool {
	return len(r.Diffs) == 0 && len(r.OnlyA) == 0 && len(r.OnlyB) == 0
}

// CompareMeta pairs members by name (a name that repeats is paired in order)
// and lists what differs.
func CompareMeta(a, b []MetaEntry) MetaReport {
	// Slices start empty, not nil: they are JSON arrays a page asks the length of.
	r := MetaReport{ByField: map[string]int{}, Diffs: []MetaDiff{}, OnlyA: []string{}, OnlyB: []string{}}
	byName := map[string][]MetaEntry{}
	for _, e := range b {
		byName[e.Name] = append(byName[e.Name], e)
	}
	for _, x := range a {
		q := byName[x.Name]
		if len(q) == 0 {
			r.OnlyA = append(r.OnlyA, x.Name)
			continue
		}
		y := q[0]
		byName[x.Name] = q[1:]
		r.Members++
		var fields []string
		seen := map[string]bool{}
		for f := range x.Fields {
			fields = append(fields, f)
			seen[f] = true
		}
		for f := range y.Fields {
			if !seen[f] {
				fields = append(fields, f)
			}
		}
		sort.Strings(fields)
		for _, f := range fields {
			if x.Fields[f] != y.Fields[f] {
				r.Diffs = append(r.Diffs, MetaDiff{x.Name, f, x.Fields[f], y.Fields[f]})
				r.ByField[f]++
			}
		}
	}
	for _, e := range b {
		if q := byName[e.Name]; len(q) > 0 {
			r.OnlyB = append(r.OnlyB, e.Name)
			byName[e.Name] = q[1:]
		}
	}
	return r
}

// Summary says in a line which details differ and how widely: "mtime of 47 of
// 52 members; uid of 2".
func (r MetaReport) Summary() string {
	var fields []string
	for f := range r.ByField {
		fields = append(fields, f)
	}
	sort.Slice(fields, func(i, j int) bool {
		if r.ByField[fields[i]] != r.ByField[fields[j]] {
			return r.ByField[fields[i]] > r.ByField[fields[j]]
		}
		return fields[i] < fields[j]
	})
	var parts []string
	for _, f := range fields {
		parts = append(parts, fmt.Sprintf("%s of %d of %d members", f, r.ByField[f], r.Members))
	}
	return strings.Join(parts, "; ")
}
