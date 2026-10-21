package srcdiff

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// Newer Mobis source releases are zips of zips: one member per project, named for it
// ("platform.external.angle_src_opened_code.zip"), whose own contents are the tree. A project
// is then a member of the release, not a directory in it. nestedSuffix is what such a name
// ends in before ".zip".
const nestedSuffix = "_src_opened_code"

// nestedProjects are the members of a release that look like one project each, by the name
// that stands for the project (the member's, without its ending). A member holding a project's
// dependencies is not one.
func nestedProjects(entries []srcfile.Entry) map[string]srcfile.Entry {
	out := map[string]srcfile.Entry{}
	for _, e := range entries {
		if strings.Contains(e.Name, "/") || !strings.HasSuffix(strings.ToLower(e.Name), ".zip") {
			continue
		}
		base := e.Name[:len(e.Name)-len(".zip")]
		if strings.HasSuffix(base, "_Dependency") {
			continue
		}
		out[strings.TrimSuffix(base, nestedSuffix)] = e
	}
	return out
}

// innerZip is a zip held in a member of the release, copied out to read.
type innerZip struct {
	dir     string
	closer  io.Closer
	entries []srcfile.Entry
	byName  map[string]srcfile.Entry
}

// maxInner bounds a member copied out to read; the biggest seen is well under it.
const maxInner = 2 << 30

// openInner copies the member to a temporary file and lists it.
func openInner(e srcfile.Entry) (*innerZip, error) {
	if e.Size > maxInner {
		return nil, errors.New("too large to open")
	}
	dir, err := os.MkdirTemp("", "srcdiff-inner-")
	if err != nil {
		return nil, err
	}
	z := &innerZip{dir: dir}
	fail := func(err error) (*innerZip, error) {
		z.close()
		return nil, err
	}
	rc, err := e.Open()
	if err != nil {
		return fail(err)
	}
	path := filepath.Join(dir, "member")
	f, err := os.Create(path)
	if err != nil {
		rc.Close()
		return fail(err)
	}
	_, err = io.Copy(f, rc)
	rc.Close()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail(err)
	}
	entries, closer, err := srcfile.Entries(path)
	if err != nil {
		return fail(err)
	}
	if closer == nil {
		return fail(errors.New("not an archive"))
	}
	z.entries, z.closer = entries, closer
	z.byName = make(map[string]srcfile.Entry, len(entries))
	for _, x := range entries {
		z.byName[x.Name] = x
	}
	return z, nil
}

func (z *innerZip) close() {
	if z.closer != nil {
		z.closer.Close()
	}
	os.RemoveAll(z.dir)
}

// wrapper is the one directory everything in the zip is under, "" if it has none (or
// several): a project zip often holds its tree in a folder of its own.
func (z *innerZip) wrapper() string {
	top := ""
	for _, e := range z.entries {
		first, _, ok := strings.Cut(e.Name, "/")
		if !ok {
			return "" // a file at the top
		}
		if top == "" {
			top = first
		} else if first != top {
			return ""
		}
	}
	return top
}

// read is a file's content (nil if it is not there or large), found with or without the wrapper.
func (z *innerZip) read(name string) []byte {
	for _, n := range []string{name, z.wrapper() + "/" + name} {
		if e, ok := z.byName[n]; ok && e.Size <= 1<<20 {
			rc, err := e.Open()
			if err != nil {
				return nil
			}
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			return b
		}
	}
	return nil
}
