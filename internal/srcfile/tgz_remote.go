package srcfile

import (
	"io"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/tgzseek"
)

// A remote .tgz is entered where its members are rather than read from the
// start (see tgzseek). Opening one is a search, so it is done once per
// process.
var remoteTGZ = struct {
	sync.Mutex
	m map[string]*tgzseek.Archive
}{m: map[string]*tgzseek.Archive{}}

func openRemoteTGZ(path string) (*archive, error) {
	remoteTGZ.Lock()
	defer remoteTGZ.Unlock()
	ta, ok := remoteTGZ.m[path]
	if !ok {
		f, err := infile.Open(path)
		if err != nil {
			return nil, err
		}
		if ta, err = tgzseek.Open(f, f.Size()); err != nil {
			return nil, err
		}
		remoteTGZ.m[path] = ta
	}
	a := &archive{close: func() error { return nil }}
	if !ta.Complete {
		a.partial = ta.String()
	}
	for i, e := range ta.Entries {
		if isAppleDouble(e.Name) {
			continue
		}
		a.entries = append(a.entries, entry{name: e.Name, size: uint64(e.Size), head: e.Head,
			open: func() (io.ReadCloser, error) { return io.NopCloser(ta.Open(i)), nil }})
	}
	return a, nil
}
