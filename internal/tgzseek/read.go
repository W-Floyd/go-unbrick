package tgzseek

import (
	"bytes"
	"errors"
	"io"

	"github.com/W-Floyd/go-unbrick/internal/inflate"
)

var errUnknown = errors.New("tgzseek: member bytes depend on stream history this read does not have")

// Open returns entry i's bytes: from memory when the listing kept them, else
// decoded again from the nearest exact checkpoint before the member, or from
// where its run entered the stream.
func (a *Archive) Open(i int) io.Reader {
	e := &a.Entries[i]
	if e.data != nil || e.Size == 0 {
		return bytes.NewReader(e.data)
	}
	m := &member{left: e.Size}
	switch {
	case e.cp != nil:
		m.d, m.skip = inflate.NewExact(a.r, e.cp.bit, e.cp.win), e.rel-e.cp.out
	case e.run.exact:
		m.d, m.skip = inflate.NewExact(a.r, e.run.start, nil), e.rel
	default:
		m.d, m.skip = inflate.NewUnknown(a.r, e.run.start), e.rel
	}
	return m
}

type member struct {
	d    *inflate.Decoder
	skip int64
	left int64
	unk  []bool
}

func (m *member) Read(p []byte) (int, error) {
	if m.left == 0 {
		return 0, io.EOF
	}
	if m.skip > 0 {
		buf := make([]byte, min(m.skip, 1<<20))
		for m.skip > 0 {
			k, err := m.d.Read(buf[:min(m.skip, int64(len(buf)))])
			m.skip -= int64(k)
			if err != nil && m.skip > 0 {
				return 0, unexpected(err)
			}
		}
	}
	p = p[:min(int64(len(p)), m.left)]
	if len(m.unk) < len(p) {
		m.unk = make([]bool, len(p))
	}
	n, err := m.d.ReadMask(p, m.unk)
	if anyUnknown(m.unk[:n]) {
		return 0, errUnknown
	}
	m.left -= int64(n)
	if err != nil && m.left > 0 {
		return n, unexpected(err)
	}
	return n, nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
