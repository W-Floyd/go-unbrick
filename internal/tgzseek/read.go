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
		if d := a.warm(e); d != nil {
			m.d = d
		} else {
			m.d, m.skip = inflate.NewUnknown(a.r, e.run.start), e.rel
		}
	}
	return m
}

// warmBacks are how far before a landing's entry a read of one of its
// members re-enters the stream, nearest first.
var warmBacks = []int64{1 << 20, 4 << 20, 16 << 20}

// warm returns a decoder positioned at e's first byte with its whole window
// known, by entering the stream before e's run: a member found by a landing
// can start before the run's own unknown history has washed out. Nil when
// no entry tried gets there settled.
func (a *Archive) warm(e *Entry) *inflate.Decoder {
	for _, back := range warmBacks {
		from := max(a.start, e.run.start/8-back)
		bit, err := inflate.FindParsed(a.r, from, e.run.start/8, 4, 1<<20)
		if err != nil || bit >= e.run.start {
			continue
		}
		d := inflate.NewUnknown(a.r, bit)
		at := int64(-1) // output at the run's entry, once crossed
		d.OnBoundary = func(b, out int64) {
			if b == e.run.start {
				at = out
			}
		}
		buf := make([]byte, 4<<10)
		var err2 error
		for (at < 0 && d.Bit() < e.run.start || at >= 0 && d.Out() < at+e.rel) && err2 == nil {
			n := int64(len(buf))
			if at >= 0 {
				n = min(n, at+e.rel-d.Out())
			}
			_, err2 = d.Read(buf[:n])
		}
		if err2 == nil && at >= 0 && d.Out() == at+e.rel && d.Settled() {
			return d
		}
		if from == a.start {
			break
		}
	}
	return nil
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
