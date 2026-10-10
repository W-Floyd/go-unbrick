package tgzseek

import (
	"fmt"
	"io"

	"github.com/W-Floyd/go-unbrick/internal/inflate"
)

// cursor reads one run forward. buf holds the decoded output from offset pos
// on; d is nil for the tail run, which is decoded already.
type cursor struct {
	run *run
	d   *inflate.Decoder
	pos int64
	buf []byte
	unk []bool
	eof bool

	cps        []checkpoint
	mbit, mout int64 // decoder position at the last mark, for the ratio since
}

func newCursor(r io.ReaderAt, bit int64, exact bool) *cursor {
	c := &cursor{run: &run{start: bit, exact: exact}, mbit: bit}
	if exact {
		c.d = inflate.NewExact(r, bit, nil)
	} else {
		c.d = inflate.NewUnknown(r, bit)
	}
	c.d.OnBoundary = func(b, out int64) {
		if c.d.Settled() && (len(c.cps) == 0 || out-c.cps[len(c.cps)-1].out >= checkEvery) {
			c.cps = append(c.cps, checkpoint{bit: b, out: out, win: c.d.Window()})
		}
	}
	return c
}

func (c *cursor) end() int64 { return c.pos + int64(len(c.buf)) }

// window returns up to n decoded bytes from offset at, which must not be
// before what the cursor has already given up; fewer only at the stream end.
func (c *cursor) window(at, n int64) ([]byte, []bool, error) {
	if at < c.pos {
		return nil, nil, fmt.Errorf("tgzseek: internal: rewind from %d to %d", c.pos, at)
	}
	if at >= c.end() {
		if err := c.discard(at - c.end()); err != nil {
			return nil, nil, err
		}
		c.buf, c.unk, c.pos = c.buf[:0], c.unk[:0], at
	} else if drop := at - c.pos; drop > 0 {
		c.buf, c.unk, c.pos = c.buf[drop:], c.unk[drop:], at
	}
	for int64(len(c.buf)) < n && !c.eof && c.d != nil {
		chunk := make([]byte, min(n-int64(len(c.buf)), 1<<20))
		mask := make([]bool, len(chunk))
		k, err := c.d.ReadMask(chunk, mask)
		c.buf, c.unk = append(c.buf, chunk[:k]...), append(c.unk, mask[:k]...)
		if err == io.EOF {
			c.eof = true
		} else if err != nil {
			return nil, nil, err
		}
	}
	k := min(n, int64(len(c.buf)))
	return c.buf[:k], c.unk[:k], nil
}

// discard decodes n bytes past the buffer without keeping them.
func (c *cursor) discard(n int64) error {
	if n == 0 {
		return nil
	}
	if c.d == nil || c.eof {
		return io.ErrUnexpectedEOF
	}
	buf := make([]byte, min(n, 1<<20))
	for n > 0 {
		k, err := c.d.Read(buf[:min(n, int64(len(buf)))])
		n -= int64(k)
		c.pos += int64(k)
		if err == io.EOF {
			c.eof = true
			if n > 0 {
				return io.ErrUnexpectedEOF
			}
		} else if err != nil {
			return err
		}
	}
	return nil
}

// bit is the compressed position of offset pos, roughly: the decoder runs
// ahead by what is buffered.
func (c *cursor) bit() int64 {
	if c.d == nil {
		return c.run.start
	}
	return c.d.Bit()
}

func (c *cursor) mark() {
	if c.d != nil {
		c.mbit, c.mout = c.d.Bit(), c.d.Out()
	}
}

// ratio is compressed bytes per output byte since the last mark.
func (c *cursor) ratio() float64 {
	if c.d == nil || c.d.Out() <= c.mout {
		return 1
	}
	return float64(c.d.Bit()-c.mbit) / 8 / float64(c.d.Out()-c.mout)
}

// checkpointAt returns the last checkpoint at or before offset at.
func (c *cursor) checkpointAt(at int64) *checkpoint {
	for i := len(c.cps) - 1; i >= 0; i-- {
		if c.cps[i].out <= at {
			cp := c.cps[i]
			return &cp
		}
	}
	return nil
}
