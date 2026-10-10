package tgzseek

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/W-Floyd/go-unbrick/internal/inflate"
)

type opener struct {
	r      *meter
	raw    io.ReaderAt
	start  int64 // offset of the deflate stream
	end    int64 // offset just past it
	isize  uint32
	total  int64 // the decoded length when known exactly (a zip's); else 0
	noTail bool  // no anchored tail: tail.first is only a bound
	budget int64

	head     []item
	headDone bool  // the head reached the end of the archive
	h1       int64 // tar offset of the header after the head
	own      *owner

	tail struct {
		bit   int64
		items []item
		first uint32 // tar offset of its first chained header, mod 2^32
	}

	middle   []item
	seen     map[string]bool
	explored []span // compressed byte ranges landings have decoded
	queue    []landing
	sweeps   int   // targets queued so far, naming each sweep
	sweep    int   // the sweep the current landing is from; 0 for none
	lo, hi   int64 // where landings search
	floor    int64 // the most lo can widen to

	back       int64 // earliest landing stepped back from the tail
	backMisses int   // consecutive steps back that found nothing
	stepping   bool  // the current landing is a step back
}

// backTries is how many steps back in a row may find nothing before a large
// member is assumed and stepping stops.
const backTries = 3

// parsedBlocks is how many whole blocks a landing's entry must parse through
// when no stored blocks confirm it.
const parsedBlocks = 4

type span struct{ from, to int64 }

// stop is where a walk left a member too costly to decode through.
type stop struct {
	bit   int64   // compressed position reached
	left  int64   // output bytes from there to the next header
	ratio float64 // the member's compressed bytes per output byte so far
}

func (o *opener) open(startBit int64) error {
	o.seen = map[string]bool{}
	c := newCursor(o.r, startBit, true)
	items, st, _, eoa, err := o.walk(c, 0)
	if err != nil {
		return err
	}
	logf("head: %d entries", len(items))
	o.head = items
	for _, it := range items {
		o.h1 += it.span
		o.note(it)
		if it.reg && o.own == nil {
			own := it.own
			o.own = &own
		}
	}
	if eoa {
		o.headDone = true
		return nil
	}
	if err := o.anchorTail(); err != nil {
		if err != errNoTail || o.total == 0 {
			return err
		}
		// A last member too large to decode back through: landings still
		// find what lies between, and the listing stays partial, as the
		// tar's own end (its padding, Odin's checksum line) is not known.
		o.noTail = true
		o.tail.bit, o.tail.first = o.end*8, uint32(o.total)
		logf("no tail anchor; the listing will be partial")
	}
	o.floor = startBit / 8
	o.hi = o.tail.bit / 8
	o.back = o.hi
	o.lo = o.floor
	if st != nil {
		o.floor = st.bit / 8
		o.lo = o.floor
		// Everything after the head decodes to total-h1 bytes, and deflate
		// cannot store those in much more than that, which bounds how far
		// before the end the next header can be. The total is known mod
		// 2^32; the smallest that fits is assumed, for where to look only.
		total := o.total
		if total == 0 {
			total = int64(o.isize)
			for total < o.h1+2*block {
				total += 1 << 32
			}
		}
		bound := o.end - int64(float64(total-o.h1)*(1+storedOverhead)) - 64<<10
		o.lo = max(o.lo, min(bound, o.hi))
		o.target(st)
	}
	err = o.discover()
	logf("read %d bytes of the stream; %d bytes of the archive not located", o.r.spent(), o.missing())
	return err
}

func key(it item) string { return fmt.Sprintf("%s\x00%d\x00%d", it.Name, it.Size, it.span) }

func (o *opener) note(it item) { o.seen[key(it)] = true }

// missing is the tar-stream length between the head and the anchored tail
// that no found entry accounts for: exact when the decoded length is (with no
// tail, it includes the tar's own end), else mod 2^32.
func (o *opener) missing() int64 {
	if o.headDone {
		return 0
	}
	sum := o.h1
	for _, it := range o.middle {
		sum += it.span
	}
	if o.total > 0 {
		end := o.total
		if !o.noTail {
			end -= int64(uint32(o.total) - o.tail.first)
		}
		return end - sum
	}
	return int64(o.tail.first - uint32(sum))
}

// walk follows the header chain in c from offset at, which holds a header,
// until the end of the archive (eoa), the end of what c can decode, or a
// member too costly to decode through (st). end is where it stopped.
func (o *opener) walk(c *cursor, at int64) (items []item, st *stop, end int64, eoa bool, err error) {
	for {
		if o.r.spent() > o.budget && c.d != nil {
			return items, nil, at, false, nil
		}
		b, u, err := c.window(at, headLen+2*block)
		if err != nil {
			return items, nil, at, false, err
		}
		if len(b) >= 2*block && !anyUnknown(u[:2*block]) && allZero(b[:2*block]) {
			return items, nil, at, true, nil
		}
		if len(b) < block || anyUnknown(u[:block]) {
			return items, nil, at, false, nil
		}
		hdr, data, next, ok := parseAt(b)
		if !ok {
			return items, nil, at, false, nil
		}
		it := item{span: next, bit: c.bit()}
		if hdr == nil {
			items = append(items, it)
			at += next
			continue
		}
		it.reg, it.Name, it.Size, it.own = true, hdr.Name, hdr.Size, ownerOf(hdr)
		it.run, it.rel = c.run, at+data
		c.mark()
		hb, hu, err := c.window(it.rel, min(hdr.Size, headLen))
		if err != nil {
			return items, nil, at, false, err
		}
		it.Head = append([]byte(nil), hb[:knownPrefix(hu)]...)
		if c.d == nil {
			db, du, _ := c.window(it.rel, hdr.Size)
			if int64(len(db)) == hdr.Size && !anyUnknown(du) {
				it.data = db
			}
		} else {
			it.cp = c.checkpointAt(it.rel)
			cost := func(n int64) bool { return float64(n)*c.ratio() > float64(WalkLimit) }
			if cost(hdr.Size) && hdr.Size > sampleLen {
				// The head alone can mislead; measure a fuller sample.
				if _, _, err := c.window(it.rel, sampleLen); err != nil {
					return items, nil, at, false, err
				}
				if cost(hdr.Size - sampleLen) {
					items = append(items, it)
					return items, &stop{bit: c.d.Bit(), left: at + next - c.end(), ratio: c.ratio()}, at, false, nil
				}
			}
			if hdr.Size <= Keep {
				db, du, err := c.window(it.rel, hdr.Size)
				if err != nil {
					return items, nil, at, false, err
				}
				if !anyUnknown(du) {
					it.data = append([]byte(nil), db...)
				}
			}
		}
		items = append(items, it)
		at += next
	}
}

// anchorTail decodes from near the end of the stream to the end, and finds a
// header there whose chain runs through the end-of-archive blocks with only
// zeros (or an Odin checksum line) after: offsets in that run are then known
// from the decoded length.
func (o *opener) anchorTail() error {
	for back := int64(1 << 20); ; back *= 4 {
		from := max(o.start, o.end-back)
		// Past a quarter of the budget, landings are the better use of the rest.
		if back > TailLimit || back > 1<<20 && back > o.budget/4 {
			return errNoTail
		}
		// From the start itself, as a block found past it would miss the
		// first header.
		bit := o.start * 8
		if from > o.start {
			var err error
			if bit, err = inflate.FindEnd(o.r, from, o.end); err != nil {
				continue
			}
		}
		d := inflate.NewUnknown(o.r, bit)
		var out bytes.Buffer
		var unk []bool
		buf, mask := make([]byte, 256<<10), make([]bool, 256<<10)
		for {
			n, err := d.ReadMask(buf, mask)
			out.Write(buf[:n])
			unk = append(unk, mask[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("tgzseek: decoding the end of the stream: %w", err)
			}
		}
		if (d.Bit()+7)/8 != o.end {
			return errors.New("tgzseek: the deflate stream does not end where its container says (concatenated gzip members are not supported)")
		}
		b := out.Bytes()
		base := o.isize - uint32(len(b))
		// With the decoded length exact, where the head ended is a place in
		// this run: the end of the archive there needs no header before it.
		if p := o.h1 - (o.total - int64(len(b))); o.total > 0 && p >= 0 && p+2*block <= int64(len(b)) &&
			!anyUnknown(unk[p:]) && allZero(odinTrimmed(b[p:])) {
			o.tail.bit, o.tail.first = bit, uint32(o.h1)
			logf("tail anchored at the end of the head, %d bytes before the end", o.end-bit/8)
			return nil
		}
		for p := int64((block - base%block) % block); p+block <= int64(len(b)); p += block {
			if anyUnknown(unk[p:p+block]) || !validHeader(b[p:p+block]) {
				continue
			}
			tc := &cursor{run: &run{start: bit}, pos: p, buf: b[p:], unk: unk[p:], eof: true}
			items, _, q, eoa, err := o.walk(tc, p)
			if err != nil || !eoa || anyUnknown(unk[q:]) || !allZero(odinTrimmed(b[q:])) {
				continue
			}
			first := base + uint32(p)
			// A short stream's tail run can reach back over the head.
			for len(items) > 0 && o.seen[key(items[0])] {
				first += uint32(items[0].span)
				items = items[1:]
			}
			o.tail.bit, o.tail.items, o.tail.first = bit, items, first
			for _, it := range items {
				o.note(it)
			}
			logf("tail anchored: %d entries from %d bytes before the end", len(items), o.end-bit/8)
			return nil
		}
		if from == o.start {
			return errNoTail
		}
	}
}

var errNoTail = errors.New("tgzseek: no tar header chain found near the end of the archive")

// landing is a queued place to land, and the sweep it belongs to.
type landing struct {
	x     int64
	sweep int
}

// target queues landings where the header after a costly member can be:
// where its compression so far predicts, just short of the most room it can
// take, then outward from the prediction to cover the stretch between, as a
// member's compression can change along it. A sweep ends at its first find.
func (o *opener) target(st *stop) {
	o.sweeps++
	q := func(x int64) { o.queue = append(o.queue, landing{x, o.sweeps}) }
	at := st.bit / 8
	pred := at + int64(float64(st.left)*st.ratio)
	ub := at + int64(float64(st.left)*(1+storedOverhead)) + 64<<10
	q(pred - LandWalk/2)
	if ub-pred <= LandWalk {
		return
	}
	q(ub - LandWalk/2)
	// A landing searches LandWalk of output, which takes about ratio as
	// much of the stream.
	step := max(int64(float64(LandWalk)*min(st.ratio, 1)), LandWalk/8)
	for k := int64(1); pred-k*step >= at || pred+k*step < ub-LandWalk; k++ {
		if x := pred + k*step - LandWalk/2; x < ub-LandWalk {
			q(x)
		}
		if x := pred - k*step - LandWalk/2; x >= at {
			q(x)
		}
	}
}

func (o *opener) discover() error {
	for o.missing() != 0 && o.r.spent() < o.budget {
		x, ok := o.next()
		if !ok {
			break
		}
		if err := o.land(x); err != nil {
			return err
		}
	}
	return nil
}

func (o *opener) isExplored(x int64) bool {
	for _, s := range o.explored {
		if x >= s.from && x < s.to {
			return true
		}
	}
	return false
}

// next picks where to land: a queued target; else a step back from the
// earliest landing behind the tail, while those keep finding members, as
// small members tend to cluster; else the middle of the widest stretch no
// landing has decoded.
func (o *opener) next() (int64, bool) {
	o.stepping = false
	o.sweep = 0
	for len(o.queue) > 0 {
		l := o.queue[0]
		o.queue = o.queue[1:]
		if l.x >= o.lo && l.x < o.hi && !o.isExplored(l.x) {
			o.sweep = l.sweep
			return l.x, true
		}
	}
	if o.backMisses < backTries {
		if x := o.back - LandWalk; x >= o.lo {
			o.back, o.stepping = x, true
			return x, true
		}
	}
	for {
		best, bestLen := int64(0), int64(0)
		at := o.lo
		for _, s := range o.explored {
			if s.from > at && s.from-at > bestLen && at < o.hi {
				best, bestLen = at, min(s.from, o.hi)-at
			}
			at = max(at, s.to)
		}
		if o.hi-at > bestLen {
			best, bestLen = at, o.hi-at
		}
		if bestLen >= 2*LandWalk {
			return best + bestLen/2, true
		}
		if o.lo <= o.floor {
			return 0, false
		}
		o.lo = o.floor
	}
}

func (o *opener) explore(from, to int64) {
	s := span{from, to}
	var out []span
	for _, e := range o.explored {
		if e.to < s.from || e.from > s.to {
			out = append(out, e)
			continue
		}
		s.from, s.to = min(s.from, e.from), max(s.to, e.to)
	}
	out = append(out, s)
	for i := len(out) - 1; i > 0 && out[i].from < out[i-1].from; i-- {
		out[i], out[i-1] = out[i-1], out[i]
	}
	o.explored = out
}

// land enters the stream at x, looks for a tar header in what follows, and
// walks the chain from the first one found.
func (o *opener) land(x int64) error {
	to := min(x+LandWalk, o.end)
	// Entered on a parse through a few blocks, not on stored blocks, which
	// compressible data lacks: a header found from a false entry would
	// still have to pass its checksum and match the owner.
	bit, err := inflate.FindParsed(o.r, x, to, parsedBlocks, LandConfirm)
	if err != nil {
		o.explore(x, to)
		logf("landing at %d: no entry", x)
		return nil
	}
	c := newCursor(o.r, bit, false)
	found, at := int64(-1), int64(0)
	for at < LandWalk && found < 0 {
		b, u, err := c.window(at, 256<<10+block)
		if err != nil {
			break
		}
		found = o.findHeader(b, u, at)
		if found >= 0 || c.eof || len(b) <= block {
			break
		}
		at += int64(len(b) - block)
	}
	if found < 0 {
		// Only what was searched, less a margin: the decoder runs ahead of
		// its output, and the place of output in the stream is estimated.
		searched := bit/8 + int64(float64(at)*c.ratio()) - LandWalk/8
		o.explore(x, max(x, min(searched, c.bit()/8)))
		logf("landing at %d: no header", x)
		return nil
	}
	items, st, _, _, err := o.walk(c, found)
	o.explore(x, c.bit()/8)
	if err != nil {
		logf("landing at %d: %v", x, err)
	}
	n := 0
	for _, it := range items {
		if o.seen[key(it)] {
			continue
		}
		o.note(it)
		o.middle = append(o.middle, it)
		n++
	}
	logf("landing at %d: %d new entries", x, n)
	if n > 0 && o.sweep != 0 {
		o.queue = slices.DeleteFunc(o.queue, func(l landing) bool { return l.sweep == o.sweep })
	}
	if st != nil && n > 0 {
		o.target(st)
	}
	if o.stepping {
		if n > 0 {
			o.backMisses = 0
		} else {
			o.backMisses++
		}
	}
	return nil
}

// findHeader returns the offset (at + i) of the first fully known, valid tar
// header in b whose owner matches the head's: a block that merely passes the
// checksum inside some member's data would have to match that too.
func (o *opener) findHeader(b []byte, u []bool, at int64) int64 {
	magic := []byte("ustar")
	for i := 257; i < len(b); i++ {
		j := bytes.Index(b[i:], magic)
		if j < 0 {
			return -1
		}
		i += j
		p := i - 257
		if p+block > len(b) {
			return -1
		}
		if anyUnknown(u[p:p+block]) || !validHeader(b[p:p+block]) {
			continue
		}
		if o.own != nil {
			h, err := tar.NewReader(bytes.NewReader(b[p : p+block])).Next()
			if err == nil && ownerOf(h) != *o.own {
				continue
			}
		}
		return at + int64(p)
	}
	return -1
}
