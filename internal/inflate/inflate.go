// Package inflate decodes raw DEFLATE entered at a block boundary in the middle
// of a stream, where the 32 KiB of history the first blocks copy from may be
// unknown. Every output byte is tracked as known or not: a literal is known, a
// copy inherits the knownness of its source. Once the last 32 KiB of output are
// all known, nothing unknown can be produced again, and from then on the output
// is exactly what a decode from the start of the stream would give.
package inflate

import (
	"errors"
	"fmt"
	"io"
)

const (
	winSize = 1 << 15
	winMask = winSize - 1
)

// Per-byte history state.
const (
	known   = 0
	unknown = 1
	invalid = 2 // before the start of the stream: a reference here is corrupt data
)

var (
	errCorrupt = errors.New("inflate: corrupt deflate data")
	errTooFar  = errors.New("inflate: distance reaches before the start of the stream")
)

const (
	stHeader = iota
	stHuff
	stStored
	stDone
)

// Decoder is an io.Reader over the decompressed bytes. Bytes it cannot know are
// returned as 0; ExactFrom says where the known-exact output begins.
type Decoder struct {
	r    io.ReaderAt
	next int64 // offset in r of the next byte to load into bits
	buf  []byte
	bp   int
	be   int
	eof  bool // r has no bytes past buf[be]
	over uint // zero bits fed in past the end of r

	bits  uint64
	nbits uint

	ring [winSize]byte
	flag [winSize]uint8
	out  int64
	unk  int // unknown bytes among the last winSize of output, placeholder included

	exactFrom int64

	state     int
	final     bool
	stored    int
	copyLen   int
	copyDist  int
	lit, dist *huff // the current block's codes: fixed, or own
	ownLit    huff
	ownDist   huff
	err       error

	blocks       int
	storedBlocks int

	// OnBoundary, when set, is called at each block boundary: bit is the bit
	// offset in r at which the next block starts, out the output offset there.
	OnBoundary func(bit, out int64)
}

// NewUnknown starts decoding at bit offset bit of r, which must begin a block,
// with unknown history.
func NewUnknown(r io.ReaderAt, bit int64) *Decoder {
	d := newDecoder(r, bit)
	for i := range d.flag {
		d.flag[i] = unknown
	}
	d.unk = winSize
	return d
}

// NewExact starts decoding at bit offset bit of r, which must begin a block,
// with hist as the exact output preceding it. A shorter hist than 32 KiB means
// the stream starts there: bit 0 of a stream takes an empty hist.
func NewExact(r io.ReaderAt, bit int64, hist []byte) *Decoder {
	d := newDecoder(r, bit)
	for i := range d.flag {
		d.flag[i] = invalid
	}
	hist = hist[max(0, len(hist)-winSize):]
	for i, b := range hist {
		j := (i - len(hist)) & winMask
		d.ring[j] = b
		d.flag[j] = known
	}
	return d
}

func newDecoder(r io.ReaderAt, bit int64) *Decoder {
	d := &Decoder{r: r, next: bit / 8, buf: make([]byte, 64<<10)}
	if s := uint(bit % 8); s > 0 {
		d.fill()
		d.bits >>= s
		d.nbits -= s
	}
	return d
}

// Out is the number of bytes decoded so far.
func (d *Decoder) Out() int64 { return d.out }

// ExactFrom is the output offset from which every byte decoded so far is exact.
// It can still advance until Settled.
func (d *Decoder) ExactFrom() int64 { return d.exactFrom }

// Settled reports that no unknown byte can be produced from here on.
func (d *Decoder) Settled() bool { return d.unk == 0 }

// Window returns a copy of the last min(Out, 32 KiB) bytes of output, the
// history a decoder resuming here needs. Valid for NewExact only once Settled.
func (d *Decoder) Window() []byte {
	n := int(min(d.out, winSize))
	w := make([]byte, n)
	for i := range w {
		w[i] = d.ring[(d.out-int64(n)+int64(i))&winMask]
	}
	return w
}

// Bit is the bit offset in r decoded next. After io.EOF it is the end of the
// deflate stream.
func (d *Decoder) Bit() int64 {
	return (d.next-int64(d.be-d.bp))*8 - int64(d.nbits-d.over)
}

// Blocks is the number of blocks decoded to their end.
func (d *Decoder) Blocks() int { return d.blocks }

// StoredBlocks is the number of stored-block headers decoded, each of which
// passed its length check.
func (d *Decoder) StoredBlocks() int { return d.storedBlocks }

func (d *Decoder) fill() {
	for d.nbits <= 56 {
		if d.bp == d.be {
			if d.eof {
				d.nbits += 8 // pad with zeros; consuming them is an error
				d.over += 8
				continue
			}
			n, err := d.r.ReadAt(d.buf, d.next)
			d.next += int64(n)
			d.bp, d.be = 0, n
			if err != nil {
				if err != io.EOF {
					d.err = err
				}
				d.eof = true
			}
			if n == 0 {
				continue
			}
		}
		d.bits |= uint64(d.buf[d.bp]) << d.nbits
		d.bp++
		d.nbits += 8
	}
}

func (d *Decoder) need(n uint) bool {
	if d.nbits < n {
		d.fill()
	}
	return d.err == nil
}

func (d *Decoder) getBits(n uint) (int, error) {
	if !d.need(n) {
		return 0, d.err
	}
	v := int(d.bits & (1<<n - 1))
	d.bits >>= n
	d.nbits -= n
	if d.over > d.nbits {
		return 0, io.ErrUnexpectedEOF
	}
	return v, nil
}

func (d *Decoder) emit(b byte, f uint8) {
	j := d.out & winMask
	if d.unk > 0 {
		if d.flag[j] == unknown {
			d.unk--
		}
		if f == unknown {
			d.unk++
			d.exactFrom = d.out + 1
		}
		d.flag[j] = f
	} else if d.flag[j] == invalid {
		d.flag[j] = f
	}
	d.ring[j] = b
	d.out++
}

// Read decodes into p. It returns io.EOF after the final block.
func (d *Decoder) Read(p []byte) (int, error) { return d.read(p, nil) }

// ReadMask is Read that also sets unk[i] for each byte p[i] it cannot know.
// len(unk) must be at least len(p).
func (d *Decoder) ReadMask(p []byte, unk []bool) (int, error) { return d.read(p, unk[:len(p)]) }

func (d *Decoder) read(p []byte, unk []bool) (int, error) {
	if unk != nil {
		clear(unk)
	}
	n := 0
	for n < len(p) && d.err == nil {
		switch {
		case d.copyLen > 0:
			for d.copyLen > 0 && n < len(p) {
				j := (d.out - int64(d.copyDist)) & winMask
				f := d.flag[j]
				if f == invalid {
					d.err = errTooFar
					break
				}
				b := d.ring[j]
				d.emit(b, f)
				p[n] = b
				if f == unknown && unk != nil {
					unk[n] = true
				}
				n++
				d.copyLen--
			}
		case d.state == stStored:
			if d.stored == 0 {
				d.endBlock()
				continue
			}
			v, err := d.getBits(8)
			if err != nil {
				d.err = err
				break
			}
			d.emit(byte(v), known)
			p[n] = byte(v)
			n++
			d.stored--
		case d.state == stHuff:
			sym, err := d.decode(d.lit)
			if err != nil {
				d.err = err
				break
			}
			switch {
			case sym < 256:
				d.emit(byte(sym), known)
				p[n] = byte(sym)
				n++
			case sym == 256:
				d.endBlock()
			default:
				d.err = d.match(sym)
			}
		case d.state == stHeader:
			d.err = d.header()
		case d.state == stDone:
			return n, io.EOF
		}
	}
	if d.err != nil {
		return n, d.err
	}
	return n, nil
}

func (d *Decoder) endBlock() {
	d.blocks++
	if d.final {
		d.state = stDone
		return
	}
	d.state = stHeader
	if d.OnBoundary != nil {
		d.OnBoundary(d.Bit(), d.out)
	}
}

func (d *Decoder) match(sym int) error {
	sym -= 257
	if sym >= len(lenBase) {
		return errCorrupt
	}
	e, err := d.getBits(lenExtra[sym])
	if err != nil {
		return err
	}
	length := lenBase[sym] + e
	ds, err := d.decode(d.dist)
	if err != nil {
		return err
	}
	if ds >= len(distBase) {
		return errCorrupt
	}
	e, err = d.getBits(distExtra[ds])
	if err != nil {
		return err
	}
	d.copyLen, d.copyDist = length, distBase[ds]+e
	return nil
}

func (d *Decoder) header() error {
	h, err := d.getBits(3)
	if err != nil {
		return err
	}
	d.final = h&1 == 1
	switch h >> 1 {
	case 0:
		d.bits >>= d.nbits % 8
		d.nbits -= d.nbits % 8
		v, err := d.getBits(16)
		if err != nil {
			return err
		}
		nv, err := d.getBits(16)
		if err != nil {
			return err
		}
		if v != ^nv&0xffff {
			return fmt.Errorf("%w: stored block length check", errCorrupt)
		}
		d.stored = v
		d.state = stStored
		d.storedBlocks++
	case 1:
		d.lit, d.dist = &fixedLit, &fixedDist
		d.state = stHuff
	case 2:
		if err := d.dynamic(); err != nil {
			return err
		}
		d.state = stHuff
	default:
		return fmt.Errorf("%w: reserved block type", errCorrupt)
	}
	return nil
}

var clOrder = [19]int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

func (d *Decoder) dynamic() error {
	hlit, err := d.getBits(5)
	if err != nil {
		return err
	}
	hdist, err := d.getBits(5)
	if err != nil {
		return err
	}
	hclen, err := d.getBits(4)
	if err != nil {
		return err
	}
	nlit, ndist := hlit+257, hdist+1
	if nlit > 286 || ndist > 30 {
		return fmt.Errorf("%w: too many codes", errCorrupt)
	}
	var cl [19]uint8
	for i := 0; i < hclen+4; i++ {
		v, err := d.getBits(3)
		if err != nil {
			return err
		}
		cl[clOrder[i]] = uint8(v)
	}
	var clh huff
	if err := clh.build(cl[:], completeOnly); err != nil {
		return err
	}
	lens := make([]uint8, nlit+ndist)
	for i := 0; i < len(lens); {
		sym, err := d.decode(&clh)
		if err != nil {
			return err
		}
		if sym < 16 {
			lens[i] = uint8(sym)
			i++
			continue
		}
		var rep int
		var val uint8
		switch sym {
		case 16:
			if i == 0 {
				return fmt.Errorf("%w: repeat with no previous length", errCorrupt)
			}
			val = lens[i-1]
			rep, err = d.getBits(2)
			rep += 3
		case 17:
			rep, err = d.getBits(3)
			rep += 3
		default:
			rep, err = d.getBits(7)
			rep += 11
		}
		if err != nil {
			return err
		}
		if i+rep > len(lens) {
			return fmt.Errorf("%w: code lengths overrun", errCorrupt)
		}
		for ; rep > 0; rep-- {
			lens[i] = val
			i++
		}
	}
	if lens[256] == 0 {
		return fmt.Errorf("%w: no end-of-block code", errCorrupt)
	}
	d.lit, d.dist = &d.ownLit, &d.ownDist
	if err := d.lit.build(lens[:nlit], singleOK); err != nil {
		return err
	}
	return d.dist.build(lens[nlit:], singleOK)
}

// huff decodes a canonical Huffman code by a table indexed with the next
// width bits of input (LSB first). An entry is sym<<4 | length; 0 is no code.
type huff struct {
	t     []uint16
	width uint
}

// Which incomplete codes build accepts. A real compressor's codes are what
// zlib accepts; holding garbage to the same rules is what makes a false block
// start fail fast.
const (
	anyCode      = iota // the fixed distance code is incomplete by definition
	completeOnly        // code-length codes
	singleOK            // literal/length and distance codes: complete, or one code
)

// check validates code lengths under rule, returning the count per length and
// the longest.
func check(lens []uint8, rule int) (count [16]int, maxLen int, err error) {
	for _, l := range lens {
		count[l]++
		maxLen = max(maxLen, int(l))
	}
	count[0] = 0
	left := 1
	for l := 1; l <= 15; l++ {
		left = left<<1 - count[l]
		if left < 0 {
			return count, 0, fmt.Errorf("%w: over-subscribed code", errCorrupt)
		}
	}
	if left > 0 && (rule == completeOnly || rule == singleOK && maxLen > 1) {
		return count, 0, fmt.Errorf("%w: incomplete code", errCorrupt)
	}
	return count, maxLen, nil
}

func (h *huff) build(lens []uint8, rule int) error {
	count, maxLen, err := check(lens, rule)
	if err != nil {
		return err
	}
	var code [16]int
	for l := 1; l <= 15; l++ {
		code[l] = (code[l-1] + count[l-1]) << 1
	}
	width := max(maxLen, 1)
	size := 1 << width
	if cap(h.t) >= size {
		h.t = h.t[:size]
		clear(h.t)
	} else {
		h.t = make([]uint16, size)
	}
	h.width = uint(width)
	for sym, l := range lens {
		if l == 0 {
			continue
		}
		c := code[l]
		code[l]++
		rev := 0
		for i := 0; i < int(l); i++ {
			rev = rev<<1 | (c>>i)&1
		}
		e := uint16(sym)<<4 | uint16(l)
		for i := rev; i < size; i += 1 << l {
			h.t[i] = e
		}
	}
	return nil
}

func (d *Decoder) decode(h *huff) (int, error) {
	if !d.need(h.width) {
		return 0, d.err
	}
	e := h.t[d.bits&(1<<h.width-1)]
	l := uint(e & 15)
	if l == 0 {
		return 0, fmt.Errorf("%w: invalid code", errCorrupt)
	}
	d.bits >>= l
	d.nbits -= l
	if d.over > d.nbits {
		return 0, io.ErrUnexpectedEOF
	}
	return int(e >> 4), nil
}

var (
	lenBase   = [29]int{3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258}
	lenExtra  = [29]uint{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
	distBase  = [30]int{1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577}
	distExtra = [30]uint{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}

	fixedLit, fixedDist huff
)

func init() {
	var l [288]uint8
	for i := range l {
		switch {
		case i < 144:
			l[i] = 8
		case i < 256:
			l[i] = 9
		case i < 280:
			l[i] = 7
		default:
			l[i] = 8
		}
	}
	fixedLit.build(l[:], anyCode)
	var dl [30]uint8
	for i := range dl {
		dl[i] = 5
	}
	fixedDist.build(dl[:], anyCode)
}
