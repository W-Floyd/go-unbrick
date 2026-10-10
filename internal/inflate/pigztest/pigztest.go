// Package pigztest writes gzip streams shaped like pigz output, for tests: a
// sync flush (an empty stored block) every block bytes of input, with matches
// still reaching back across it. Go's compress/flate starts matching afresh
// after a flush, so its output never needs the history that pigz's does.
package pigztest

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
)

const window = 1 << 15

var (
	lenBase   = [29]int{3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258}
	lenExtra  = [29]uint{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
	distBase  = [30]int{1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577}
	distExtra = [30]uint{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}
)

type bitWriter struct {
	out   bytes.Buffer
	bits  uint64
	nbits uint
}

func (w *bitWriter) put(v uint64, n uint) {
	w.bits |= v << w.nbits
	w.nbits += n
	for w.nbits >= 8 {
		w.out.WriteByte(byte(w.bits))
		w.bits >>= 8
		w.nbits -= 8
	}
}

// code writes a Huffman code, which DEFLATE packs most significant bit first.
func (w *bitWriter) code(c uint64, n uint) {
	var r uint64
	for i := uint(0); i < n; i++ {
		r = r<<1 | (c>>i)&1
	}
	w.put(r, n)
}

func (w *bitWriter) align() {
	if w.nbits > 0 {
		w.put(0, 8-w.nbits)
	}
}

func (w *bitWriter) lit(v int) {
	switch {
	case v < 144:
		w.code(uint64(0x30+v), 8)
	case v < 256:
		w.code(uint64(0x190+v-144), 9)
	case v < 280:
		w.code(uint64(v-256), 7)
	default:
		w.code(uint64(0xc0+v-280), 8)
	}
}

func (w *bitWriter) match(length, dist int) {
	i := len(lenBase) - 1
	for lenBase[i] > length {
		i--
	}
	w.lit(257 + i)
	w.put(uint64(length-lenBase[i]), lenExtra[i])
	j := len(distBase) - 1
	for distBase[j] > dist {
		j--
	}
	w.code(uint64(j), 5)
	w.put(uint64(dist-distBase[j]), distExtra[j])
}

type token struct{ lit, length, dist int }

func (w *bitWriter) tokens(ts []token) {
	for _, t := range ts {
		if t.length == 0 {
			w.lit(t.lit)
		} else {
			w.match(t.length, t.dist)
		}
	}
	w.lit(256)
}

// Gzip compresses data with greedy matching, block bytes of input at a time:
// a fixed-Huffman block, or stored blocks where that would be larger, as zlib
// chooses for incompressible input.
func Gzip(data []byte, block int) []byte {
	w := &bitWriter{}
	w.out.Write([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3})
	head := map[uint32]int{}
	for start := 0; start < len(data) || start == 0; start += block {
		end := min(start+block, len(data))
		final := end == len(data)
		var ts []token
		for i := start; i < end; {
			best, dist := 0, 0
			if i+3 <= len(data) {
				h := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16
				if p, ok := head[h]; ok && i-p <= window {
					n := 0
					for n < 258 && i+n < end && data[p+n] == data[i+n] {
						n++
					}
					if n >= 3 {
						best, dist = n, i-p
					}
				}
				head[h] = i
			}
			if best == 0 {
				ts = append(ts, token{lit: int(data[i])})
				i++
				continue
			}
			ts = append(ts, token{length: best, dist: dist})
			i += best
		}
		var dry bitWriter
		dry.tokens(ts)
		if dry.out.Len() > end-start+5*(1+(end-start)/0xffff) {
			for i := start; i < end || i == start; i += 0xffff {
				j := min(i+0xffff, end)
				last := uint64(0)
				if final && j == end {
					last = 1
				}
				w.put(last, 3)
				w.align()
				binary.Write(&w.out, binary.LittleEndian, uint16(j-i))
				binary.Write(&w.out, binary.LittleEndian, ^uint16(j-i))
				w.out.Write(data[i:j])
				if j == end {
					break
				}
			}
		} else {
			if final {
				w.put(0b011, 3)
			} else {
				w.put(0b010, 3)
			}
			w.tokens(ts)
		}
		if final {
			break
		}
		w.put(0, 3) // empty stored block: the sync flush
		w.align()
		w.out.Write([]byte{0, 0, 0xff, 0xff})
	}
	w.align()
	binary.Write(&w.out, binary.LittleEndian, crc32.ChecksumIEEE(data))
	binary.Write(&w.out, binary.LittleEndian, uint32(len(data)))
	return w.out.Bytes()
}
