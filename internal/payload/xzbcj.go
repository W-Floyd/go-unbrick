package payload

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"

	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// xz filter IDs (xz file format §5.3).
const (
	xzFilterX86      = 0x04
	xzFilterARM      = 0x07
	xzFilterARMThumb = 0x08
	xzFilterARM64    = 0x0a
	xzFilterLZMA2    = 0x21
)

var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

// newXZReader decodes an xz stream. update_engine often compresses firmware
// with a BCJ pre-filter ahead of LZMA2, a chain ulikunitz/xz rejects, so those
// streams are decoded here: LZMA2 through the library's raw chunk reader, then
// the branch-address filter reversed in memory.
func newXZReader(r io.Reader) (io.ReadCloser, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if !xzHasFilterChain(data) {
		xr, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("creating xz reader: %w", err)
		}
		return readCloser{Reader: xr}, nil
	}
	out, err := decodeXZ(data)
	if err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	return readCloser{Reader: bytes.NewReader(out)}, nil
}

// xzHasFilterChain reports whether the first block uses more than one filter.
func xzHasFilterChain(b []byte) bool {
	return len(b) > 13 && bytes.Equal(b[:6], xzMagic) && b[12] != 0 && b[13]&0x03 != 0
}

type xzFilter struct {
	id    uint64
	props []byte
}

func decodeXZ(b []byte) ([]byte, error) {
	if len(b) < 12 || !bytes.Equal(b[:6], xzMagic) {
		return nil, errors.New("not an xz stream")
	}
	check := b[7] & 0x0f
	checkLen := [16]int{0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64}[check]
	pos := 12
	var out []byte
	for {
		if pos >= len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		if b[pos] == 0 { // index indicator: no more blocks
			return out, nil
		}
		blockStart := pos
		filters, next, err := parseXZBlockHeader(b, pos)
		if err != nil {
			return nil, err
		}
		pos = next
		br := bytes.NewReader(b[pos:])
		block, err := decodeXZBlock(br, filters)
		if err != nil {
			return nil, err
		}
		pos += int(br.Size()) - br.Len()
		pos += (4 - (pos-blockStart)%4) % 4
		if pos+checkLen > len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		if err := verifyXZCheck(check, block, b[pos:pos+checkLen]); err != nil {
			return nil, err
		}
		pos += checkLen
		out = append(out, block...)
	}
}

func parseXZBlockHeader(b []byte, pos int) ([]xzFilter, int, error) {
	size := (int(b[pos]) + 1) * 4
	if pos+size > len(b) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	h := b[pos : pos+size]
	if crc32.ChecksumIEEE(h[:size-4]) != binary.LittleEndian.Uint32(h[size-4:]) {
		return nil, 0, errors.New("block header CRC mismatch")
	}
	flags := h[1]
	r := bytes.NewReader(h[2 : size-4])
	for _, present := range []bool{flags&0x40 != 0, flags&0x80 != 0} { // compressed, uncompressed size
		if present {
			if _, err := binary.ReadUvarint(r); err != nil {
				return nil, 0, err
			}
		}
	}
	var filters []xzFilter
	for range int(flags&0x03) + 1 {
		id, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, 0, err
		}
		n, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, 0, err
		}
		props := make([]byte, n)
		if _, err := io.ReadFull(r, props); err != nil {
			return nil, 0, err
		}
		filters = append(filters, xzFilter{id, props})
	}
	return filters, pos + size, nil
}

// decodeXZBlock runs the filter chain backwards: LZMA2 (always last) first,
// then each simple filter in reverse order of encoding.
func decodeXZBlock(r *bytes.Reader, filters []xzFilter) ([]byte, error) {
	last := filters[len(filters)-1]
	if last.id != xzFilterLZMA2 || len(last.props) != 1 {
		return nil, fmt.Errorf("unsupported final filter 0x%x", last.id)
	}
	cfg := lzma.Reader2Config{DictCap: xzLZMA2DictCap(last.props[0])}
	lr, err := cfg.NewReader2(r)
	if err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	for i := len(filters) - 2; i >= 0; i-- {
		f := filters[i]
		var start uint32
		switch len(f.props) {
		case 0:
		case 4:
			start = binary.LittleEndian.Uint32(f.props)
		default:
			return nil, fmt.Errorf("filter 0x%x: bad properties", f.id)
		}
		switch f.id {
		case xzFilterX86:
			bcjX86(buf, start)
		case xzFilterARM:
			bcjARM(buf, start)
		case xzFilterARMThumb:
			bcjARMThumb(buf, start)
		case xzFilterARM64:
			bcjARM64(buf, start)
		default:
			return nil, fmt.Errorf("unsupported filter 0x%x", f.id)
		}
	}
	return buf, nil
}

func xzLZMA2DictCap(p byte) int {
	bits := uint(p & 0x3f)
	c := int64(lzma.MaxDictCap)
	if bits < 40 {
		c = min(int64(2|bits&1)<<(bits/2+11), c)
	}
	return int(max(c, lzma.MinDictCap))
}

func verifyXZCheck(check byte, data, want []byte) error {
	var got []byte
	switch check {
	case 0x01:
		got = binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(data))
	case 0x04:
		got = binary.LittleEndian.AppendUint64(nil, crc64.Checksum(data, crc64.MakeTable(crc64.ECMA)))
	case 0x0a:
		s := sha256.Sum256(data)
		got = s[:]
	default:
		return nil // reserved check types carry no verifiable digest
	}
	if !bytes.Equal(got, want) {
		return errors.New("block check mismatch")
	}
	return nil
}

// The BCJ decoders below follow liblzma's simple filters: each rewrites
// absolute branch targets the encoder produced back into relative ones.

func bcjX86(buf []byte, pos uint32) {
	allowed := [8]bool{true, true, true, false, true, false, false, false}
	bitNum := [8]uint32{0, 1, 2, 2, 3, 3, 3, 3}
	msb := func(b byte) bool { return b == 0x00 || b == 0xff }
	if len(buf) <= 4 {
		return
	}
	size := len(buf) - 4
	prevPos := -1
	var prevMask uint32
	for i := 0; i < size; i++ {
		if buf[i]&0xfe != 0xe8 {
			continue
		}
		d := i - prevPos
		if d > 3 {
			prevMask = 0
		} else {
			prevMask = (prevMask << (d - 1)) & 7
			if prevMask != 0 {
				b := buf[i+4-int(bitNum[prevMask])]
				if !allowed[prevMask] || msb(b) {
					prevPos = i
					prevMask = prevMask<<1 | 1
					continue
				}
			}
		}
		prevPos = i
		if !msb(buf[i+4]) {
			prevMask = prevMask<<1 | 1
			continue
		}
		src := binary.LittleEndian.Uint32(buf[i+1:])
		var dest uint32
		for {
			dest = src - (pos + uint32(i) + 5)
			if prevMask == 0 {
				break
			}
			j := bitNum[prevMask] * 8
			if !msb(byte(dest >> (24 - j))) {
				break
			}
			src = dest ^ (1<<(32-j) - 1)
		}
		dest &= 0x01ffffff
		dest |= 0 - dest&0x01000000
		binary.LittleEndian.PutUint32(buf[i+1:], dest)
		i += 4
	}
}

func bcjARM(buf []byte, pos uint32) {
	for i := 0; i+4 <= len(buf); i += 4 {
		if buf[i+3] != 0xeb {
			continue
		}
		addr := uint32(buf[i]) | uint32(buf[i+1])<<8 | uint32(buf[i+2])<<16
		addr = (addr<<2 - (pos + uint32(i) + 8)) >> 2
		buf[i], buf[i+1], buf[i+2] = byte(addr), byte(addr>>8), byte(addr>>16)
	}
}

func bcjARMThumb(buf []byte, pos uint32) {
	for i := 0; i+4 <= len(buf); i += 2 {
		if buf[i+1]&0xf8 != 0xf0 || buf[i+3]&0xf8 != 0xf8 {
			continue
		}
		addr := uint32(buf[i+1]&7)<<19 | uint32(buf[i])<<11 | uint32(buf[i+3]&7)<<8 | uint32(buf[i+2])
		addr = (addr<<1 - (pos + uint32(i) + 4)) >> 1
		buf[i+1] = 0xf0 | byte(addr>>19)&7
		buf[i] = byte(addr >> 11)
		buf[i+3] = 0xf8 | byte(addr>>8)&7
		buf[i+2] = byte(addr)
		i += 2
	}
}

func bcjARM64(buf []byte, pos uint32) {
	for i := 0; i+4 <= len(buf); i += 4 {
		pc := pos + uint32(i)
		ins := binary.LittleEndian.Uint32(buf[i:])
		switch {
		case ins>>26 == 0x25: // BL
			ins = 0x94000000 | (ins-pc>>2)&0x03ffffff
		case ins&0x9f000000 == 0x90000000: // ADRP
			src := (ins>>29)&3 | (ins>>3)&0x001ffffc
			if (src+0x00020000)&0x001c0000 != 0 {
				continue
			}
			dest := src - pc>>12
			ins &= 0x9000001f
			ins |= (dest & 3) << 29
			ins |= (dest & 0x0003fffc) << 3
			ins |= (0 - dest&0x00020000) & 0x00e00000
		default:
			continue
		}
		binary.LittleEndian.PutUint32(buf[i:], ins)
	}
}
