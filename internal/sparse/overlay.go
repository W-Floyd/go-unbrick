package sparse

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// record is one raw or fill run of a sparse image's output, located in the
// file it was read from.
type record struct {
	out, n int64
	off    int64 // data offset in ra, for raw
	fill   [4]byte
	isFill bool
	ra     io.ReaderAt
}

// Overlay reads several sparse images of one raw image as that image, lazily:
// only each file's chunk headers are read up front. Each file addresses the
// whole image and carries data for its own span (the way Motorola splits
// super), so a byte comes from whichever file wrote it, else zero. Size is the
// largest image any file declares.
type Overlay struct {
	recs []record
	size int64
}

// NewOverlay indexes the sparse files. A file that is not sparse is an error:
// there is no offset to place it at.
func NewOverlay(files []io.ReaderAt) (*Overlay, error) {
	o := &Overlay{}
	le := binary.LittleEndian
	for i, ra := range files {
		h := make([]byte, 28)
		if _, err := ra.ReadAt(h, 0); err != nil || le.Uint32(h) != Magic {
			return nil, fmt.Errorf("sparse: overlay file %d is not sparse", i)
		}
		fileHdr, chunkHdr := int64(le.Uint16(h[8:])), int64(le.Uint16(h[10:]))
		blk := int64(le.Uint32(h[12:]))
		o.size = max(o.size, int64(le.Uint32(h[16:]))*blk)
		p, pos := fileHdr, int64(0)
		for c := uint32(0); c < le.Uint32(h[20:]); c++ {
			ch := make([]byte, chunkHdr)
			if _, err := ra.ReadAt(ch, p); err != nil {
				return nil, fmt.Errorf("sparse: file %d chunk %d: %w", i, c, err)
			}
			typ, n, total := le.Uint16(ch), int64(le.Uint32(ch[4:]))*blk, int64(le.Uint32(ch[8:]))
			switch typ {
			case chunkRaw:
				o.recs = append(o.recs, record{out: pos, n: n, off: p + chunkHdr, ra: ra})
			case chunkFill:
				r := record{out: pos, n: n, isFill: true}
				if _, err := ra.ReadAt(r.fill[:], p+chunkHdr); err != nil {
					return nil, err
				}
				o.recs = append(o.recs, r)
			case chunkDontCare:
			case chunkCRC:
				n = 0
			default:
				return nil, fmt.Errorf("sparse: file %d: unknown chunk type 0x%04x", i, typ)
			}
			pos += n
			p += total
		}
	}
	sort.SliceStable(o.recs, func(i, j int) bool { return o.recs[i].out < o.recs[j].out })
	return o, nil
}

// Size is the raw image's length.
func (o *Overlay) Size() int64 { return o.size }

func (o *Overlay) ReadAt(p []byte, off int64) (int, error) {
	if off >= o.size {
		return 0, io.EOF
	}
	want := p
	if off+int64(len(p)) > o.size {
		want = p[:o.size-off]
	}
	clear(want)
	end := off + int64(len(want))
	i := sort.Search(len(o.recs), func(i int) bool { return o.recs[i].out+o.recs[i].n > off })
	for ; i < len(o.recs) && o.recs[i].out < end; i++ {
		r := o.recs[i]
		lo, hi := max(off, r.out), min(end, r.out+r.n)
		if lo >= hi {
			continue
		}
		dst := want[lo-off : hi-off]
		if r.isFill {
			for j := range dst {
				dst[j] = r.fill[(lo-r.out+int64(j))%4]
			}
		} else if _, err := r.ra.ReadAt(dst, r.off+lo-r.out); err != nil && err != io.EOF {
			return 0, err
		}
	}
	if len(want) < len(p) {
		return len(want), io.EOF
	}
	return len(want), nil
}
