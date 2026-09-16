package payload

import (
	"fmt"
	"io"
	"math"
)

const sparseHoleBlock = math.MaxUint64

func totalBlocks(extents []*Extent) uint64 {
	var n uint64
	for _, e := range extents {
		n += e.GetNumBlocks()
	}
	return n
}

func validateExtents(extents []*Extent, blockSize uint64) error {
	for _, e := range extents {
		start := e.GetStartBlock()
		num := e.GetNumBlocks()
		if start == sparseHoleBlock {
			return fmt.Errorf("sparse hole extents are not supported")
		}
		if num == 0 {
			continue
		}
		end := start + num
		if end < start || end > math.MaxInt64/blockSize {
			return fmt.Errorf("extent out of addressable range (start=%d, num=%d)", start, num)
		}
	}
	return nil
}

type extentsWriter struct {
	w         io.WriterAt
	extents   []*Extent
	blockSize uint64
	idx       int
	written   int64
}

func newExtentsWriter(w io.WriterAt, extents []*Extent, blockSize uint64) (*extentsWriter, error) {
	if err := validateExtents(extents, blockSize); err != nil {
		return nil, err
	}
	return &extentsWriter{w: w, extents: extents, blockSize: blockSize}, nil
}

func (w *extentsWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		if w.idx >= len(w.extents) {
			return total, fmt.Errorf("attempted to write past destination extents")
		}
		e := w.extents[w.idx]
		length := int64(e.GetNumBlocks() * w.blockSize)
		if w.written >= length {
			w.idx++
			w.written = 0
			continue
		}
		chunk := p
		remain := length - w.written
		if int64(len(chunk)) > remain {
			chunk = chunk[:remain]
		}
		off := int64(e.GetStartBlock()*w.blockSize) + w.written
		n, err := w.w.WriteAt(chunk, off)
		total += n
		w.written += int64(n)
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

