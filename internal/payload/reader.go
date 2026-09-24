package payload

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// PartitionReaderAt returns an io.ReaderAt over a partition's decompressed image
// that materializes lazily: a read decompresses only the operations whose output
// covers the requested byte range, caching recently used ones. Reading a few
// small files out of a multi-GB partition — e.g. build.prop from an EROFS system
// — then costs a handful of operation decompressions rather than the whole
// partition. Reads past the partition end, or over a gap no operation writes,
// return zeros (never a short read), which is what an EROFS reader over the image
// needs. Full (non-delta) payloads only; a delta operation is reported here.
func (p *Payload) PartitionReaderAt(name string) (io.ReaderAt, int64, error) {
	part := p.Partition(name)
	if part == nil {
		return nil, 0, fmt.Errorf("partition %q not found in payload", name)
	}
	bs := int64(p.blockSize)
	var segs []opSegment
	for i, op := range part.GetOperations() {
		switch op.GetType() {
		case InstallOperation_REPLACE, InstallOperation_REPLACE_BZ,
			InstallOperation_REPLACE_XZ, InstallOperation_ZSTD,
			InstallOperation_ZERO, InstallOperation_DISCARD:
		default:
			return nil, 0, fmt.Errorf("partition %q operation %d is %s (delta payloads unsupported)", name, i, op.GetType())
		}
		if err := validateExtents(op.GetDstExtents(), p.blockSize); err != nil {
			return nil, 0, err
		}
		var opOff int64 // byte offset within this op's contiguous decompressed output
		for _, e := range op.GetDstExtents() {
			n := int64(e.GetNumBlocks()) * bs
			if n == 0 {
				continue
			}
			segs = append(segs, opSegment{
				startByte: int64(e.GetStartBlock()) * bs,
				length:    n,
				opIndex:   i,
				opOffset:  opOff,
			})
			opOff += n
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].startByte < segs[j].startByte })

	size := int64(part.GetNewPartitionInfo().GetSize())
	if size == 0 {
		for _, s := range segs { // fall back to the furthest extent end
			if end := s.startByte + s.length; end > size {
				size = end
			}
		}
	}
	return &partitionReaderAt{p: p, part: part, size: size, segs: segs, cache: map[int][]byte{}, maxCache: 24}, size, nil
}

// opSegment maps one output extent to the operation that produces it and where
// the extent's bytes sit within that operation's contiguous decompressed output.
type opSegment struct {
	startByte int64 // partition byte offset the extent begins at
	length    int64
	opIndex   int
	opOffset  int64
}

type partitionReaderAt struct {
	p    *Payload
	part *PartitionUpdate
	size int64
	segs []opSegment // sorted by startByte, non-overlapping in a full OTA

	mu       sync.Mutex
	cache    map[int][]byte // opIndex -> decompressed contiguous output
	order    []int          // insertion order, for FIFO eviction
	maxCache int
}

func (r *partitionReaderAt) ReadAt(dst []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("payload: negative offset %d", off)
	}
	for i := range dst {
		dst[i] = 0 // gaps and past-end read as zero
	}
	end := off + int64(len(dst))
	// First segment that could reach past off.
	i := sort.Search(len(r.segs), func(i int) bool {
		return r.segs[i].startByte+r.segs[i].length > off
	})
	for ; i < len(r.segs); i++ {
		s := r.segs[i]
		if s.startByte >= end {
			break
		}
		from, to := max64(off, s.startByte), min64(end, s.startByte+s.length)
		if to <= from {
			continue
		}
		opData, err := r.opData(s.opIndex)
		if err != nil {
			return 0, err
		}
		src := s.opOffset + (from - s.startByte)
		copy(dst[from-off:to-off], opData[src:src+(to-from)])
	}
	return len(dst), nil
}

// opData returns the operation's full decompressed output, from cache or by
// decompressing it, evicting the oldest entry past the cache bound.
func (r *partitionReaderAt) opData(idx int) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.cache[idx]; ok {
		return d, nil
	}
	d, err := r.p.decompressOp(r.part.GetOperations()[idx])
	if err != nil {
		return nil, err
	}
	r.cache[idx] = d
	r.order = append(r.order, idx)
	if len(r.order) > r.maxCache {
		delete(r.cache, r.order[0])
		r.order = r.order[1:]
	}
	return d, nil
}

// decompressOp decompresses one operation into its contiguous output buffer
// (totalBlocks*blockSize), zero-padding a stream shorter than its extents.
func (p *Payload) decompressOp(op *InstallOperation) ([]byte, error) {
	out := make([]byte, int64(totalBlocks(op.GetDstExtents()))*int64(p.blockSize))
	switch op.GetType() {
	case InstallOperation_ZERO, InstallOperation_DISCARD:
		return out, nil // already zero
	}
	sr := io.NewSectionReader(p.ra, p.dataOffset+int64(op.GetDataOffset()), int64(op.GetDataLength()))
	var rd io.ReadCloser
	switch op.GetType() {
	case InstallOperation_REPLACE:
		rd = readCloser{Reader: sr}
	case InstallOperation_REPLACE_BZ:
		rd = newBzip2Reader(sr)
	case InstallOperation_REPLACE_XZ:
		var err error
		if rd, err = newXZReader(sr); err != nil {
			return nil, err
		}
	case InstallOperation_ZSTD:
		var err error
		if rd, err = newZstdReader(sr); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("payload: unsupported operation %s", op.GetType())
	}
	_, err := io.ReadFull(rd, out)
	rd.Close()
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = nil // shorter than the extents: the remainder stays zero-padded
	}
	if err != nil {
		return nil, fmt.Errorf("decompressing operation data: %w", err)
	}
	return out, nil
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
