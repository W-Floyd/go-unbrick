// Package sparse decodes the Android sparse image format (the layout `simg2img`
// reverses) to a raw image. Motorola ships NON-HLOS.bin (the modem partition)
// and the super chunks in this format.
package sparse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Magic is the little-endian sparse file magic (0xed26ff3a).
const Magic = 0xed26ff3a

const (
	chunkRaw      = 0xcac1
	chunkFill     = 0xcac2
	chunkDontCare = 0xcac3
	chunkCRC      = 0xcac4
)

// IsSparse reports whether blob begins with the sparse magic.
func IsSparse(blob []byte) bool {
	return len(blob) >= 4 && binary.LittleEndian.Uint32(blob[:4]) == Magic
}

// CopyRange copies the output window [off, off+len(dst)) of the raw image a
// sparse blob describes into dst, without expanding the whole image. Only raw
// and fill records overlapping the window are written; don't-care (and unwritten)
// regions are left as they are in dst. This is what lets the super.img sparse
// *chunks* — each a full-image sparse file carrying real data only for its own
// span and don't-care elsewhere — be overlaid: call CopyRange with the same
// window on each chunk and only the owning chunk writes. Returns the number of
// bytes actually written into dst (raw+fill overlap), so a caller can stop once
// the window is covered. A non-sparse blob is treated as the raw image itself.
func CopyRange(blob []byte, off uint64, dst []byte) (wrote int, err error) {
	end := off + uint64(len(dst))
	if !IsSparse(blob) {
		if uint64(len(blob)) <= off {
			return 0, nil
		}
		hi := end
		if hi > uint64(len(blob)) {
			hi = uint64(len(blob))
		}
		return copy(dst, blob[off:hi]), nil
	}
	le := binary.LittleEndian
	if len(blob) < 28 {
		return 0, fmt.Errorf("sparse: header truncated (%d bytes)", len(blob))
	}
	fileHdrSz := int(le.Uint16(blob[8:10]))
	chunkHdrSz := int(le.Uint16(blob[10:12]))
	blkSz := le.Uint32(blob[12:16])
	totalChunks := le.Uint32(blob[20:24])
	if fileHdrSz < 28 || chunkHdrSz < 12 {
		return 0, fmt.Errorf("sparse: bad header sizes file=%d chunk=%d", fileHdrSz, chunkHdrSz)
	}
	var outPos uint64 // absolute output offset of the current record
	p := fileHdrSz
	for i := uint32(0); i < totalChunks; i++ {
		if p+chunkHdrSz > len(blob) {
			return wrote, fmt.Errorf("sparse: chunk %d header past end", i)
		}
		ctype := le.Uint16(blob[p : p+2])
		chunkBlks := le.Uint32(blob[p+4 : p+8])
		totalSz := int(le.Uint32(blob[p+8 : p+12]))
		if totalSz < chunkHdrSz || p+totalSz > len(blob) {
			return wrote, fmt.Errorf("sparse: chunk %d size %d out of range", i, totalSz)
		}
		data := blob[p+chunkHdrSz : p+totalSz]
		n := uint64(chunkBlks) * uint64(blkSz)
		recEnd := outPos + n
		// Only touch dst for records overlapping [off, end).
		if ctype != chunkCRC && recEnd > off && outPos < end {
			lo, hi := maxu(outPos, off), minu(recEnd, end)
			d := dst[lo-off : hi-off]
			switch ctype {
			case chunkRaw:
				if uint64(len(data)) < n {
					return wrote, fmt.Errorf("sparse: raw chunk %d short", i)
				}
				wrote += copy(d, data[lo-outPos:hi-outPos])
			case chunkFill:
				if len(data) < 4 {
					return wrote, fmt.Errorf("sparse: fill chunk %d short", i)
				}
				phase := lo - outPos // keep the 4-byte pattern aligned to the record
				for j := range d {
					d[j] = data[(uint64(j)+phase)&3]
				}
				wrote += len(d)
			case chunkDontCare:
				// leave dst untouched — another chunk owns this region
			default:
				return wrote, fmt.Errorf("sparse: unknown chunk type 0x%04x at %d", ctype, i)
			}
		}
		if ctype != chunkCRC {
			outPos = recEnd
		}
		p += totalSz
	}
	return wrote, nil
}

func maxu(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func minu(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// OutputSize returns the raw image size a sparse blob expands to, read from its
// header (total_blks × blk_sz) without decoding — O(1), so a 45 GiB userdata is
// cheap to report. A non-sparse blob returns its own length.
func OutputSize(blob []byte) (int64, error) {
	if !IsSparse(blob) {
		return int64(len(blob)), nil
	}
	if len(blob) < 28 {
		return 0, fmt.Errorf("sparse: header truncated (%d bytes)", len(blob))
	}
	le := binary.LittleEndian
	blkSz := le.Uint32(blob[12:16])
	totalBlks := le.Uint32(blob[16:20])
	return int64(totalBlks) * int64(blkSz), nil
}

// Prefix expands just the first n bytes of the raw image, enough to identify its
// filesystem without materializing the whole thing. Don't-care regions read as
// zero. A non-sparse blob returns its own first n bytes.
func Prefix(blob []byte, n int) ([]byte, error) {
	if !IsSparse(blob) {
		if n > len(blob) {
			n = len(blob)
		}
		return blob[:n], nil
	}
	buf := make([]byte, n)
	if _, err := CopyRange(blob, 0, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReaderAt presents a sparse blob as a random-access raw image without expanding
// it: each ReadAt maps to a CopyRange window, and don't-care regions read as
// zero. This lets a filesystem reader (ext4fs, erofs) walk a multi-GiB image by
// range instead of materializing it. A non-sparse blob is wrapped as-is. The
// returned size is the raw (expanded) size.
func ReaderAt(blob []byte) (io.ReaderAt, int64, error) {
	size, err := OutputSize(blob)
	if err != nil {
		return nil, 0, err
	}
	if !IsSparse(blob) {
		return bytes.NewReader(blob), size, nil
	}
	return &sparseReaderAt{blob: blob, size: size}, size, nil
}

type sparseReaderAt struct {
	blob []byte
	size int64
}

// ReadAt fills p from the raw image at off. CopyRange writes only raw/fill data,
// so p is zeroed first for the don't-care (and unwritten) regions. It costs one
// chunk-table walk per call.
func (s *sparseReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("sparse: negative offset %d", off)
	}
	if off >= s.size {
		return 0, io.EOF
	}
	n := p
	var atEnd error
	if off+int64(len(p)) > s.size {
		n = p[:s.size-off]
		atEnd = io.EOF
	}
	for i := range n {
		n[i] = 0
	}
	if _, err := CopyRange(s.blob, uint64(off), n); err != nil {
		return 0, err
	}
	return len(n), atEnd
}

// Decode expands a sparse image to its raw form. A non-sparse blob is returned
// unchanged, so callers can pass through images that are already raw.
func Decode(blob []byte) ([]byte, error) {
	if !IsSparse(blob) {
		return blob, nil
	}
	le := binary.LittleEndian
	if len(blob) < 28 {
		return nil, fmt.Errorf("sparse: header truncated (%d bytes)", len(blob))
	}
	fileHdrSz := int(le.Uint16(blob[8:10]))
	chunkHdrSz := int(le.Uint16(blob[10:12]))
	blkSz := le.Uint32(blob[12:16])
	totalChunks := le.Uint32(blob[20:24])
	if fileHdrSz < 28 || chunkHdrSz < 12 {
		return nil, fmt.Errorf("sparse: bad header sizes file=%d chunk=%d", fileHdrSz, chunkHdrSz)
	}

	var out bytes.Buffer
	p := fileHdrSz
	for i := uint32(0); i < totalChunks; i++ {
		if p+chunkHdrSz > len(blob) {
			return nil, fmt.Errorf("sparse: chunk %d header past end", i)
		}
		ctype := le.Uint16(blob[p : p+2])
		chunkBlks := le.Uint32(blob[p+4 : p+8])
		totalSz := int(le.Uint32(blob[p+8 : p+12]))
		if totalSz < chunkHdrSz || p+totalSz > len(blob) {
			return nil, fmt.Errorf("sparse: chunk %d size %d out of range", i, totalSz)
		}
		data := blob[p+chunkHdrSz : p+totalSz]
		n := int(chunkBlks) * int(blkSz)
		switch ctype {
		case chunkRaw:
			if len(data) < n {
				return nil, fmt.Errorf("sparse: raw chunk %d short", i)
			}
			out.Write(data[:n])
		case chunkFill:
			if len(data) < 4 {
				return nil, fmt.Errorf("sparse: fill chunk %d short", i)
			}
			fill := data[:4]
			for j := 0; j < n; j += 4 {
				out.Write(fill)
			}
		case chunkDontCare:
			out.Write(make([]byte, n))
		case chunkCRC:
			// no output
		default:
			return nil, fmt.Errorf("sparse: unknown chunk type 0x%04x at %d", ctype, i)
		}
		p += totalSz
	}
	return out.Bytes(), nil
}
