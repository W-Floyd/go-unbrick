// Package sparse decodes the Android sparse image format (the layout `simg2img`
// reverses) to a raw image. Motorola ships NON-HLOS.bin (the modem partition)
// and the super chunks in this format.
package sparse

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
