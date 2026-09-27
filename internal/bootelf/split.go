package bootelf

import (
	"bytes"
	"debug/elf"
	"fmt"
)

// JoinSplit reassembles a PIL split image (name.mdt + name.bNN) into the single
// ELF the remoteproc loader sees, placing each segment at its program-header
// offset. seg(i) returns segment i's .bNN file, or nil if absent. The .mdt holds
// the ELF and program headers followed directly by the hash segment, so that
// segment (and with it the secboot identity) survives even with no .bNN files.
// Any other absent segment is zero-filled and its index returned in missing.
func JoinSplit(mdt []byte, seg func(i int) []byte) (img []byte, missing []int, err error) {
	f, err := elf.NewFile(bytes.NewReader(mdt))
	if err != nil {
		return nil, nil, err
	}
	// debug/elf does not expose e_phoff; the header table ends where the hash
	// segment begins inside the .mdt.
	var hdrEnd uint64
	switch f.Class {
	case elf.ELFCLASS32:
		hdrEnd = uint64(f.ByteOrder.Uint32(mdt[0x1c:])) + uint64(f.ByteOrder.Uint16(mdt[0x2a:]))*uint64(f.ByteOrder.Uint16(mdt[0x2c:]))
	case elf.ELFCLASS64:
		hdrEnd = f.ByteOrder.Uint64(mdt[0x20:]) + uint64(f.ByteOrder.Uint16(mdt[0x36:]))*uint64(f.ByteOrder.Uint16(mdt[0x38:]))
	default:
		return nil, nil, fmt.Errorf("unsupported ELF class %v", f.Class)
	}
	if hdrEnd > uint64(len(mdt)) {
		return nil, nil, fmt.Errorf("program headers run past the .mdt (%d > %d)", hdrEnd, len(mdt))
	}
	var end uint64
	for _, p := range f.Progs {
		if e := p.Off + p.Filesz; e > end {
			end = e
		}
	}
	if end > 1<<31 {
		return nil, nil, fmt.Errorf("implausible image size %d", end)
	}
	if uint64(len(mdt)) >= end { // already a whole ELF, not a split
		return mdt, nil, nil
	}
	img = make([]byte, max(end, hdrEnd))
	copy(img, mdt[:hdrEnd])
	for i, p := range f.Progs {
		if p.Filesz == 0 {
			continue
		}
		data := seg(i)
		if data == nil {
			switch {
			case p.Off == 0:
				data = mdt[:min(p.Filesz, uint64(len(mdt)))]
			case (uint32(p.Flags)>>24)&0xf == 2: // hash segment
				data = mdt[hdrEnd:]
			default:
				missing = append(missing, i)
				continue
			}
		}
		copy(img[p.Off:p.Off+p.Filesz], data)
	}
	return img, missing, nil
}
