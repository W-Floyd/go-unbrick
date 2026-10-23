// Package ubi reads a raw UBI image (a NAND dump or an .ubi file): the volumes
// the layout volume names, each presented as one contiguous byte range.
package ubi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sort"
)

const (
	ecMagic       = "UBI#"
	vidMagic      = "UBI!"
	layoutVolID   = 0x7fffefff
	volRecordSize = 172
	maxVolumes    = 128
	headerSize    = 64
)

// Version is this package's current behavior version, for pkg/analysis/cache:
// raise it whenever parsing changes in a way that could change what is
// reported for bytes already seen.
const Version = 1

// Volume is one named UBI volume. Dynamic is false for a static volume.
type Volume struct {
	ID      uint32
	Name    string
	Dynamic bool
	Size    int64
	ra      io.ReaderAt
	lebs    map[uint32]int64 // lnum → absolute offset of the LEB's data
	lebSize int64
	sizes   map[uint32]int64 // static volumes: valid bytes of the LEB
}

// Image is a parsed UBI image.
type Image struct {
	PEBSize int64
	Volumes []*Volume
}

// ReaderAt returns the volume's contents; an unmapped LEB reads as 0xff.
func (v *Volume) ReaderAt() io.ReaderAt { return v }

// ReadAt implements io.ReaderAt over the LEB map.
func (v *Volume) ReadAt(p []byte, off int64) (int, error) {
	if off >= v.Size {
		return 0, io.EOF
	}
	want := int64(len(p))
	eof := false
	if off+want > v.Size {
		want, eof = v.Size-off, true
	}
	n := int64(0)
	for n < want {
		lnum := uint32((off + n) / v.lebSize)
		in := (off + n) % v.lebSize
		chunk := min(want-n, v.lebSize-in)
		dst := p[n : n+chunk]
		if base, ok := v.lebs[lnum]; ok {
			if _, err := v.ra.ReadAt(dst, base+in); err != nil && err != io.EOF {
				return int(n), err
			}
		} else {
			for i := range dst {
				dst[i] = 0xff
			}
		}
		n += chunk
	}
	if eof {
		return int(n), io.EOF
	}
	return int(n), nil
}

type leb struct {
	vol, lnum uint32
	sqnum     uint64
	data      int64
	static    bool
	dataSize  uint32
}

// Parse reads the volumes of the UBI image in ra.
func Parse(ra io.ReaderAt, size int64) (*Image, error) {
	be := binary.BigEndian
	hdr := make([]byte, headerSize)
	if _, err := ra.ReadAt(hdr, 0); err != nil || string(hdr[:4]) != ecMagic {
		return nil, errors.New("ubi: no erase-counter header")
	}
	vidOff, dataOff := int64(be.Uint32(hdr[16:])), int64(be.Uint32(hdr[20:]))
	if vidOff < headerSize || dataOff <= vidOff {
		return nil, errors.New("ubi: implausible header offsets")
	}
	// The PEB size is not stored: it is the smallest power of two past the
	// data offset whose end starts another erase-counter header.
	peb := int64(0)
	for s := int64(16 << 10); s <= 4<<20 && s < size; s <<= 1 {
		if s <= dataOff {
			continue
		}
		if _, err := ra.ReadAt(hdr[:4], s); err == nil && string(hdr[:4]) == ecMagic {
			peb = s
			break
		}
	}
	if peb == 0 {
		return nil, errors.New("ubi: cannot determine the eraseblock size")
	}

	best := map[[2]uint32]leb{}
	vid := make([]byte, headerSize)
	for off := int64(0); off+peb <= size; off += peb {
		if _, err := ra.ReadAt(hdr[:4], off); err != nil || string(hdr[:4]) != ecMagic {
			continue
		}
		if _, err := ra.ReadAt(vid, off+vidOff); err != nil || string(vid[:4]) != vidMagic {
			continue
		}
		l := leb{
			vol: be.Uint32(vid[8:]), lnum: be.Uint32(vid[12:]),
			sqnum: be.Uint64(vid[40:]), data: off + dataOff,
			static: vid[5] == 2, dataSize: be.Uint32(vid[20:]),
		}
		k := [2]uint32{l.vol, l.lnum}
		if old, ok := best[k]; !ok || l.sqnum > old.sqnum {
			best[k] = l
		}
	}

	lebSize := peb - dataOff
	im := &Image{PEBSize: peb}
	layout, ok := best[[2]uint32{layoutVolID, 0}]
	if !ok {
		return nil, errors.New("ubi: no layout volume")
	}
	tbl := make([]byte, volRecordSize*maxVolumes)
	if _, err := ra.ReadAt(tbl, layout.data); err != nil && err != io.EOF {
		return nil, err
	}
	for id := uint32(0); id < maxVolumes; id++ {
		rec := tbl[id*volRecordSize : (id+1)*volRecordSize]
		reserved := be.Uint32(rec[0:])
		nameLen := int(be.Uint16(rec[14:]))
		if reserved == 0 || nameLen == 0 || nameLen > 127 {
			continue
		}
		v := &Volume{
			ID: id, Name: string(bytes.TrimRight(rec[16:16+nameLen], "\x00")),
			Dynamic: rec[12] != 2, ra: ra, lebSize: lebSize,
			lebs: map[uint32]int64{}, sizes: map[uint32]int64{},
		}
		v.Size = int64(reserved) * lebSize
		var last uint32
		for k, l := range best {
			if k[0] != id {
				continue
			}
			v.lebs[l.lnum] = l.data
			if l.static {
				v.sizes[l.lnum] = int64(l.dataSize)
			}
			last = max(last, l.lnum)
		}
		if !v.Dynamic && len(v.lebs) > 0 {
			v.Size = int64(last)*lebSize + v.sizes[last]
		}
		im.Volumes = append(im.Volumes, v)
	}
	sort.Slice(im.Volumes, func(i, j int) bool { return im.Volumes[i].ID < im.Volumes[j].ID })
	return im, nil
}
