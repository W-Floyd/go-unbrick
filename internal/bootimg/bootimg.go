// Package bootimg unpacks Android boot images and the ramdisks inside them, so a
// recovery.img / boot.img / vendor_boot.img from a stock package can be dissected
// down to individual files (e.g. the fastbootd binary in a recovery ramdisk).
//
// It covers the two container magics a modern Motorola package carries:
//
//	ANDROID!  — boot/recovery/init_boot, header versions 0–4
//	VNDRBOOT  — vendor_boot, header versions 3–4 (may hold several ramdisks)
//
// and the ramdisk codecs Android ships: gzip, lz4 (frame), lzma/xz, zstd, bzip2,
// or an already-plain cpio. The ramdisk itself is a newc-format cpio, parsed by
// the cpio.go sibling. Only reading is implemented — nothing here repacks.
package bootimg

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	bootMagic   = "ANDROID!"
	vendorMagic = "VNDRBOOT"
	pageV3      = 4096 // v3/v4 fix the page size rather than storing it
)

// Section is one named blob carved out of a boot image.
type Section struct {
	Name string // kernel, ramdisk, vendor_ramdisk, dtb, recovery_dtbo, second, ...
	Data []byte
}

// Image is a parsed boot image: its container kind, header version, and sections.
type Image struct {
	Magic         string // bootMagic or vendorMagic
	HeaderVersion int
	OSVersion     string // decoded from the v3+ os_version field, when present
	Cmdline       string
	Sections      []Section
}

// Ramdisks returns every ramdisk section, in file order. A boot image has one; a
// v4 vendor_boot can carry several (a table of vendor ramdisk fragments).
func (im *Image) Ramdisks() []Section {
	var out []Section
	for _, s := range im.Sections {
		if s.Name == "ramdisk" || s.Name == "vendor_ramdisk" ||
			(len(s.Name) > 15 && s.Name[:15] == "vendor_ramdisk_") {
			out = append(out, s)
		}
	}
	return out
}

// Parse identifies and unpacks a boot image from its raw bytes.
func Parse(b []byte) (*Image, error) {
	switch {
	case len(b) >= 8 && string(b[:8]) == bootMagic:
		return parseBoot(b)
	case len(b) >= 8 && string(b[:8]) == vendorMagic:
		return parseVendor(b)
	default:
		return nil, fmt.Errorf("not an Android boot image (no ANDROID!/VNDRBOOT magic)")
	}
}

func align(n, page uint32) uint32 {
	if page == 0 {
		return n
	}
	if r := n % page; r != 0 {
		return n + (page - r)
	}
	return n
}

// decodeOSVersion unpacks the packed os_version|patch_level field the v3+ header
// carries: 11+11+10 bits of A.B.C version, then 7+4 bits of yyyy-mm patch level.
func decodeOSVersion(v uint32) string {
	if v == 0 {
		return ""
	}
	ver := v >> 11
	a, b, c := (ver>>14)&0x7f, (ver>>7)&0x7f, ver&0x7f
	patch := v & 0x7ff
	year, month := 2000+int(patch>>4), patch&0xf
	return fmt.Sprintf("%d.%d.%d (%04d-%02d)", a, b, c, year, month)
}

// parseBoot handles the ANDROID! header, versions 0–4. v0–v2 store the page size
// and several extra sections; v3–v4 drop to a fixed 4096 page and just kernel +
// ramdisk. Fields are read defensively so a truncated image errors rather than
// panics.
func parseBoot(b []byte) (*Image, error) {
	if len(b) < 64 {
		return nil, fmt.Errorf("boot image too short")
	}
	ver := le32(b, 40)
	im := &Image{Magic: bootMagic, HeaderVersion: int(ver)}

	if ver >= 3 {
		kernelSz := le32(b, 8)
		ramdiskSz := le32(b, 12)
		im.OSVersion = decodeOSVersion(le32(b, 16))
		im.Cmdline = cstr(b, 44, 1536)
		off := align(le32(b, 20), pageV3) // header_size rounded to the page
		var err error
		if im.Sections, err = carve(b, off, pageV3, []secSpec{
			{"kernel", kernelSz}, {"ramdisk", ramdiskSz},
		}); err != nil {
			return nil, err
		}
		return im, nil
	}

	// v0–v2: page size is in the header, and there are up to five sections.
	kernelSz := le32(b, 8)
	ramdiskSz := le32(b, 16)
	secondSz := le32(b, 24)
	page := le32(b, 36)
	if page == 0 {
		return nil, fmt.Errorf("v%d boot image reports zero page size", ver)
	}
	im.Cmdline = cstr(b, 64, 512)
	specs := []secSpec{{"kernel", kernelSz}, {"ramdisk", ramdiskSz}, {"second", secondSz}}
	if ver >= 1 {
		specs = append(specs, secSpec{"recovery_dtbo", le32(b, 1632)})
	}
	if ver >= 2 {
		specs = append(specs, secSpec{"dtb", le32(b, 1648)})
	}
	sec, err := carve(b, page, page, specs) // sections start after 1 header page
	if err != nil {
		return nil, err
	}
	im.Sections = sec
	return im, nil
}

// parseVendor handles VNDRBOOT v3–v4. v4 adds a vendor-ramdisk table that splits
// the single ramdisk region into named fragments; without it the whole region is
// one vendor_ramdisk.
func parseVendor(b []byte) (*Image, error) {
	if len(b) < 2112 {
		return nil, fmt.Errorf("vendor_boot image too short")
	}
	ver := le32(b, 8)
	page := le32(b, 12)
	if page == 0 {
		return nil, fmt.Errorf("vendor_boot reports zero page size")
	}
	im := &Image{Magic: vendorMagic, HeaderVersion: int(ver)}
	ramdiskSz := le32(b, 24)
	im.Cmdline = cstr(b, 28, 2048)
	dtbSz := le32(b, 2100)

	// Region layout (each padded to page): header, vendor ramdisk, dtb, then the
	// v4 ramdisk table and bootconfig.
	hdrEnd := align(2112, page)
	ramOff := hdrEnd
	dtbOff := ramOff + align(ramdiskSz, page)

	if ver < 4 {
		sec, err := carve(b, ramOff, 0, []secSpec{{"vendor_ramdisk", ramdiskSz}})
		if err != nil {
			return nil, err
		}
		im.Sections = sec
	} else {
		// v4 header tail, after cmdline[2048]@28: tags_addr@2076, name[16]@2080,
		// header_size@2096, dtb_size@2100, dtb_addr(u64)@2104, then the table:
		// table_size@2112, entry_num@2116, entry_size@2120, bootconfig_size@2124.
		entryNum := le32(b, 2116)
		entrySize := le32(b, 2120)
		tableOff := dtbOff + align(dtbSz, page)
		secs, err := carveVendorTable(b, ramOff, tableOff, entryNum, entrySize)
		if err != nil {
			return nil, err
		}
		im.Sections = secs
	}

	if dtbSz > 0 {
		if d, err := slice(b, dtbOff, dtbSz); err == nil {
			im.Sections = append(im.Sections, Section{Name: "dtb", Data: d})
		}
	}
	return im, nil
}

type secSpec struct {
	name string
	size uint32
}

// carve reads consecutive sections starting at off, each padded up to page before
// the next. A zero page means no inter-section padding.
func carve(b []byte, off, page uint32, specs []secSpec) ([]Section, error) {
	var out []Section
	for _, s := range specs {
		if s.size == 0 {
			continue
		}
		d, err := slice(b, off, s.size)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
		out = append(out, Section{Name: s.name, Data: d})
		off += align(s.size, page)
	}
	return out, nil
}

// carveVendorTable splits the vendor ramdisk region into the named fragments the
// v4 table describes. Each entry is 108 bytes: size, offset, type, name[32], then
// board-id words we ignore.
func carveVendorTable(b []byte, ramBase, tableOff, entryNum, entrySize uint32) ([]Section, error) {
	if entrySize < 44 || entryNum == 0 {
		// No usable table — treat the whole region as one ramdisk.
		return []Section{{Name: "vendor_ramdisk", Data: b[min(len(b), int(ramBase)):]}}, nil
	}
	var out []Section
	for i := uint32(0); i < entryNum; i++ {
		base := tableOff + i*entrySize
		if int(base)+44 > len(b) {
			break
		}
		sz := le32(b, int(base))
		off := le32(b, int(base)+4)
		name := cstr(b, int(base)+12, 32)
		d, err := slice(b, ramBase+off, sz)
		if err != nil {
			return nil, fmt.Errorf("vendor_ramdisk fragment %d: %w", i, err)
		}
		label := "vendor_ramdisk_" + name
		if name == "" {
			label = fmt.Sprintf("vendor_ramdisk_%d", i)
		}
		out = append(out, Section{Name: label, Data: d})
	}
	return out, nil
}

func le32(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off : off+4])
}

func slice(b []byte, off, size uint32) ([]byte, error) {
	if int(off)+int(size) > len(b) {
		return nil, fmt.Errorf("section [%d:%d] exceeds image length %d", off, int(off)+int(size), len(b))
	}
	out := make([]byte, size)
	copy(out, b[off:int(off)+int(size)])
	return out, nil
}

func cstr(b []byte, off, max int) string {
	if off >= len(b) {
		return ""
	}
	end := off + max
	if end > len(b) {
		end = len(b)
	}
	s := b[off:end]
	if i := bytes.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return string(s)
}
