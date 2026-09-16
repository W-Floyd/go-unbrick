// Package efi extracts UEFI modules from the firmware volumes embedded in a
// device's boot chain. On Qualcomm platforms abl and xbl are UEFI images: each
// carries an EFI_FIRMWARE_VOLUME whose files are usually a single LZMA-packed
// nested volume holding the real modules, so walking to a module means
// descending volume -> file -> section -> (decompress) -> volume again.
package efi

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/ulikunitz/xz/lzma"
)

// fvSignature marks an EFI_FIRMWARE_VOLUME_HEADER; it sits 40 bytes into the
// header, after the 16 zero bytes and the filesystem GUID.
var fvSignature = []byte("_FVH")

const sigOffset = 40

// Section types we need to descend through or read.
const (
	sectionCompression = 0x01
	sectionGUIDDefined = 0x02
	sectionPE32        = 0x10
	sectionUserface    = 0x15 // EFI_SECTION_USER_INTERFACE: the module's own name
	sectionFVImage     = 0x17
	fileTypeFVImage    = 0x0b
	fileTypePad        = 0xf0 // EFI_FV_FILETYPE_FFS_PAD: alignment filler only
	fileHeaderLen      = 24
	sectionHeaderLen   = 4
	lzmaGUIDDefinedHdr = 24 // GUID (16) + data offset (2) + attributes (2) + section header (4)
	maxNestingDepth    = 8
	minVolumeHeaderLen = 64
)

// The GUID-defined section GUIDs we can unwrap. abl uses the standard EDK2
// LZMA compressor; xbl uses a Qualcomm-specific GUID that in practice wraps a
// plain gzip stream.
var (
	// LZMA_CUSTOM_DECOMPRESS_GUID, EE4E5898-3914-4259-9D6E-DC7BD79403CF.
	lzmaGUID = []byte{
		0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42,
		0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf,
	}
	// Qualcomm, 1D301FE9-BE79-4353-91C2-D23BC959AE0C.
	qcomGzipGUID = []byte{
		0xe9, 0x1f, 0x30, 0x1d, 0x79, 0xbe, 0x53, 0x43,
		0x91, 0xc2, 0xd2, 0x3b, 0xc9, 0x59, 0xae, 0x0c,
	}
)

// Module is one extracted UEFI file.
type Module struct {
	GUID   string // canonical 8-4-4-4-12, lowercase
	Name   string // from the module's UI section; empty if it carries none
	Type   byte   // EFI_FV_FILETYPE_*
	Volume int    // index of the containing volume, in discovery order
	Data   []byte // the module's PE32 body where present, else the whole file
}

// Volume is a firmware volume located inside an image.
type Volume struct {
	Offset int // byte offset within the image it was found in
	GUID   string
	Size   int
}

// LoadGUIDNames reads a "guid,name" CSV mapping module GUIDs to names, for the
// modules that ship no UI section. Blank lines and those starting with # are
// ignored, as are extra columns.
func LoadGUIDNames(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 2 {
			continue
		}
		guid := strings.ToLower(strings.TrimSpace(f[0]))
		name := strings.TrimSpace(f[1])
		if guid == "" || name == "" || strings.EqualFold(guid, "guid") {
			continue
		}
		out[guid] = name
	}
	return out, sc.Err()
}

// ApplyNames fills in the name of any module that carries no UI section, from a
// GUID lookup table. A module's own UI section always wins.
func ApplyNames(mods []Module, names map[string]string) {
	for i := range mods {
		if mods[i].Name == "" {
			mods[i].Name = names[strings.ToLower(mods[i].GUID)]
		}
	}
}

// Filename is the name a module should be written under: its own name where it
// has one, prefixed by GUID so the output is unique and sorts stably.
func (m Module) Filename() string {
	if m.Name == "" {
		return m.GUID + m.ext()
	}
	return m.GUID + "-" + sanitize(m.Name) + m.ext()
}

func (m Module) ext() string {
	if m.Type == fileTypeFVImage {
		return ".fv"
	}
	return ".efi"
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, s)
}

// guidString renders a mixed-endian EFI GUID the way UEFI tooling prints it.
func guidString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

// uint24 reads the 3-byte little-endian lengths FFS headers use.
func uint24(b []byte) int {
	if len(b) < 3 {
		return 0
	}
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16
}

// Volumes reports every firmware volume in an image, in offset order. It scans
// rather than trusting a fixed layout, because the volume's position inside a
// signed ELF varies with the header and hash-table segments ahead of it.
func Volumes(img []byte) []Volume {
	var out []Volume
	for i := 0; ; {
		j := bytes.Index(img[i:], fvSignature)
		if j < 0 {
			return out
		}
		at := i + j
		i = at + len(fvSignature)
		start := at - sigOffset
		if start < 0 || start+minVolumeHeaderLen > len(img) {
			continue
		}
		size := int(binary.LittleEndian.Uint64(img[start+32:]))
		hdrLen := int(binary.LittleEndian.Uint16(img[start+48:]))
		if size <= 0 || hdrLen < minVolumeHeaderLen || start+size > len(img) || hdrLen > size {
			continue // a stray "_FVH" in data, not a real header
		}
		out = append(out, Volume{Offset: start, GUID: guidString(img[start+16:]), Size: size})
	}
}

// Extract returns every UEFI module in an image, descending through nested and
// LZMA-compressed volumes.
func Extract(img []byte) ([]Module, error) {
	var out []Module
	for n, v := range Volumes(img) {
		mods, err := walkVolume(img[v.Offset:v.Offset+v.Size], n, 0)
		if err != nil {
			return nil, fmt.Errorf("volume %d at %d: %w", n, v.Offset, err)
		}
		out = append(out, mods...)
	}
	return out, nil
}

// walkVolume iterates the FFS files of one volume.
func walkVolume(fv []byte, volume, depth int) ([]Module, error) {
	if depth > maxNestingDepth {
		return nil, fmt.Errorf("nesting deeper than %d volumes", maxNestingDepth)
	}
	if len(fv) < minVolumeHeaderLen {
		return nil, nil
	}
	hdrLen := int(binary.LittleEndian.Uint16(fv[48:]))
	if hdrLen < minVolumeHeaderLen || hdrLen > len(fv) {
		return nil, fmt.Errorf("implausible header length %d", hdrLen)
	}
	var out []Module
	for off := hdrLen; off+fileHeaderLen <= len(fv); {
		hdr := fv[off:]
		size := uint24(hdr[20:23])
		// Erased flash is 0xff all the way through, size included; the rest of
		// the volume is then unused. A pad file also has an all-0xff GUID but a
		// real size, so the size is what distinguishes them.
		if size == 0xffffff || size < fileHeaderLen || off+size > len(fv) {
			break
		}
		// Pad files only align what follows; they hold nothing to extract.
		if hdr[18] != fileTypePad {
			mods, err := walkFile(hdr[:size], volume, depth)
			if err != nil {
				return nil, err
			}
			out = append(out, mods...)
		}
		off = align8(off + size)
	}
	return out, nil
}

// walkFile turns one FFS file into modules: either the nested volumes its
// sections carry, or the file itself.
func walkFile(file []byte, volume, depth int) ([]Module, error) {
	m := Module{
		GUID:   guidString(file),
		Type:   file[18],
		Volume: volume,
		Data:   file[fileHeaderLen:],
	}
	name, body, nested, err := walkSections(file[fileHeaderLen:], depth)
	if err != nil {
		return nil, err
	}
	if len(nested) > 0 {
		return nested, nil // a container file: its payload is the modules within
	}
	m.Name = name
	if body != nil {
		m.Data = body
	}
	return []Module{m}, nil
}

// walkSections scans a file's sections, returning its UI name, its PE32 body,
// and any modules recovered from nested volumes.
func walkSections(b []byte, depth int) (name string, body []byte, nested []Module, err error) {
	for off := 0; off+sectionHeaderLen <= len(b); {
		size := uint24(b[off : off+3])
		typ := b[off+3]
		if size < sectionHeaderLen || off+size > len(b) {
			break
		}
		sec := b[off : off+size]
		switch typ {
		case sectionUserface:
			name = ucs2(sec[sectionHeaderLen:])
		case sectionPE32:
			body = sec[sectionHeaderLen:]
		case sectionFVImage:
			mods, werr := walkVolume(sec[sectionHeaderLen:], -1, depth+1)
			if werr != nil {
				return "", nil, nil, werr
			}
			nested = append(nested, mods...)
		case sectionGUIDDefined, sectionCompression:
			inner, derr := decompress(sec, typ)
			if derr != nil {
				// An unknown compressor is not fatal: keep the raw file rather
				// than abandoning the rest of the volume.
				break
			}
			for _, v := range Volumes(inner) {
				mods, werr := walkVolume(inner[v.Offset:v.Offset+v.Size], -1, depth+1)
				if werr != nil {
					return "", nil, nil, werr
				}
				nested = append(nested, mods...)
			}
			if len(nested) == 0 {
				// Not a volume inside: treat the decompressed bytes as sections.
				n2, b2, m2, werr := walkSections(inner, depth+1)
				if werr != nil {
					return "", nil, nil, werr
				}
				if name == "" {
					name = n2
				}
				if body == nil {
					body = b2
				}
				nested = append(nested, m2...)
			}
		}
		off = align4(off + size)
	}
	return name, body, nested, nil
}

// decompress unwraps a GUID-defined compressed section, dispatching on the
// compressor GUID.
func decompress(sec []byte, typ byte) ([]byte, error) {
	if typ != sectionGUIDDefined {
		return nil, fmt.Errorf("section type 0x%02x: unsupported compressor", typ)
	}
	if len(sec) < lzmaGUIDDefinedHdr {
		return nil, fmt.Errorf("GUID-defined section too short")
	}
	dataOff := int(binary.LittleEndian.Uint16(sec[20:22]))
	if dataOff < lzmaGUIDDefinedHdr || dataOff > len(sec) {
		return nil, fmt.Errorf("bad data offset %d", dataOff)
	}
	payload := bytes.NewReader(sec[dataOff:])

	var r io.Reader
	var err error
	switch {
	case bytes.Equal(sec[4:20], lzmaGUID):
		r, err = lzma.NewReader(payload)
	case bytes.Equal(sec[4:20], qcomGzipGUID):
		r, err = gzip.NewReader(payload)
	default:
		return nil, fmt.Errorf("unknown compressor GUID %s", guidString(sec[4:20]))
	}
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(r)
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return out, nil // a truncated tail still yields usable leading modules
}

// ucs2 decodes the NUL-terminated UCS-2 string a UI section holds.
func ucs2(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

func isBlank(b []byte) bool {
	for _, c := range b {
		if c != 0xff {
			return false
		}
	}
	return true
}

func align4(n int) int { return (n + 3) &^ 3 }
func align8(n int) int { return (n + 7) &^ 7 }
