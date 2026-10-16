package vendor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

const (
	splashMagic  = "splash\x00\x00"
	splashEntry  = 52
	splashHeader = 16
)

type splashImage struct {
	Name, Type string
	Off, Size  uint32
	W, H       uint32
}

// ParseSplash reads the image table of a head-unit splash container: "splash",
// an entry count, then fixed 52-byte entries (name[20], offset, size, width,
// height, a word, type[12]) whose offsets are from the start of the file.
func ParseSplash(b []byte) ([]splashImage, error) {
	if len(b) < splashHeader || !bytes.HasPrefix(b, []byte(splashMagic)) {
		return nil, errors.New("not a splash container")
	}
	n := int(binary.LittleEndian.Uint32(b[8:]))
	if n <= 0 || splashHeader+n*splashEntry > len(b) {
		return nil, errors.New("splash: bad entry count")
	}
	cstr := func(p []byte) string { return string(bytes.TrimRight(p, "\x00")) }
	out := make([]splashImage, n)
	for i := range out {
		e := b[splashHeader+i*splashEntry:]
		le := binary.LittleEndian
		out[i] = splashImage{
			Name: cstr(e[:20]), Off: le.Uint32(e[20:]), Size: le.Uint32(e[24:]),
			W: le.Uint32(e[28:]), H: le.Uint32(e[32:]), Type: cstr(e[40:52]),
		}
	}
	return out, nil
}

// CarveExpanders implements Carver: a splash container's images as members.
func (hkmc) CarveExpanders() []carve.Expander {
	return []carve.Expander{{
		Kind:  "splash",
		Match: func(_ *carve.Node, head []byte) bool { return bytes.HasPrefix(head, []byte(splashMagic)) },
		Expand: func(n *carve.Node) ([]*carve.Node, error) {
			ra, err := n.ReaderAt()
			if err != nil {
				return nil, err
			}
			head := make([]byte, 64<<10)
			k, _ := ra.ReadAt(head, 0)
			imgs, err := ParseSplash(head[:k])
			if err != nil {
				return nil, err
			}
			var out []*carve.Node
			for _, im := range imgs {
				if int64(im.Off)+int64(im.Size) > n.Size {
					continue
				}
				name := im.Name
				if strings.EqualFold(im.Type, "JPEG") {
					name += ".jpg"
				}
				out = append(out, carve.FromReaderAt(name, io.NewSectionReader(ra, int64(im.Off), int64(im.Size)), int64(im.Size)))
			}
			return out, nil
		},
	}}
}
