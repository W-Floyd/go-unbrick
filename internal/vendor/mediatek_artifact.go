package vendor

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
)

// MediaTek's partition image header: magic, data size, part name, and an
// extended header giving its own size and the part alignment. Images are
// parts concatenated (scp.img: tinysys-loader, then tinysys-scp).
var (
	mtkImageMagic = []byte{0x88, 0x16, 0x88, 0x58}
	mtkExtMagic   = []byte{0x89, 0x16, 0x89, 0x58}
)

// mtkParts lists the part names whose headers data holds.
func mtkParts(data []byte) []string {
	var names []string
	for o := 0; o+0x48 <= len(data) && bytes.HasPrefix(data[o:], mtkImageMagic); {
		le := binary.LittleEndian
		h := data[o:]
		names = append(names, cstrN(h[8:40]))
		size := int(le.Uint32(h[4:]))
		hdr, align, last := 512, 1, false
		if bytes.Equal(h[0x30:0x34], mtkExtMagic) {
			hdr, last = int(le.Uint32(h[0x34:])), le.Uint32(h[0x40:]) != 0
			if a := int(le.Uint32(h[0x44:])); a > 0 {
				align = a
			}
		}
		if last || hdr <= 0 {
			break
		}
		o += hdr + (size+align-1)/align*align
	}
	return names
}

// mollyRe finds a MediaTek modem build (MOLY.LR12A.R3.MP.V255.5).
var mollyRe = regexp.MustCompile(`MOLY\.[A-Za-z0-9._]+`)

func mediatekArtifact(data []byte) (ArtifactInfo, bool) {
	switch {
	case bytes.HasPrefix(data, mtkImageMagic):
		return ArtifactInfo{Label: "MediaTek image", Detail: strings.Join(mtkParts(data), " + ")}, true
	case bytes.HasPrefix(data, []byte("MTK_DOWNLOAD_AGENT")):
		info := ArtifactInfo{Label: "MediaTek Download Agent"}
		if len(data) >= 0x60 {
			info.Detail = cstrN(data[0x20:0x60])
		}
		return info, true
	case bytes.HasPrefix(data, []byte("MMM\x01")) && len(data) >= 0x11 && bytes.HasPrefix(data[8:], []byte("FILE_INFO")):
		return ArtifactInfo{Label: "MediaTek GFH image"}, true
	case bytes.HasPrefix(data, []byte("CATI")), bytes.HasPrefix(data, []byte("CATD")):
		info := ArtifactInfo{Label: "MediaTek modem debug database"}
		if m := mollyRe.Find(data[:min(len(data), 4096)]); m != nil {
			info.Detail = string(m)
		}
		return info, true
	}
	return ArtifactInfo{}, false
}

func cstrN(b []byte) string { return strings.TrimSpace(cstr(b)) }
