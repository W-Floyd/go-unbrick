package vendor

// Content recognition for the Hyundai/Kia head-unit package's own formats and
// the supplier firmware it carries (Trimble GPS, Micron FFU).

import (
	"bytes"
	"path/filepath"
)

func hkmcArtifact(name string, data []byte) (ArtifactInfo, bool) {
	switch {
	case bytes.HasPrefix(data, []byte("ConB")) && len(data) >= 0x28:
		info := ArtifactInfo{Label: "navi config (ConB)"}
		if n := utf16Name(data[0x28:]); n != "" {
			info.Detail = n
		}
		return info, true
	case bytes.HasPrefix(data, []byte("PRNM")) && len(data) >= 0x20:
		return ArtifactInfo{Label: "navi package (PRNM)", Detail: "built " + string(bytes.TrimRight(data[0x10:0x20], "\x00"))}, true
	case bytes.HasPrefix(data, []byte("TRMB")):
		return ArtifactInfo{Label: "Trimble GPS firmware (TRMB)"}, true
	case filepath.Base(name) == "ffu_sw.bin" && len(data) >= 0x28 && bytes.HasPrefix(data[0x20:], []byte("FQT")):
		return ArtifactInfo{Label: "Micron FFU firmware", Detail: string(bytes.TrimRight(data[0x20:0x28], "\x00"))}, true
	}
	return ArtifactInfo{}, false
}

// utf16Name reads the first NUL-terminated UTF-16LE ASCII string of b, which
// begins with a 4-byte length field before the text in ConB records.
func utf16Name(b []byte) string {
	var out []byte
	for i := 0; i+1 < len(b) && len(out) < 64; i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			break
		}
		if b[i+1] != 0 || b[i] < 0x20 || b[i] > 0x7e {
			return ""
		}
		out = append(out, b[i])
	}
	return string(out)
}
