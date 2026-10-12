package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"regexp"
)

var qdbBaseline = regexp.MustCompile(`<Baseline>\s*(?:QC_IMAGE_VERSION_STRING=)?(\S+)\s*<\\Baseline>`)

// qdbNote summarizes a Qshrink hash database (qdsp6m.qdb), which maps the
// modem's compressed F3 log hashes back to their message strings. The image
// is a 0x40-byte header (magic, then the database GUID the firmware embeds)
// and a zlib stream; only its first block, which names the baseline build,
// is read.
func qdbNote(data []byte) string {
	const hdr = 0x40
	if len(data) < hdr || !bytes.HasPrefix(data, []byte("\x7fQDB")) {
		return ""
	}
	g := data[4:20]
	note := fmt.Sprintf("Qshrink hash db, GUID %x-%x-%x-%x-%x", g[0:4], g[4:6], g[6:8], g[8:10], g[10:16])
	zr, err := zlib.NewReader(bytes.NewReader(data[hdr:]))
	if err != nil {
		return note
	}
	head, _ := io.ReadAll(io.LimitReader(zr, 8<<10))
	if m := qdbBaseline.FindSubmatch(head); m != nil {
		note += ", baseline " + string(m[1])
	}
	return note
}
