package vendor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// fsgVariants reads an FSGADAPT image (fs_image.tar.gz.mbn.img): a table of
// 64-byte entries "FSG_000N" + a board ID, each pointing at that board's
// modem EFS golden copy. It returns the board IDs, or nil if data is not one.
func fsgVariants(data []byte) []string {
	if !bytes.HasPrefix(data, []byte("FSGADAPT")) {
		return nil
	}
	var ids []string
	for o := 8; o+24 <= len(data) && bytes.HasPrefix(data[o:], []byte("FSG_")); o += 64 {
		ids = append(ids, strings.TrimSpace(string(bytes.TrimRight(data[o+8:o+24], "\x00"))))
	}
	return ids
}

func fsgArtifact(data []byte) (ArtifactInfo, bool) {
	ids := fsgVariants(data)
	if ids == nil {
		return ArtifactInfo{}, false
	}
	return ArtifactInfo{Label: "modem EFS (FSG) image", Detail: fmt.Sprintf("%d board variant(s): %s", len(ids), strings.Join(ids, ", "))}, true
}

// qcomArtifact recognises Qualcomm's own images by their magic: a non-ELF boot
// image (sbl1.mbn: the 0x844bdcd1 header) and the partition table (partition.mbn:
// 0xaa7d1b9a). Both are little-endian words at the start of the file.
func qcomArtifact(data []byte) (ArtifactInfo, bool) {
	if len(data) < 4 {
		return ArtifactInfo{}, false
	}
	switch binary.LittleEndian.Uint32(data[:4]) {
	case 0x844bdcd1:
		return ArtifactInfo{Label: "Qualcomm MBN"}, true
	case 0xaa7d1b9a:
		return ArtifactInfo{Label: "Qualcomm partition table"}, true
	}
	return ArtifactInfo{}, false
}
