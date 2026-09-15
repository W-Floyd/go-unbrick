// Package qcdt patches Qualcomm/Motorola device-tree (QCDT) blobs for cross-model
// blankflash derivation. An extended-v3 QCDT tags each dt_entry with a 32-byte
// model string, and a bootloader rejects a device-tree table whose model doesn't
// match the handset — so a sibling model's signed boot chain is refused. Stripping
// the model field (and clearing the extended flag) makes device-tree matching
// model-agnostic, so the sibling's boot chain authenticates and boots.
//
// This is needed only for the harder case: donating a boot chain from a sibling
// model. Restoring a unit from its own stock never needs it.
//
// Header (12B): magic "QCDT", u8 version, u8 extended, u16 reserved, u32 entries.
// Extended v3 dt_entry (72B): platform_id, variant_id, board_hw_subtype, soc_rev,
// pmic_rev[4], offset, size (first 40B), then char model[32].
package qcdt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

const (
	headerSize    = 12
	extEntrySize  = 72
	baseEntrySize = 40 // extended entry minus the trailing model[32]
	modelSize     = 32
)

var (
	magic         = []byte("QCDT")
	lz4FrameMagic = []byte{0x04, 0x22, 0x4d, 0x18}
)

func isLZ4Frame(b []byte) bool {
	return len(b) >= 4 && bytes.Equal(b[:4], lz4FrameMagic)
}

func isQCDT(b []byte) bool {
	return len(b) >= 4 && bytes.Equal(b[:4], magic)
}

func lz4Decompress(b []byte) ([]byte, error) {
	return io.ReadAll(lz4.NewReader(bytes.NewReader(b)))
}

// StripModel removes the model field from an extended-v3 QCDT so its device-tree
// entries match any model in the family. Input may be LZ4-framed (Motorola packs
// the blob compressed); the returned blob is decompressed. It reports changed=true
// only when it actually stripped an extended QCDT — a non-QCDT part, or a QCDT with
// no model field, yields changed=false and out=nil so the caller leaves it alone.
//
// The 32 bytes freed per entry are zero-filled rather than removed, so the total
// size and every entry's DTB offset stay valid without any rewriting.
func StripModel(data []byte) (out []byte, changed bool, err error) {
	dec := data
	if isLZ4Frame(data) {
		if dec, err = lz4Decompress(data); err != nil {
			return nil, false, fmt.Errorf("lz4 decompress: %w", err)
		}
	}
	if !isQCDT(dec) {
		return nil, false, nil
	}
	if len(dec) < headerSize {
		return nil, false, fmt.Errorf("qcdt header truncated")
	}
	version, extended := dec[4], dec[5]
	num := int(binary.LittleEndian.Uint32(dec[8:12]))
	if version != 3 || extended != 1 { // no model field to strip
		return nil, false, nil
	}
	dtStart := headerSize + num*extEntrySize
	if num < 0 || dtStart > len(dec) {
		return nil, false, fmt.Errorf("qcdt: %d entries exceed %d bytes", num, len(dec))
	}

	out = make([]byte, 0, len(dec))
	hdr := append([]byte(nil), dec[:headerSize]...)
	hdr[5] = 0 // clear extended flag
	out = append(out, hdr...)
	for i := 0; i < num; i++ {
		e := headerSize + i*extEntrySize
		out = append(out, dec[e:e+baseEntrySize]...) // keep fields, drop model[32]
	}
	out = append(out, make([]byte, num*modelSize)...) // zero-fill reclaimed space
	out = append(out, dec[dtStart:]...)               // DTB blobs untouched
	return out, true, nil
}
