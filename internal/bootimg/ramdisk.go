package bootimg

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// Codec names the compression a ramdisk blob used, for reporting.
type Codec string

const (
	CodecGzip  Codec = "gzip"
	CodecLZ4   Codec = "lz4"
	CodecXZ    Codec = "xz"
	CodecLZMA  Codec = "lzma"
	CodecZstd  Codec = "zstd"
	CodecBzip2 Codec = "bzip2"
	CodecNone  Codec = "none" // already a plain cpio
)

// magic prefixes, longest-first where they could overlap.
var (
	magicGzip  = []byte{0x1f, 0x8b}
	magicLZ4   = []byte{0x04, 0x22, 0x4d, 0x18} // lz4 frame
	magicLZ4Lg = []byte{0x02, 0x21, 0x4c, 0x18} // legacy lz4 frame (older Android)
	magicXZ    = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	magicZstd  = []byte{0x28, 0xb5, 0x2f, 0xfd}
	magicBzip2 = []byte{'B', 'Z', 'h'}
	magicLZMA  = []byte{0x5d, 0x00, 0x00}        // raw lzma alone: props 0x5d, then dict size
	magicCpio  = []byte{'0', '7', '0', '7', '0'} // newc/odc cpio ascii header
)

// DetectCodec identifies a ramdisk blob's compression from its magic.
func DetectCodec(b []byte) Codec {
	switch {
	case bytes.HasPrefix(b, magicGzip):
		return CodecGzip
	case bytes.HasPrefix(b, magicLZ4) || bytes.HasPrefix(b, magicLZ4Lg):
		return CodecLZ4
	case bytes.HasPrefix(b, magicXZ):
		return CodecXZ
	case bytes.HasPrefix(b, magicZstd):
		return CodecZstd
	case bytes.HasPrefix(b, magicBzip2):
		return CodecBzip2
	case bytes.HasPrefix(b, magicCpio):
		return CodecNone
	case bytes.HasPrefix(b, magicLZMA):
		return CodecLZMA
	default:
		return ""
	}
}

// DecompressRamdisk returns the plain cpio bytes of a ramdisk blob and the codec
// it detected. An unrecognized blob is an error rather than a guess, since the
// downstream cpio parser would only produce noise from the wrong codec.
func DecompressRamdisk(b []byte) ([]byte, Codec, error) {
	codec := DetectCodec(b)
	var r io.Reader
	switch codec {
	case CodecNone:
		return b, codec, nil
	case CodecGzip:
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, codec, err
		}
		r = zr
	case CodecLZ4:
		r = lz4.NewReader(bytes.NewReader(b))
	case CodecXZ:
		xr, err := xz.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, codec, err
		}
		r = xr
	case CodecLZMA:
		// Handled by xz's lzma reader; imported lazily to keep the switch flat.
		return decompressLZMA(b)
	case CodecZstd:
		zr, err := zstd.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, codec, err
		}
		defer zr.Close()
		out, err := io.ReadAll(zr)
		return out, codec, err
	case CodecBzip2:
		r = bzip2.NewReader(bytes.NewReader(b))
	default:
		return nil, "", fmt.Errorf("unrecognized ramdisk compression (magic %x)", b[:min(len(b), 4)])
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, codec, fmt.Errorf("%s decompress: %w", codec, err)
	}
	return out, codec, nil
}

// decompressLZMA handles a raw .lzma (alone) stream, the codec some older Android
// ramdisks used. Kept apart so the xz/lzma import stays out of the main switch.
func decompressLZMA(b []byte) ([]byte, Codec, error) {
	lr, err := lzma.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, CodecLZMA, err
	}
	out, err := io.ReadAll(lr)
	if err != nil {
		return nil, CodecLZMA, fmt.Errorf("lzma decompress: %w", err)
	}
	return out, CodecLZMA, nil
}
