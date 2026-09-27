package payload_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"google.golang.org/protobuf/proto"

	"github.com/W-Floyd/go-unbrick/internal/payload"
)

const blockSize = 4096

func ext(start, num uint64) *payload.Extent {
	return &payload.Extent{StartBlock: proto.Uint64(start), NumBlocks: proto.Uint64(num)}
}

func sum(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}

func compressBZ2(t *testing.T, data []byte) []byte {
	t.Helper()
	// bzip2 writer: use bzip2 via bzip2 CLI or manual test block if needed.
	// Since stdlib only has bzip2.NewReader, we can test REPLACE, XZ, and ZSTD directly,
	// or create a simple bz2 fixture.
	return nil
}

func compressXZ(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func compressZSTD(t *testing.T, data []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(data, nil)
}

type opSpec struct {
	typ  payload.InstallOperation_Type
	data []byte
	dst  []*payload.Extent
}

type partSpec struct {
	name string
	size uint64
	ops  []opSpec
}

func buildTestPayload(t *testing.T, parts []partSpec) []byte {
	t.Helper()
	var blobs bytes.Buffer
	var updates []*payload.PartitionUpdate

	for _, ps := range parts {
		var ops []*payload.InstallOperation
		for _, o := range ps.ops {
			op := &payload.InstallOperation{
				Type:       o.typ.Enum(),
				DstExtents: o.dst,
			}
			if o.data != nil {
				op.DataOffset = proto.Uint64(uint64(blobs.Len()))
				op.DataLength = proto.Uint64(uint64(len(o.data)))
				op.DataSha256Hash = sum(o.data)
				blobs.Write(o.data)
			}
			ops = append(ops, op)
		}
		updates = append(updates, &payload.PartitionUpdate{
			PartitionName: proto.String(ps.name),
			Operations:    ops,
			NewPartitionInfo: &payload.PartitionInfo{
				Size: proto.Uint64(ps.size),
				Hash: sum(make([]byte, ps.size)),
			},
		})
	}

	manifest := &payload.DeltaArchiveManifest{
		BlockSize:    proto.Uint32(blockSize),
		MinorVersion: proto.Uint32(0),
		Partitions:   updates,
	}
	manifestBytes, err := proto.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	out.WriteString("CrAU")
	binary.Write(&out, binary.BigEndian, uint64(2))
	binary.Write(&out, binary.BigEndian, uint64(len(manifestBytes)))
	binary.Write(&out, binary.BigEndian, uint32(0))
	out.Write(manifestBytes)
	out.Write(blobs.Bytes())
	return out.Bytes()
}

func TestPayloadHeaderValidation(t *testing.T) {
	// Bad magic
	badMagic := []byte("XXXX12345678901234567890")
	_, err := payload.ReadHeader(bytes.NewReader(badMagic))
	if err != payload.ErrNotPayload {
		t.Fatalf("expected ErrNotPayload, got %v", err)
	}

	// Unsupported major version
	var badVer bytes.Buffer
	badVer.WriteString("CrAU")
	binary.Write(&badVer, binary.BigEndian, uint64(1)) // Version 1
	binary.Write(&badVer, binary.BigEndian, uint64(100))
	binary.Write(&badVer, binary.BigEndian, uint32(0))
	_, err = payload.ReadHeader(bytes.NewReader(badVer.Bytes()))
	if err == nil {
		t.Fatalf("expected error for version 1, got nil")
	}
}

func TestPayloadExtraction(t *testing.T) {
	rawXBL := bytes.Repeat([]byte("XBL_STAGE_CONTENT_"), 256) // 4608 bytes -> spans 2 blocks (8192 bytes)
	xzABL := compressXZ(t, bytes.Repeat([]byte("ABL_FASTBOOT_IMAGE_"), 256))
	zstdTZ := compressZSTD(t, bytes.Repeat([]byte("TRUSTZONE_SECURE_OS_"), 256))

	payloadBytes := buildTestPayload(t, []partSpec{
		{
			name: "xbl",
			size: uint64(len(rawXBL)),
			ops: []opSpec{
				{
					typ:  payload.InstallOperation_REPLACE,
					data: append(rawXBL, make([]byte, 8192-len(rawXBL))...),
					dst:  []*payload.Extent{ext(0, 2)},
				},
			},
		},
		{
			name: "abl",
			size: 4096,
			ops: []opSpec{
				{
					typ:  payload.InstallOperation_REPLACE_XZ,
					data: xzABL,
					dst:  []*payload.Extent{ext(0, 2)},
				},
			},
		},
		{
			name: "tz",
			size: 4096,
			ops: []opSpec{
				{
					typ:  payload.InstallOperation_ZSTD,
					data: zstdTZ,
					dst:  []*payload.Extent{ext(0, 2)},
				},
			},
		},
		{
			name: "system",
			size: 4096,
			ops: []opSpec{
				{
					typ:  payload.InstallOperation_REPLACE,
					data: bytes.Repeat([]byte{0x55}, 4096),
					dst:  []*payload.Extent{ext(0, 1)},
				},
			},
		},
	})

	p, err := payload.NewFromReaderAt(bytes.NewReader(payloadBytes), int64(len(payloadBytes)))
	if err != nil {
		t.Fatalf("NewFromReaderAt failed: %v", err)
	}

	if p.IsDelta() {
		t.Fatalf("expected full payload, got delta")
	}

	parts := p.Partitions()
	if len(parts) != 4 {
		t.Fatalf("expected 4 partitions, got %d: %v", len(parts), parts)
	}

	ctx := context.Background()

	// Test ExtractPartitionToBytes
	xblData, err := p.ExtractPartitionToBytes(ctx, "xbl")
	if err != nil {
		t.Fatalf("extract xbl failed: %v", err)
	}
	if !bytes.Equal(xblData[:len(rawXBL)], rawXBL) {
		t.Fatalf("xbl data mismatch")
	}

	ablData, err := p.ExtractPartitionToBytes(ctx, "abl")
	if err != nil {
		t.Fatalf("extract abl (XZ) failed: %v", err)
	}
	if len(ablData) != 4096 {
		t.Fatalf("abl size mismatch: got %d, expected 4096", len(ablData))
	}

	tzData, err := p.ExtractPartitionToBytes(ctx, "tz")
	if err != nil {
		t.Fatalf("extract tz (ZSTD) failed: %v", err)
	}
	if len(tzData) != 4096 {
		t.Fatalf("tz size mismatch: got %d, expected 4096", len(tzData))
	}

	// Test ExtractBootloaderPartitions to disk
	tmpDir := t.TempDir()
	extracted, err := p.ExtractBootloaderPartitions(ctx, tmpDir)
	if err != nil {
		t.Fatalf("ExtractBootloaderPartitions failed: %v", err)
	}

	// Ensure xbl, abl, and tz were extracted, but system was ignored
	if _, ok := extracted["xbl"]; !ok {
		t.Errorf("expected xbl in extracted bootloader partitions")
	}
	if _, ok := extracted["abl"]; !ok {
		t.Errorf("expected abl in extracted bootloader partitions")
	}
	if _, ok := extracted["tz"]; !ok {
		t.Errorf("expected tz in extracted bootloader partitions")
	}
	if _, ok := extracted["system"]; ok {
		t.Errorf("system partition should NOT be extracted as bootloader partition")
	}
}

func TestPayloadZipStreaming(t *testing.T) {
	rawXBL := bytes.Repeat([]byte("RAW_XBL_BLOCK_"), 256)
	payloadBytes := buildTestPayload(t, []partSpec{
		{
			name: "xbl",
			size: 4096,
			ops: []opSpec{
				{
					typ:  payload.InstallOperation_REPLACE,
					data: append(rawXBL, make([]byte, 4096-len(rawXBL))...),
					dst:  []*payload.Extent{ext(0, 1)},
				},
			},
		},
	})

	// Build a zip containing payload.bin stored uncompressed (Store)
	zipPath := filepath.Join(t.TempDir(), "ota_update.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	header := &zip.FileHeader{
		Name:   "payload.bin",
		Method: zip.Store,
	}
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payloadBytes); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zf.Close()

	// Test OpenZip
	p, closer, err := payload.OpenZip(zipPath)
	if err != nil {
		t.Fatalf("OpenZip failed: %v", err)
	}
	defer closer.Close()

	xblBytes, err := p.ExtractPartitionToBytes(context.Background(), "xbl")
	if err != nil {
		t.Fatalf("failed to extract xbl from zip: %v", err)
	}
	if !bytes.Equal(xblBytes[:len(rawXBL)], rawXBL) {
		t.Fatalf("extracted xbl from zip mismatch")
	}
}

// TestPartitionReaderAtMatchesFullExtract checks that the lazy ReaderAt returns
// byte-identical data to a full extraction — across operation boundaries,
// scattered extents (an op whose two output blocks land in non-adjacent
// partition blocks), a ZERO gap, and reads past the partition end (zeros).
func TestPartitionReaderAtMatchesFullExtract(t *testing.T) {
	blkA := bytes.Repeat([]byte{0xA1}, blockSize)   // block 0 (REPLACE)
	blkB := bytes.Repeat([]byte{0xB2}, 2*blockSize) // blocks 1 & 4 (REPLACE_XZ, scattered)
	blkC := bytes.Repeat([]byte{0xC3}, blockSize)   // block 5 (REPLACE)
	const nblocks = 6

	payloadBytes := buildTestPayload(t, []partSpec{{
		name: "system",
		size: nblocks * blockSize,
		ops: []opSpec{
			{typ: payload.InstallOperation_REPLACE, data: blkA, dst: []*payload.Extent{ext(0, 1)}},
			// One op, two output blocks, landing in non-adjacent partition blocks:
			// exercises the per-extent opOffset mapping.
			{typ: payload.InstallOperation_REPLACE_XZ, data: compressXZ(t, blkB), dst: []*payload.Extent{ext(1, 1), ext(4, 1)}},
			{typ: payload.InstallOperation_ZERO, dst: []*payload.Extent{ext(2, 2)}}, // blocks 2-3 zero
			{typ: payload.InstallOperation_REPLACE, data: blkC, dst: []*payload.Extent{ext(5, 1)}},
		},
	}})

	p, err := payload.NewFromReaderAt(bytes.NewReader(payloadBytes), int64(len(payloadBytes)))
	if err != nil {
		t.Fatal(err)
	}
	want, err := p.ExtractPartitionToBytes(context.Background(), "system")
	if err != nil {
		t.Fatal(err)
	}
	ra, size, err := p.PartitionReaderAt("system")
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(want)) {
		t.Fatalf("reader size %d, want %d", size, len(want))
	}

	// Every offset/length combination must agree with the full extraction.
	for off := 0; off <= len(want); off += 500 {
		for _, l := range []int{1, blockSize - 1, blockSize + 7, 3 * blockSize} {
			buf := make([]byte, l)
			n, _ := ra.ReadAt(buf, int64(off))
			if n != l {
				t.Fatalf("ReadAt(off=%d,len=%d) n=%d", off, l, n)
			}
			exp := make([]byte, l)
			if off < len(want) {
				copy(exp, want[off:]) // past-end bytes stay zero
			}
			if !bytes.Equal(buf, exp) {
				t.Fatalf("mismatch at off=%d len=%d", off, l)
			}
		}
	}
}
