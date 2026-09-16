package payload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Known bootloader, firmware, and core recovery partitions to extract when dumping an OTA.
var DefaultBootloaderPartitions = []string{
	"xbl", "xbl_config", "abl", "tz", "hyp", "devcfg",
	"keymaster", "cmnlib", "cmnlib64", "qupfw", "uefisecapp",
	"featenabler", "modem", "dsp", "bluetooth",
	"boot", "vendor_boot", "init_boot", "vendor_kernel_boot",
	"dtbo", "vbmeta", "vbmeta_system", "vbmeta_vendor",
	"preloader", "lk", "tee", "md1img", "spmfw", "scp", "sspm",
	// Google Tensor & Pixel firmware stages:
	"bl31", "gsa_bl1", "gsa_fw", "tzsw", "pvmfw",
	"cpm", "dbc", "dbl", "dram_phy", "gc", "gdmc", "cap",
}

// IsBootloaderPartition reports if a partition name matches known firmware/boot partitions.
func IsBootloaderPartition(name string) bool {
	clean := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(name, "_a"), "_b"))
	if strings.HasPrefix(clean, "dram_init") {
		return true
	}
	for _, p := range DefaultBootloaderPartitions {
		if clean == p {
			return true
		}
	}
	return false
}

// ExtractPartition extracts all extents of a single partition into an io.WriterAt.
func (p *Payload) ExtractPartition(ctx context.Context, part *PartitionUpdate, w io.WriterAt) error {
	for i, op := range part.GetOperations() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.runOp(op, w); err != nil {
			return fmt.Errorf("partition %q operation %d (%s): %w", part.GetPartitionName(), i, op.GetType(), err)
		}
	}
	return nil
}

func (p *Payload) runOp(op *InstallOperation, out io.WriterAt) error {
	switch op.GetType() {
	case InstallOperation_REPLACE,
		InstallOperation_REPLACE_BZ,
		InstallOperation_REPLACE_XZ,
		InstallOperation_ZSTD:
		return p.runReplace(op, out)
	case InstallOperation_ZERO,
		InstallOperation_DISCARD:
		return p.runZero(op, out)
	default:
		return fmt.Errorf("unsupported operation type %s (delta updates not supported)", op.GetType())
	}
}

func (p *Payload) runReplace(op *InstallOperation, out io.WriterAt) error {
	dst := op.GetDstExtents()
	if len(dst) == 0 {
		return fmt.Errorf("missing dst_extents")
	}
	expected := int64(totalBlocks(dst) * p.blockSize)
	w, err := newExtentsWriter(out, dst, p.blockSize)
	if err != nil {
		return err
	}

	secReader := io.NewSectionReader(p.ra, p.dataOffset+int64(op.GetDataOffset()), int64(op.GetDataLength()))
	var rd io.ReadCloser

	switch op.GetType() {
	case InstallOperation_REPLACE:
		rd = readCloser{Reader: secReader}
	case InstallOperation_REPLACE_BZ:
		rd = newBzip2Reader(secReader)
	case InstallOperation_REPLACE_XZ:
		var xzErr error
		rd, xzErr = newXZReader(secReader)
		if xzErr != nil {
			return xzErr
		}
	case InstallOperation_ZSTD:
		var zstdErr error
		rd, zstdErr = newZstdReader(secReader)
		if zstdErr != nil {
			return zstdErr
		}
	}

	n, err := io.Copy(w, rd)
	rd.Close()
	if err != nil {
		return fmt.Errorf("decompressing operation data: %w", err)
	}
	if n < expected {
		rem := expected - n
		if _, err := io.CopyN(w, zeroReader{}, rem); err != nil {
			return fmt.Errorf("zero padding extents: %w", err)
		}
	} else if n > expected {
		return fmt.Errorf("wrote %d bytes, expected %d bytes", n, expected)
	}
	return nil
}

func (p *Payload) runZero(op *InstallOperation, out io.WriterAt) error {
	dst := op.GetDstExtents()
	if len(dst) == 0 {
		return fmt.Errorf("missing dst_extents")
	}
	expected := int64(totalBlocks(dst) * p.blockSize)
	w, err := newExtentsWriter(out, dst, p.blockSize)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(w, zeroReader{}, expected); err != nil {
		return fmt.Errorf("writing zeros: %w", err)
	}
	return nil
}

type bufferWriterAt struct {
	buf []byte
}

func (b *bufferWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	end := int(off) + len(p)
	if end > len(b.buf) {
		newBuf := make([]byte, end)
		copy(newBuf, b.buf)
		b.buf = newBuf
	}
	copy(b.buf[off:], p)
	return len(p), nil
}

// ExtractPartitionToBytes extracts a named partition entirely into memory.
func (p *Payload) ExtractPartitionToBytes(ctx context.Context, name string) ([]byte, error) {
	part := p.Partition(name)
	if part == nil {
		return nil, fmt.Errorf("partition %q not found in payload", name)
	}
	size := part.GetNewPartitionInfo().GetSize()
	b := &bufferWriterAt{buf: make([]byte, size)}
	if err := p.ExtractPartition(ctx, part, b); err != nil {
		return nil, err
	}
	if size > 0 && uint64(len(b.buf)) > size {
		b.buf = b.buf[:size]
	}
	return b.buf, nil
}

// ExtractPartitionToFile extracts a named partition directly to a destination file path.
func (p *Payload) ExtractPartitionToFile(ctx context.Context, name string, destPath string) error {
	part := p.Partition(name)
	if part == nil {
		return fmt.Errorf("partition %q not found in payload", name)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if size := part.GetNewPartitionInfo().GetSize(); size > 0 {
		_ = f.Truncate(int64(size))
	}

	if err := p.ExtractPartition(ctx, part, f); err != nil {
		_ = os.Remove(destPath)
		return err
	}
	return nil
}

// ExtractPartitions extracts the requested list of partitions into destDir,
// returning a map of partition_name -> extracted_file_path.
func (p *Payload) ExtractPartitions(ctx context.Context, destDir string, names []string) (map[string]string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	results := make(map[string]string, len(names))
	for _, name := range names {
		part := p.Partition(name)
		if part == nil {
			continue
		}
		outPath := filepath.Join(destDir, name+".img")
		if err := p.ExtractPartitionToFile(ctx, name, outPath); err != nil {
			return nil, err
		}
		results[name] = outPath
	}
	return results, nil
}

// ExtractBootloaderPartitions selectively extracts all recognized bootloader
// partitions into destDir, ignoring bulk OS partitions (super, system, vendor, product).
func (p *Payload) ExtractBootloaderPartitions(ctx context.Context, destDir string) (map[string]string, error) {
	var bootParts []string
	for _, name := range p.Partitions() {
		if IsBootloaderPartition(name) {
			bootParts = append(bootParts, name)
		}
	}
	return p.ExtractPartitions(ctx, destDir, bootParts)
}
