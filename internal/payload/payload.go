package payload

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// Payload represents an opened Android OTA payload.bin.
type Payload struct {
	header     Header
	manifest   *DeltaArchiveManifest
	ra         io.ReaderAt
	size       int64
	dataOffset int64
	blockSize  uint64
}

// NewFromReaderAt initializes a Payload from an io.ReaderAt and its total byte size.
func NewFromReaderAt(ra io.ReaderAt, size int64) (*Payload, error) {
	header, err := ReadHeader(io.NewSectionReader(ra, 0, size))
	if err != nil {
		return nil, err
	}

	metadataLen := int64(HeaderLen) + int64(header.ManifestLen) + int64(header.MetadataSignatureLen)
	if int64(header.ManifestLen) < 0 || metadataLen < HeaderLen || metadataLen > size {
		return nil, fmt.Errorf("corrupt payload metadata sizes (manifest=%d, signature=%d, total=%d)",
			header.ManifestLen, header.MetadataSignatureLen, size)
	}

	manifestBuf := make([]byte, header.ManifestLen)
	if _, err := io.ReadFull(io.NewSectionReader(ra, HeaderLen, int64(header.ManifestLen)), manifestBuf); err != nil {
		return nil, fmt.Errorf("reading manifest bytes: %w", err)
	}

	manifest := &DeltaArchiveManifest{}
	if err := proto.Unmarshal(manifestBuf, manifest); err != nil {
		return nil, fmt.Errorf("unmarshaling manifest protobuf: %w", err)
	}

	blockSize := uint64(manifest.GetBlockSize())
	if blockSize == 0 {
		blockSize = 4096
	}

	return &Payload{
		header:     header,
		manifest:   manifest,
		ra:         ra,
		size:       size,
		dataOffset: metadataLen,
		blockSize:  blockSize,
	}, nil
}

func (p *Payload) Header() Header {
	return p.header
}

func (p *Payload) Manifest() *DeltaArchiveManifest {
	return p.manifest
}

func (p *Payload) BlockSize() uint64 {
	return p.blockSize
}

// Partitions returns the list of partition names in the payload manifest.
func (p *Payload) Partitions() []string {
	names := make([]string, 0, len(p.manifest.GetPartitions()))
	for _, part := range p.manifest.GetPartitions() {
		names = append(names, part.GetPartitionName())
	}
	return names
}

// Partition returns the PartitionUpdate entry for a named partition, or nil if not present.
func (p *Payload) Partition(name string) *PartitionUpdate {
	for _, part := range p.manifest.GetPartitions() {
		if part.GetPartitionName() == name {
			return part
		}
	}
	return nil
}

// IsDelta reports whether this payload requires existing source partitions to apply.
func (p *Payload) IsDelta() bool {
	if p.manifest.GetMinorVersion() != 0 || p.manifest.GetPartialUpdate() {
		return true
	}
	for _, part := range p.manifest.GetPartitions() {
		for _, op := range part.GetOperations() {
			if len(op.GetSrcExtents()) > 0 {
				return true
			}
			switch op.GetType() {
			case InstallOperation_MOVE,
				InstallOperation_BSDIFF,
				InstallOperation_SOURCE_COPY,
				InstallOperation_SOURCE_BSDIFF,
				InstallOperation_BROTLI_BSDIFF,
				InstallOperation_PUFFDIFF,
				InstallOperation_ZUCCHINI,
				InstallOperation_LZ4DIFF_BSDIFF,
				InstallOperation_LZ4DIFF_PUFFDIFF:
				return true
			}
		}
	}
	return false
}

