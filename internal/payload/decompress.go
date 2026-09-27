package payload

import (
	"compress/bzip2"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

type readCloser struct {
	io.Reader
	closeFn func() error
}

func (rc readCloser) Close() error {
	if rc.closeFn != nil {
		return rc.closeFn()
	}
	return nil
}

func newBzip2Reader(r io.Reader) io.ReadCloser {
	return readCloser{Reader: bzip2.NewReader(r)}
}

func newZstdReader(r io.Reader) (io.ReadCloser, error) {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("creating zstd reader: %w", err)
	}
	return readCloser{
		Reader: zr,
		closeFn: func() error {
			zr.Close()
			return nil
		},
	}, nil
}

