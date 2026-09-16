package payload

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

type payloadCloser struct {
	*Payload
	closers []io.Closer
	tmpFile string
}

func (c *payloadCloser) Close() error {
	var firstErr error
	for _, cl := range c.closers {
		if err := cl.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.tmpFile != "" {
		if err := os.Remove(c.tmpFile); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// OpenZip opens an OTA .zip package, locates payload.bin, and returns a *Payload.
// If payload.bin was stored uncompressed in the zip, it streams directly via io.ReaderAt
// without writing anything to disk. If deflated, it unpacks payload.bin to a temp file.
func OpenZip(zipPath string) (*Payload, io.Closer, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening zip %s: %w", zipPath, err)
	}

	var targetFile *zip.File
	// 1. Content inspection first: look for the "CrAU" payload magic in any member
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if rc, err := f.Open(); err == nil {
			var magic [4]byte
			n, _ := io.ReadFull(rc, magic[:])
			rc.Close()
			if n == 4 && string(magic[:]) == HeaderMagic {
				targetFile = f
				break
			}
		}
	}

	// 2. Last resort only: match on filename payload.bin
	if targetFile == nil {
		for _, f := range zr.File {
			if f.Name == "payload.bin" {
				targetFile = f
				break
			}
		}
	}

	if targetFile == nil {
		zr.Close()
		return nil, nil, fmt.Errorf("payload.bin not found in zip %s", zipPath)
	}

	// Case 1: Stored uncompressed (standard for OTA zips)
	if targetFile.Method == zip.Store {
		rawFile, err := os.Open(zipPath)
		if err != nil {
			zr.Close()
			return nil, nil, err
		}
		dataOffset, err := targetFile.DataOffset()
		if err != nil {
			rawFile.Close()
			zr.Close()
			return nil, nil, fmt.Errorf("getting payload.bin offset: %w", err)
		}
		secReader := io.NewSectionReader(rawFile, dataOffset, int64(targetFile.UncompressedSize64))
		p, err := NewFromReaderAt(secReader, int64(targetFile.UncompressedSize64))
		if err != nil {
			rawFile.Close()
			zr.Close()
			return nil, nil, err
		}
		closer := &payloadCloser{
			Payload: p,
			closers: []io.Closer{rawFile, zr},
		}
		return p, closer, nil
	}

	// Case 2: Deflated in zip (rare, but supported via temp file)
	rc, err := targetFile.Open()
	if err != nil {
		zr.Close()
		return nil, nil, fmt.Errorf("opening payload.bin in zip: %w", err)
	}
	defer rc.Close()

	tmp, err := os.CreateTemp("", "payload-*.bin")
	if err != nil {
		zr.Close()
		return nil, nil, fmt.Errorf("creating temp file: %w", err)
	}

	size, err := io.Copy(tmp, rc)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		zr.Close()
		return nil, nil, fmt.Errorf("extracting payload.bin: %w", err)
	}

	p, err := NewFromReaderAt(tmp, size)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		zr.Close()
		return nil, nil, err
	}

	closer := &payloadCloser{
		Payload: p,
		closers: []io.Closer{tmp, zr},
		tmpFile: tmp.Name(),
	}
	return p, closer, nil
}

