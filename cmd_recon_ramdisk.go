package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"

	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// lz4ReconCap bounds how much of an LZ4 file is read to report on what it holds.
const lz4ReconCap = 1 << 30

// reconLZ4 reports on an LZ4 stream (frame or the older legacy format) and on what it
// decompresses to: a root filesystem (a cpio initramfs) is described, anything else is
// named by its type.
func reconLZ4(path string) error {
	f, err := infile.Stat(path)
	if err != nil {
		return err
	}
	if f.Size() > lz4ReconCap {
		fmt.Println("  too large to decompress for a report; `unbrick extract` reads it")
		return nil
	}
	data, err := infile.ReadFile(path)
	if err != nil {
		return err
	}
	var plain []byte
	if bootimg.IsLZ4Legacy(data) {
		var used int
		if plain, used, err = bootimg.DecompressLZ4Legacy(data); err != nil {
			return fmt.Errorf("lz4 (legacy): %w", err)
		}
		fmt.Printf("  Form: LZ4 legacy stream, %s compressed to %s (%.1fx)\n", humanBytes(int64(used)), humanBytes(int64(len(plain))), float64(len(plain))/float64(max(used, 1)))
		if rest := data[used:]; len(rest) > 0 {
			if allZero(rest) {
				fmt.Printf("  Then %s of zero padding\n", humanBytes(int64(len(rest))))
			} else {
				fmt.Printf("  Then %s that is not part of the stream\n", humanBytes(int64(len(rest))))
			}
		}
	} else {
		if plain, err = io.ReadAll(lz4.NewReader(bytes.NewReader(data))); err != nil {
			return fmt.Errorf("lz4: %w", err)
		}
		fmt.Printf("  Form: LZ4 frame, %s compressed to %s\n", humanBytes(int64(len(data))), humanBytes(int64(len(plain))))
	}
	if bytes.HasPrefix(plain, []byte("0707")) {
		entries, perr := bootimg.ParseCpioConcat(plain)
		if perr != nil && len(entries) == 0 {
			return fmt.Errorf("the contents look like a cpio archive but do not parse: %w", perr)
		}
		fmt.Printf("  Contents: cpio (newc) archive, the initial root filesystem\n")
		for _, l := range bootimg.DescribeRootfs(entries) {
			fmt.Println("    " + l)
		}
		fmt.Println("  (`unbrick ls -r` lists its files; `browse` opens them)")
		return nil
	}
	head := plain[:min(len(plain), 8192)]
	fmt.Printf("  Contents: %s, %s\n", typeLabel("", head), humanBytes(int64(len(plain))))
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
