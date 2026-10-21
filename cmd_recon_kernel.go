package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// kernelReadCap bounds how much of a file is read to report on a kernel: more than
// any kernel image, less than a partition.
const kernelReadCap = 128 << 20

// kernelNamed says a file's name is the conventional one of a kernel image: how a
// raw ARM Image, which has no header to know it by, is told from other binaries.
func kernelNamed(path string) bool {
	switch b := strings.ToLower(filepath.Base(path)); {
	case b == "image", b == "zimage", b == "uimage", b == "vmlinux", b == "vmlinuz", b == "kernel.out":
		return true
	case strings.HasPrefix(b, "image."), strings.HasPrefix(b, "vmlinux."), strings.HasPrefix(b, "zimage."):
		return true
	}
	return false
}

// reconKernel reports on a Linux kernel: an AArch64 Image, an ARM zImage, or (when
// forced by its name) a raw image, by its version banner. It prints nothing and
// returns false for a file with no banner and no kernel header.
func reconKernel(path string, forced bool) (bool, error) {
	f, err := infile.Stat(path)
	if err != nil {
		return false, err
	}
	if f.Size() > kernelReadCap {
		return false, nil
	}
	data, err := infile.ReadFile(path)
	if err != nil {
		return false, err
	}
	lines := bootimg.Describe(data)
	known := bootimg.IsZImage(data) || bootimg.IsAArch64Image(data)
	if !known {
		if _, ok := bootimg.FindBanner(data); !ok || !forced {
			return false, nil
		}
	}
	for _, l := range lines {
		fmt.Println("  " + l)
	}
	return true, nil
}

// kernelLabel is a type label for a kernel recognised by its header or its name.
func kernelLabel(name string, head []byte) (string, bool) {
	switch {
	case bootimg.IsAArch64Image(head):
		return "ARM64 Linux kernel", true
	case bootimg.IsZImage(head):
		return "ARM zImage", true
	case kernelNamed(name) && !highEntropy(head):
		return "Linux kernel image", true
	}
	return "", false
}
