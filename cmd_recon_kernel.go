package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
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
		return !notKernelExt[filepath.Ext(b)] // image.dat is a key file, image.png a picture
	}
	return false
}

// notKernelExt are the extensions of files that are never a kernel, whatever they are called.
var notKernelExt = map[string]bool{
	".dat": true, ".txt": true, ".md": true, ".png": true, ".jpg": true, ".jpeg": true, ".webp": true, ".gif": true,
	".bmp": true, ".svg": true, ".ini": true, ".cfg": true, ".conf": true, ".json": true, ".xml": true, ".hex": true,
	".log": true, ".zip": true, ".tar": true, ".html": true, ".csv": true, ".sha256": true, ".sig": true,
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
		// No header: a kernel by its name (forced), or by what is in it.
		if _, ok := bootimg.FindBanner(data); !ok || !(forced || bootimg.IsRawKernel(data)) {
			return false, nil
		}
	}
	for _, l := range lines {
		fmt.Println("  " + l)
	}
	return true, nil
}

// looksBinaryKernelSized says head could be the start of a kernel by what it is, when only its name says
// so: not text, and not a few bytes.
func looksBinaryKernelSized(head []byte) bool {
	if len(head) < 64 {
		return false
	}
	ok, _ := filetype.Text(head)
	return !ok
}

// kernelLabel is a type label for a kernel recognised by its header or its name.
func kernelLabel(name string, head []byte) (string, bool) {
	switch {
	case bootimg.IsAArch64Image(head):
		return "ARM64 Linux kernel", true
	case bootimg.IsZImage(head):
		return "ARM zImage", true
	case kernelNamed(name) && !highEntropy(head) && looksBinaryKernelSized(head):
		return "Linux kernel image", true
	}
	return "", false
}
