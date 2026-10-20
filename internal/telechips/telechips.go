// Package telechips reads the boot stages Telechips TCC803x firmware ships: a
// signed-image wrapper (a "CERT" block, then an "HDR" header, then the stage) whose
// stage is aarch64 code with its own small boot header. The BL3 stage of a
// head-unit package is a U-Boot build, so beyond the wrapper this reads what that
// build says about itself: its version, its default environment, what it is built
// to do.
//
// Layout of the image (little-endian):
//
//	0x000  "CERT", then zeros: the signature block (256 bytes; empty in an eng build)
//	0x100  "HDR\0"
//	0x104  u32 payload size
//	0x108  u32 payload offset (0x1000)
//	0x110  name[16], e.g. "803xA53-BL3"
//	0x120  version[16], e.g. "0.0.0"
//	0x130  u32 load address
//	0x160  hash[32]
//	payload: b <entry>; u32 0xffff0106; "Ver:NNNN"; at 0x60 the base address,
//	         at 0x68 a tag ("BOOT"), at 0x70 the base again, at 0x78 and 0x80 the
//	         code size, at 0x88 the end of the image including bss.
package telechips

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	certSize = 0x100
	hdrOff   = 0x100
)

// IsImage reports whether head begins a Telechips signed boot image.
func IsImage(head []byte) bool {
	return len(head) >= hdrOff+4 && bytes.Equal(head[:4], []byte("CERT")) && bytes.Equal(head[hdrOff:hdrOff+4], []byte("HDR\x00"))
}

// Image is what the wrapper and the stage's own header say.
type Image struct {
	Name, Version string
	PayloadOff    uint32
	PayloadSize   uint32
	LoadAddr      uint32
	Hash          [32]byte
	Signed        bool // the CERT block holds more than its magic

	// The stage's boot header.
	StageVer string // "Ver:1234": a placeholder in the sources, not a version
	Tag      string
	Base     uint32
	CodeSize uint32
	EndSize  uint32

	// What a U-Boot stage says about itself.
	UBoot    string            // "U-Boot 2020.01 (Jan 07 2026 - 17:20:41 +0900)"
	Compiler string            // the toolchain's banner
	Env      map[string]string // default environment: bootargs, bootcmd, board_id, ...
	Features []string          // what it is built to do: "AVB", "fastboot", ...
}

// Header reads the wrapper from the start of an image: the first 0x180 bytes are
// enough, so a file's head identifies it without reading it all.
func Header(head []byte) (*Image, error) {
	if !IsImage(head) {
		return nil, errors.New("not a Telechips boot image")
	}
	if len(head) < hdrOff+0x180 {
		return nil, errors.New("telechips: header truncated")
	}
	le := binary.LittleEndian
	im := &Image{
		Name:        cstr(head[hdrOff+0x10 : hdrOff+0x20]),
		Version:     cstr(head[hdrOff+0x20 : hdrOff+0x30]),
		PayloadSize: le.Uint32(head[hdrOff+4:]),
		PayloadOff:  le.Uint32(head[hdrOff+8:]),
		LoadAddr:    le.Uint32(head[hdrOff+0x30:]),
		Signed:      !allZero(head[4:certSize]),
	}
	copy(im.Hash[:], head[hdrOff+0x60:hdrOff+0x80])
	return im, nil
}

// Parse reads a whole image: the wrapper, the stage's header, and what a U-Boot
// stage says about itself.
func Parse(data []byte) (*Image, error) {
	im, err := Header(data)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	end := int64(im.PayloadOff) + int64(im.PayloadSize)
	if im.PayloadOff < hdrOff+0x180 || end > int64(len(data)) {
		return nil, fmt.Errorf("telechips: payload %#x+%#x outside the %#x byte image", im.PayloadOff, im.PayloadSize, len(data))
	}
	p := data[im.PayloadOff:end]
	if len(p) >= 0x90 {
		if bytes.HasPrefix(p[8:], []byte("Ver:")) {
			im.StageVer = cstr(p[8:0x20])
		}
		im.Tag = cstr(p[0x68:0x70])
		im.Base = le.Uint32(p[0x60:])
		im.CodeSize = le.Uint32(p[0x78:])
		im.EndSize = le.Uint32(p[0x88:])
	}
	im.readUBoot(p)
	return im, nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

var (
	ubootRE    = regexp.MustCompile(`^U-Boot \d{4}\.\d{2}[^\n]*\(\w{3} +\d+ \d{4} - [\d:]+ [+-]\d{4}\)`)
	compilerRE = regexp.MustCompile(`^\S*-gcc \(`)
	envKeys    = map[string]bool{
		"bootargs": true, "bootcmd": true, "bootdelay": true, "board_id": true, "bootdev": true, "bootpart": true,
		"miscpart": true, "fdtpart": true, "kerneladdr": true, "fdt_addr": true, "overlay_addr": true, "baudrate": true,
		"preboot": true, "fastbootcmd": true, "recoverycmd": true, "avb_verify": true,
	}
	// features are what to look for, and what to call it.
	features = []struct{ needle, name string }{
		{"lib/libavb/avb_rsa.c", "Android Verified Boot (libavb)"},
		{"ab_select_slot", "A/B slots"},
		{"Android Fastboot", "fastboot"},
		{"fastboot_mmc_flash_write", "fastboot flashing"},
		{"flashing unlock", "flashing unlock"},
		{"oem format", "oem format"},
		{"avb is_unlocked", "AVB lock state"},
		{"OPTEE management in bootloader", "OP-TEE"},
		{"dtimg ", "DT overlays (dtbo)"},
		{"gpt_verify_headers", "GPT"},
		{"drivers/usb/dwc3/gadget.c", "USB gadget (dwc3)"},
		{"tcc_lcd_interface_probe", "LCD init"},
		{"U-Boot Boot Menu", "boot menu"},
	}
)

// readUBoot scans the stage's strings for the U-Boot banner, the toolchain, the
// default environment and the features.
func (im *Image) readUBoot(p []byte) {
	im.Env = map[string]string{}
	have := map[string]bool{}
	for _, s := range printableRuns(p, 4) {
		switch {
		case im.UBoot == "" && ubootRE.MatchString(s):
			im.UBoot = s
		case im.Compiler == "" && compilerRE.MatchString(s):
			im.Compiler = s
		}
		if k, v, ok := strings.Cut(s, "="); ok && envKeys[k] {
			// The environment block repeats a few keys (bootcmd twice: a stub and the
			// real one); the longest is the one that does something.
			if len(v) > len(im.Env[k]) {
				im.Env[k] = v
			}
		}
		for _, f := range features {
			if !have[f.name] && strings.Contains(s, f.needle) {
				have[f.name] = true
				im.Features = append(im.Features, f.name)
			}
		}
	}
}

// printableRuns is the runs of printable ASCII of at least min bytes.
func printableRuns(b []byte, min int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(b); i++ {
		printable := i < len(b) && (b[i] >= 0x20 && b[i] < 0x7f || b[i] == '\t')
		switch {
		case printable && start < 0:
			start = i
		case !printable && start >= 0:
			if i-start >= min {
				out = append(out, string(b[start:i]))
			}
			start = -1
		}
	}
	return out
}

// Report is what recon says about a whole image, as lines.
func (im *Image) Report() []string {
	size := func(n uint32) string { return fmt.Sprintf("%.1f KiB", float64(n)/1024) }
	sig := "none (CERT block empty)"
	if im.Signed {
		sig = "present"
	}
	out := []string{
		fmt.Sprintf("Image: %s %s, payload %s at 0x%x, load 0x%08x", im.Name, im.Version, size(im.PayloadSize), im.PayloadOff, im.LoadAddr),
		fmt.Sprintf("Signature: %s; header hash %x…", sig, im.Hash[:8]),
	}
	if im.Tag != "" {
		out = append(out, fmt.Sprintf("Stage: %s at 0x%08x, code %s, %s with bss", im.Tag, im.Base, size(im.CodeSize), size(im.EndSize)))
	}
	if im.UBoot != "" {
		out = append(out, "Bootloader: "+im.UBoot)
	}
	if im.Compiler != "" {
		out = append(out, "Built with: "+im.Compiler)
	}
	if len(im.Features) > 0 {
		out = append(out, "Built to: "+strings.Join(im.Features, ", "))
	}
	if len(im.Env) > 0 {
		keys := make([]string, 0, len(im.Env))
		for k := range im.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out = append(out, "Default environment:")
		for _, k := range keys {
			v := im.Env[k]
			if len(v) > 110 {
				v = v[:110] + fmt.Sprintf("… (%d chars)", len(v))
			}
			out = append(out, "  "+k+"="+v)
		}
	}
	return out
}
