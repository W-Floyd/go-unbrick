package vendor

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"regexp"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// Facts read from a Hyundai/Kia head-unit package's plain-text members and its
// decrypted boot image.
var (
	KernelVersion = facts.Key[string]("kernel_version")
	KernelCmdline = facts.Key[string]("kernel_cmdline")
	// DebugBuild is ro.debuggable from the ramdisk's default.prop.
	DebugBuild  = facts.Key[bool]("debug_build")
	GPSFirmware = facts.Key[string]("gps_firmware")
)

var swVersionRe = regexp.MustCompile(`(?m)^SWVERSION\s*-\s*(\S+)`)

// ParseUpdateInfo returns the SWVERSION an update.info declares.
func ParseUpdateInfo(b []byte) string {
	if m := swVersionRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// ParseModemVersion reads a modem_version.txt ("boot:01J_BBOOT, modem:01T_WVZW,
// gw:37") as "01T_WVZW [boot 01J_BBOOT, gw 37]": the modem build first, the
// rest of the sheet after it.
func ParseModemVersion(b []byte) string {
	var modem string
	var rest []string
	for _, f := range strings.Split(string(b), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(f), ":")
		switch {
		case !ok:
		case k == "modem":
			modem = v
		default:
			rest = append(rest, k+" "+v)
		}
	}
	if modem == "" {
		return ""
	}
	if len(rest) == 0 {
		return modem
	}
	return modem + " [" + strings.Join(rest, ", ") + "]"
}

// zImageMagic sits at offset 0x24 of an ARM zImage.
const zImageMagic = 0x016f2818

// ZImageKernelVersion returns the "Linux version" banner of an ARM zImage's
// gzip-compressed payload, or "".
func ZImageKernelVersion(z []byte) string {
	if len(z) < 0x28 || binary.LittleEndian.Uint32(z[0x24:]) != zImageMagic {
		return ""
	}
	i := bytes.Index(z, []byte{0x1f, 0x8b, 0x08})
	if i < 0 {
		return ""
	}
	zr, err := gzip.NewReader(bytes.NewReader(z[i:]))
	if err != nil {
		return ""
	}
	// The banner is in the first few MiB; trailing zImage bytes after the
	// stream end are not a gzip error worth reporting.
	plain, _ := io.ReadAll(io.LimitReader(zr, 64<<20))
	j := bytes.Index(plain, []byte("Linux version "))
	if j < 0 {
		return ""
	}
	banner := plain[j:]
	if k := bytes.IndexAny(banner, "\n\x00"); k >= 0 {
		banner = banner[:k]
	}
	return string(banner)
}
