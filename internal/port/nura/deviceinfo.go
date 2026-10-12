package nura

import (
	"fmt"
	"slices"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/port"
)

// Line is one deviceinfo line. Todo, when set, is why the value could not be
// derived; the line is then emitted commented out with that reason.
type Line struct {
	Key, Val string
	Why      string // where the value came from
	Todo     string
}

// Deviceinfo derives the deviceinfo fields the package settles. loader says
// msm-firmware-loader will supply firmware, which has a precondition of its own.
func Deviceinfo(p port.Package, loader bool) []Line {
	var out []Line
	set := func(k, v, why string) { out = append(out, Line{Key: k, Val: v, Why: why}) }
	todo := func(k, why string) { out = append(out, Line{Key: k, Todo: why}) }

	brand, code, name := p.Identity()
	set("name", name, "vendor build.prop")
	set("manufacturer", port.TitleWords(brand), "vendor build.prop")
	set("codename", strings.ToLower(brand)+"-"+code, "vendor build.prop")
	todo("year", "not recorded in a package")
	todo("dtb", "upstream name; stock overlays are `"+strings.Join(p.DT.Compat, ", ")+"`, base `"+p.DT.SoC+"`")
	if abis := port.FirstProp(p.Props, "ro.vendor.product.cpu.abilist64", "ro.product.cpu.abilist64"); strings.HasPrefix(abis, "arm64") {
		set("arch", "aarch64", "vendor build.prop 64-bit abi")
	} else {
		todo("arch", "no 64-bit abi in the vendor build.prop")
	}

	todo("chassis", "a package does not say handset or tablet")
	if w, h, ok := port.CommonResolution(p.DT.Panels); ok {
		set("screen_width", fmt.Sprint(w), "every panel in the board overlays")
		set("screen_height", fmt.Sprint(h), "every panel in the board overlays")
	} else if len(p.DT.Panels) > 0 {
		todo("screen_width", "panels disagree: "+port.PanelSizes(p.DT.Panels))
		todo("screen_height", "panels disagree: "+port.PanelSizes(p.DT.Panels))
	}

	set("flash_method", "fastboot", "package flashes by fastboot")
	if slices.Contains(p.Partitions, "vbmeta") || slices.Contains(p.Partitions, "vbmeta_a") {
		set("flash_fastboot_partition_vbmeta", "vbmeta", "GPT")
	}
	if slices.Contains(p.Partitions, "super") {
		set("flash_fastboot_partition_rootfs", "super", "GPT: dynamic partitions")
	}
	if p.SectorSize == 4096 {
		set("rootfs_image_sector_size", "4096", "GPT logical block size (UFS)")
	}
	if b := p.Boot; b.PageSize != 0 {
		set("generate_bootimg", "true", "")
		set("flash_pagesize", fmt.Sprint(b.PageSize), "vendor_boot header")
		set("header_version", fmt.Sprint(b.HeaderVersion), "vendor_boot header; the stock layout, not necessarily the one a port wants")
		// Load addresses assume base 0, which the header cannot confirm.
		set("flash_offset_base", "0x00000000", "assumed; the header holds absolute addresses")
		set("flash_offset_kernel", hex(b.Kernel), "vendor_boot header")
		set("flash_offset_ramdisk", hex(b.Ramdisk), "vendor_boot header")
		set("flash_offset_second", "0x00000000", "")
		set("flash_offset_tags", hex(b.Tags), "vendor_boot header")
		set("flash_offset_dtb", hex(b.DTB), "vendor_boot header")
	}
	if loader {
		set("initfs_udev_subsystems", "block", "msm-firmware-loader finds partitions through /dev/disk/by-partlabel, which only udev creates")
	}
	return out
}

// Render writes the lines as a deviceinfo file.
func Render(lines []Line) string {
	var b strings.Builder
	b.WriteString("# Draft from a stock package: every line carries where it came from.\n")
	b.WriteString("deviceinfo_format_version=\"0\"\n")
	for _, l := range lines {
		switch {
		case l.Todo != "":
			fmt.Fprintf(&b, "# TODO deviceinfo_%s: %s\n", l.Key, l.Todo)
		case l.Why != "":
			fmt.Fprintf(&b, "deviceinfo_%s=%q # %s\n", l.Key, l.Val, l.Why)
		default:
			fmt.Fprintf(&b, "deviceinfo_%s=%q\n", l.Key, l.Val)
		}
	}
	return b.String()
}

func hex(v uint32) string { return fmt.Sprintf("0x%08x", v) }
