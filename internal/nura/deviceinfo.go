package nura

import (
	"fmt"
	"slices"
	"strings"
)

// Package is everything read out of a stock package that a port draft uses.
type Package struct {
	Props      map[string]string // vendor build.prop
	Partitions []string          // GPT labels
	SectorSize uint32            // GPT logical block size
	Boot       Boot
	DT         DT
	Kernel     string // "5.15.167" from the stock kernel's banner
	Modules    []string
	Fstab      []FstabEntry
	Display    *AndroidDisplay // Android's screen shape resources, if read
	// SizeMM is the visible panel size in millimetres, when known. A package
	// does not carry a trustworthy one, so it is supplied from outside.
	SizeMM [2]int
	// VendorFiles are the file names on the vendor partition, searched for a
	// panel's diagonal (see DiagonalFromNames).
	VendorFiles []string

	// LoaderSlot and LoaderParts are the A/B suffix and the file lists of the
	// partitions msm-firmware-loader would walk; FileIndex locates any file by
	// base name across the partitions the package carries.
	LoaderSlot  string
	LoaderParts []PartFiles
	FileIndex   map[string][]string
	Loader      *LoaderCheck // set by CheckLoader
}

// FstabEntry is one mount of the first-stage fstab.
type FstabEntry struct {
	Source, Mount, FS string
	Logical           bool
}

// Line is one deviceinfo line. Todo, when set, is why the value could not be
// derived; the line is then emitted commented out with that reason.
type Line struct {
	Key, Val string
	Why      string // where the value came from
	Todo     string
}

// identity is the maker, the codename and the marketing name from the vendor
// build.prop, the codename falling back to the overlay's model.
func (p Package) identity() (brand, code, name string) {
	brand = firstProp(p.Props, "ro.product.vendor.manufacturer", "ro.product.vendor.brand")
	code = firstProp(p.Props, "ro.product.vendor.device", "ro.product.board")
	if code == "" {
		code = p.DT.Model
	}
	model := strings.ReplaceAll(firstProp(p.Props, "ro.product.vendor.model"), " - ", " ")
	return brand, code, titleWords(brand) + " " + titleWords(model)
}

// Deviceinfo derives the deviceinfo fields the package settles.
func Deviceinfo(p Package) []Line {
	var out []Line
	set := func(k, v, why string) { out = append(out, Line{Key: k, Val: v, Why: why}) }
	todo := func(k, why string) { out = append(out, Line{Key: k, Todo: why}) }

	brand, code, name := p.identity()
	set("name", name, "vendor build.prop")
	set("manufacturer", titleWords(brand), "vendor build.prop")
	set("codename", strings.ToLower(brand)+"-"+code, "vendor build.prop")
	todo("year", "not recorded in a package")
	todo("dtb", "upstream name; stock overlays are `"+strings.Join(p.DT.Compat, ", ")+"`, base `"+p.DT.SoC+"`")
	if abis := firstProp(p.Props, "ro.vendor.product.cpu.abilist64", "ro.product.cpu.abilist64"); strings.HasPrefix(abis, "arm64") {
		set("arch", "aarch64", "vendor build.prop 64-bit abi")
	} else {
		todo("arch", "no 64-bit abi in the vendor build.prop")
	}

	todo("chassis", "a package does not say handset or tablet")
	if w, h, ok := commonResolution(p.DT.Panels); ok {
		set("screen_width", fmt.Sprint(w), "every panel in the board overlays")
		set("screen_height", fmt.Sprint(h), "every panel in the board overlays")
	} else if len(p.DT.Panels) > 0 {
		todo("screen_width", "panels disagree: "+panelSizes(p.DT.Panels))
		todo("screen_height", "panels disagree: "+panelSizes(p.DT.Panels))
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

func commonResolution(ps []Panel) (w, h uint32, ok bool) {
	for i, p := range ps {
		if p.W == 0 || p.H == 0 {
			continue
		}
		if i > 0 && w != 0 && (p.W != w || p.H != h) {
			return 0, 0, false
		}
		w, h = p.W, p.H
	}
	return w, h, w != 0
}

func panelSizes(ps []Panel) string {
	var s []string
	for _, p := range ps {
		s = append(s, fmt.Sprintf("%s %dx%d", p.Name, p.W, p.H))
	}
	return strings.Join(s, "; ")
}

func firstProp(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func hex(v uint32) string { return fmt.Sprintf("0x%08x", v) }

// titleWords capitalizes each word that is all lowercase letters, leaving
// anything with a digit or capital ("g32", "XT2413") as it was.
func titleWords(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if strings.ToLower(w) == w && strings.IndexFunc(w, func(r rune) bool { return r >= '0' && r <= '9' }) < 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
