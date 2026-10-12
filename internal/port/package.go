package port

import (
	"fmt"
	"strings"
)

// Package is everything read out of a stock package that a port draws on. It
// holds facts, not a distribution's opinions: an Emitter decides what to do
// with them.
type Package struct {
	Props      map[string]string // vendor build.prop
	Partitions []string          // GPT labels
	SectorSize uint32            // GPT logical block size
	Boot       Boot
	DT         DT
	Kernel     string   // "5.15.167" from the stock kernel's banner
	Modules    []Module // the stock kernel modules, read from their .modinfo
	Fstab      []FstabEntry
	Display    *AndroidDisplay // Android's screen shape resources, if read
	// SizeMM is the visible panel size in millimetres, when known. A package
	// does not carry a trustworthy one, so it is supplied from outside.
	SizeMM [2]int
	// VendorFiles are the file names on the vendor partition, searched for a
	// panel's diagonal (see DiagonalFromNames).
	VendorFiles []string

	// Slot is the A/B suffix ("_a", or "" on a non-A/B device). PartFiles are
	// the file lists of the firmware-bearing partitions the package carries
	// (see FirmwarePartitions), and FileIndex locates any file in them by base
	// name as "partition:path".
	Slot      string
	PartFiles []PartFiles
	FileIndex map[string][]string
}

// FirmwarePartitions are the partitions a Qualcomm Android device keeps its
// firmware on, by base name; reading a package lists the ones it carries.
var FirmwarePartitions = []string{"apnhlos", "bluetooth", "dsp", "fsg", "modem", "persist", "vendor"}

// PartFiles is the file list of one partition a package carries.
type PartFiles struct {
	Name  string   // base name, without a slot suffix: "modem"
	Files []string // paths inside the partition: "image/adsp.mdt"
}

// FstabEntry is one mount of the first-stage fstab.
type FstabEntry struct {
	Source, Mount, FS string
	Logical           bool
}

// Identity is the maker, the codename and the marketing name from the vendor
// build.prop, the codename falling back to the overlay's model.
func (p Package) Identity() (brand, code, name string) {
	brand = FirstProp(p.Props, "ro.product.vendor.manufacturer", "ro.product.vendor.brand")
	code = FirstProp(p.Props, "ro.product.vendor.device", "ro.product.board")
	if code == "" {
		code = p.DT.Model
	}
	model := strings.ReplaceAll(FirstProp(p.Props, "ro.product.vendor.model"), " - ", " ")
	return brand, code, TitleWords(brand) + " " + TitleWords(model)
}

// CommonResolution is the resolution every panel agrees on.
func CommonResolution(ps []Panel) (w, h uint32, ok bool) {
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

// PanelSizes lists the panels' resolutions, for a message about a disagreement.
func PanelSizes(ps []Panel) string {
	var s []string
	for _, p := range ps {
		s = append(s, fmt.Sprintf("%s %dx%d", p.Name, p.W, p.H))
	}
	return strings.Join(s, "; ")
}

// FirstProp is the first non-empty value among the keys.
func FirstProp(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

// TitleWords capitalizes each word that is all lowercase letters, leaving
// anything with a digit or capital ("g32", "XT2413") as it was.
func TitleWords(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if strings.ToLower(w) == w && strings.IndexFunc(w, func(r rune) bool { return r >= '0' && r <= '9' }) < 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
