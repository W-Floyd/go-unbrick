package transport

// Each firmware image the boot chain loads stamps its build string into an
// SMEM table, so a booted kernel can say which firmware is actually running —
// not what a package or partition holds. Downstream kernels print the table as
// /sys/devices/soc0/images; mainline puts it under debugfs qcom_socinfo, one
// directory per image.

import (
	"strconv"
	"strings"
)

// FWImage is one populated slot of the SMEM image-version table.
type FWImage struct {
	Name    string // "boot", "tz", "mpss", …, or the slot index when unnamed
	CRM     string // build string, e.g. TZ.XF.5.1.6-82754-2
	Variant string
	OEM     string
}

// smemImageNames maps table slots to mainline qcom-socinfo's names, which
// downstream's numbered listing leaves implicit.
var smemImageNames = map[int]string{
	0: "boot", 1: "tz", 3: "rpm", 10: "apps", 11: "mpss", 12: "adsp",
	13: "cnss", 14: "video", 15: "dsps", 16: "cdsp",
}

// ParseSoCImages reads downstream's soc0/images:
//
//	0:
//		CRM:		00:BOOT.XF.4.1-00374-KAMORTALAZ-1
//		Variant:	KamortaLAA
//		Version:	moto-build-host
func ParseSoCImages(s string) []FWImage {
	var out []FWImage
	var cur *FWImage
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if n, ok := strings.CutSuffix(t, ":"); ok {
			if i, err := strconv.Atoi(n); err == nil {
				out = append(out, FWImage{Name: imageName(i)})
				cur = &out[len(out)-1]
				continue
			}
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok || cur == nil {
			continue
		}
		v = strings.TrimSpace(v)
		// The SMEM strings carry their own "NN:" slot prefix on CRM and a
		// leading ":" on the OEM field; mainline's debugfs strips both.
		switch k {
		case "CRM":
			if p, rest, ok := strings.Cut(v, ":"); ok {
				if _, err := strconv.Atoi(p); err == nil {
					v = rest
				}
			}
			cur.CRM = v
		case "Variant":
			cur.Variant = v
		case "Version":
			cur.OEM = strings.TrimPrefix(v, ":")
		}
	}
	return dropEmptyImages(out)
}

// ParseDebugfsImages reads the collection's tab-separated rendering of
// debugfs qcom_socinfo: directory, name, variant, oem.
func ParseDebugfsImages(s string) []FWImage {
	var out []FWImage
	for _, line := range NonEmptyLines(s) {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		for len(f) < 4 {
			f = append(f, "")
		}
		out = append(out, FWImage{
			Name:    strings.TrimSpace(f[0]),
			CRM:     strings.TrimSpace(f[1]),
			Variant: strings.TrimSpace(f[2]),
			OEM:     strings.TrimSpace(f[3]),
		})
	}
	return dropEmptyImages(out)
}

func imageName(i int) string {
	if n, ok := smemImageNames[i]; ok {
		return n
	}
	return strconv.Itoa(i)
}

func dropEmptyImages(in []FWImage) []FWImage {
	out := in[:0]
	for _, im := range in {
		if im.CRM != "" || im.Variant != "" || im.OEM != "" {
			out = append(out, im)
		}
	}
	return out
}
