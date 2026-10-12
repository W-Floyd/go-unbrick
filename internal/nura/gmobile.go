package nura

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/arsc"
)

// Cutout is one display cutout in gmobile's terms: an SVG path in display
// pixels, origin top-left.
type Cutout struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// Gmobile is a gmobile display-panel description
// (data/devices/display-panels/<vendor>,<codename>.json).
type Gmobile struct {
	Name         string   `json:"name"`
	XRes         int      `json:"x-res"`
	YRes         int      `json:"y-res"`
	BorderRadius int      `json:"border-radius,omitempty"`
	Width        int      `json:"width,omitempty"`  // mm
	Height       int      `json:"height,omitempty"` // mm
	Cutouts      []Cutout `json:"cutouts,omitempty"`
}

// JSON renders the description as gmobile reads it.
func (g Gmobile) JSON() string {
	b, _ := json.MarshalIndent(g, "", "  ")
	return string(b) + "\n"
}

// AndroidDisplay is what Android's resources say about the screen's shape.
type AndroidDisplay struct {
	Cutout     string  // config_mainBuiltInDisplayCutout
	CornerPx   float64 // rounded_corner_radius, in pixels
	RealPx     float64 // Motorola's real_rounded_corner_radius, in pixels (0 if absent)
	DensityDPI int
	// Source names where each value came from, for the report.
	Source map[string]string
}

// ReadAndroidDisplay resolves the display resources: the base framework table
// first, then overlays in order, each replacing what it defines.
func ReadAndroidDisplay(density int, base *arsc.Table, overlays map[string]*arsc.Table, order []string) AndroidDisplay {
	d := AndroidDisplay{DensityDPI: density, Source: map[string]string{}}
	apply := func(name string, t *arsc.Table) {
		if t == nil {
			return
		}
		if e := t.Lookup("string", "config_mainBuiltInDisplayCutout"); e != nil {
			if v, ok := e.Default(); ok && v.Kind == arsc.Str {
				d.Cutout, d.Source["cutout"] = v.Str, name
			}
		}
		for key, dst := range map[string]*float64{"rounded_corner_radius": &d.CornerPx, "real_rounded_corner_radius": &d.RealPx} {
			if e := t.Lookup("dimen", key); e != nil {
				if v, ok := e.Default(); ok {
					if px, ok := toPx(v, density); ok {
						*dst, d.Source[key] = px, name
					}
				}
			}
		}
	}
	apply("framework-res", base)
	for _, n := range order {
		apply(n, overlays[n])
	}
	return d
}

func toPx(v arsc.Value, density int) (float64, bool) {
	n, unit, ok := v.Dimension()
	switch {
	case !ok:
		return 0, false
	case unit == "px":
		return n, true
	case unit == "dp" && density > 0:
		return n * float64(density) / 160, true
	}
	return 0, false
}

// ToGmobile converts Android's display shape to gmobile. xres and yres are the
// panel's resolution and mmW and mmH its physical size (0 when unknown).
func ToGmobile(name string, xres, yres, mmW, mmH int, d AndroidDisplay) Gmobile {
	// Motorola's per-device real_rounded_corner_radius over the framework's
	// rounded_corner_radius, a default its shared system image sets for every
	// device. On fogona the former (62px, 6.0mm) matches the panel's corner
	// measured with a ruler; the latter (42px) does not.
	radius := d.CornerPx
	if d.RealPx > 0 {
		radius = d.RealPx
	}
	g := Gmobile{Name: name, XRes: xres, YRes: yres, Width: mmW, Height: mmH,
		BorderRadius: int(math.Round(radius))}
	g.Cutouts = CutoutsFromSpec(d.Cutout, xres, yres, d.DensityDPI)
	return g
}

var pathToken = regexp.MustCompile(`[A-Za-z]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?`)

// CutoutsFromSpec converts an Android DisplayCutout spec to gmobile cutouts,
// following DisplayCutout.fromSpec: x is relative to the display's horizontal
// centre unless the spec says @left or @right, the part after @bottom is
// anchored to the bottom edge, and @dp means the path is in dp.
func CutoutsFromSpec(spec string, xres, yres, density int) []Cutout {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	top, bottom, hasBottom := strings.Cut(spec, "@bottom")
	var out []Cutout
	if p := convertPath(top, xres, 0, density); p != "" {
		out = append(out, Cutout{Name: "camera", Path: p})
	}
	if hasBottom {
		if p := convertPath(bottom, xres, yres, density); p != "" {
			out = append(out, Cutout{Name: "bottom", Path: p})
		}
	}
	return out
}

// arity and roles of SVG path arguments: x, y, r (radius, scaled with no
// offset), o (other, unchanged).
var pathArgs = map[byte]string{
	'M': "xy", 'L': "xy", 'T': "xy", 'H': "x", 'V': "y",
	'C': "xyxyxy", 'S': "xyxy", 'Q': "xyxy", 'A': "rroooxy", 'Z': "",
}

func convertPath(spec string, xres, offY, density int) string {
	dp := strings.Contains(spec, "@dp")
	offX := float64(xres) / 2
	switch {
	case strings.Contains(spec, "@right"):
		offX = float64(xres)
	case strings.Contains(spec, "@left"):
		offX = 0
	}
	for _, m := range []string{"@dp", "@left", "@right"} {
		spec = strings.ReplaceAll(spec, m, "")
	}
	scale := 1.0
	if dp && density > 0 {
		scale = float64(density) / 160
	}

	toks := pathToken.FindAllString(spec, -1)
	var out []string
	for i := 0; i < len(toks); {
		cmd := toks[i][0]
		if !(cmd >= 'A' && cmd <= 'Z' || cmd >= 'a' && cmd <= 'z') {
			return "" // numbers with no command: not a path we understand
		}
		i++
		roles, ok := pathArgs[upper(cmd)]
		if !ok {
			return ""
		}
		abs := cmd == upper(cmd)
		if roles == "" {
			out = append(out, string(cmd))
			continue
		}
		var groups []string
		for i < len(toks) && !isLetter(toks[i][0]) {
			if i+len(roles) > len(toks) {
				return ""
			}
			var args []string
			for j, r := range roles {
				v, err := strconv.ParseFloat(toks[i+j], 64)
				if err != nil {
					return ""
				}
				switch r {
				case 'x':
					v = v * scale
					if abs {
						v += offX
					}
				case 'y':
					v = v * scale
					if abs {
						v += float64(offY)
					}
				case 'r':
					v *= scale
				}
				args = append(args, num(v))
			}
			i += len(roles)
			groups = append(groups, strings.Join(args, ","))
		}
		if len(groups) == 0 {
			return ""
		}
		out = append(out, string(cmd)+" "+strings.Join(groups, " "))
	}
	return strings.Join(out, " ")
}

func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 32
	}
	return c
}

func isLetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

// num formats a coordinate to at most two decimals, without trailing zeros.
func num(v float64) string {
	return strconv.FormatFloat(math.Round(v*100)/100, 'f', -1, 64)
}

// GmobileFile is the file name gmobile looks a device up by: the device-tree
// compatible, "<vendor>,<codename>.json".
func GmobileFile(vendor, codename string) string {
	return fmt.Sprintf("%s,%s.json", strings.ToLower(vendor), codename)
}

// Gmobile derives the device's gmobile description from the package. notes
// says what was chosen and what could not be settled; ok is false when the
// package names no single resolution or the display resources were not read.
func (p Package) Gmobile() (file string, g Gmobile, notes []string, ok bool) {
	if p.Display == nil {
		return "", g, []string{"Android display resources were not read"}, false
	}
	w, h, same := commonResolution(p.DT.Panels)
	if !same {
		return "", g, []string{"no single panel resolution: " + panelSizes(p.DT.Panels)}, false
	}
	brand, code, name := p.identity()
	// Precedence: a size the caller measured; the diagonal in a vendor panel
	// file's name; the device tree's size, which on fogona (70x156mm) ran about
	// 3% over the visible area (68x151mm by ruler, and by the 6.52in in the name).
	var sizeNote string
	mmW, mmH := p.SizeMM[0], p.SizeMM[1]
	if mmW == 0 {
		if diag, file, ok := DiagonalFromNames(p.VendorFiles, int(w), int(h)); ok {
			mmW, mmH = SizeFromDiagonal(diag, int(w), int(h))
			sizeNote = fmt.Sprintf("width and height (%dx%d mm) are a %.2f-inch diagonal at %dx%d, from the file name %s", mmW, mmH, diag, w, h, file)
		} else if mmW, mmH = commonSizeMM(p.DT.Panels); mmW != 0 {
			sizeNote = fmt.Sprintf("width and height are the device tree's panel size (%dx%d mm); on fogona that was ~3%% over the visible area, so measure and pass --size-mm", mmW, mmH)
		} else {
			sizeNote = "no panel size found: width and height omitted; pass the visible size with --size-mm"
		}
	}
	g = ToGmobile(name, int(w), int(h), mmW, mmH, *p.Display)

	d := p.Display
	if d.Cutout == "" {
		notes = append(notes, "Android declares no display cutout")
	} else if len(g.Cutouts) == 0 {
		notes = append(notes, fmt.Sprintf("cutout spec %q was not understood", d.Cutout))
	}
	if d.RealPx > 0 {
		notes = append(notes, fmt.Sprintf("border-radius is Motorola's real_rounded_corner_radius (%.0fpx), not the framework default (%.0fpx)", d.RealPx, d.CornerPx))
	}
	if d.DensityDPI == 0 {
		notes = append(notes, "no ro.sf.lcd_density: dp values could not be converted to pixels")
	}
	if sizeNote != "" {
		notes = append(notes, sizeNote)
	}
	return GmobileFile(brand, code), g, notes, true
}

// panelFile matches a Motorola panel file name: <ic>-<vendor>_<panel>_<w>x<h>_<diag>_<mode>,
// where diag is the diagonal in hundredths of an inch ("652" is 6.52in).
var panelFile = regexp.MustCompile(`_(\d+)x(\d+)_(\d{3})_`)

// DiagonalFromNames finds a panel's diagonal, in inches, in a file name that
// names its resolution: the three digits after "<w>x<h>_". It answers only when
// every such file for this resolution agrees; file is one of them.
func DiagonalFromNames(names []string, w, h int) (inches float64, file string, ok bool) {
	var found int
	for _, n := range names {
		base := n[strings.LastIndex(n, "/")+1:]
		m := panelFile.FindStringSubmatch(base)
		if m == nil || m[1] != strconv.Itoa(w) || m[2] != strconv.Itoa(h) {
			continue
		}
		v, _ := strconv.Atoi(m[3])
		if found != 0 && found != v {
			return 0, "", false
		}
		found, file = v, base
	}
	if found == 0 {
		return 0, "", false
	}
	return float64(found) / 100, file, true
}

// SizeFromDiagonal is the width and height in millimetres of a panel with the
// given diagonal in inches and pixel resolution (square pixels).
func SizeFromDiagonal(inches float64, w, h int) (mmW, mmH int) {
	diag := inches * 25.4
	k := math.Hypot(float64(w), float64(h))
	return int(math.Round(diag * float64(w) / k)), int(math.Round(diag * float64(h) / k))
}

// commonSizeMM is the physical size every panel agrees on, else 0.
func commonSizeMM(ps []Panel) (w, h int) {
	for i, p := range ps {
		if p.MMW == 0 || p.MMH == 0 {
			continue
		}
		if i > 0 && w != 0 && (int(p.MMW) != w || int(p.MMH) != h) {
			return 0, 0
		}
		w, h = int(p.MMW), int(p.MMH)
	}
	return w, h
}
