package port

import (
	"os"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/arsc"
)

func TestCutoutIsCentredByDefault(t *testing.T) {
	// fogona's own spec; the hand-written gmobile file has 325..395.
	got := CutoutsFromSpec("M -35,0 L 35,0 L 35,80 L -35,80 Z", 720, 1600, 280)
	want := "M 325,0 L 395,0 L 395,80 L 325,80 Z"
	if len(got) != 1 || got[0].Path != want || got[0].Name != "camera" {
		t.Errorf("got %+v, want path %q", got, want)
	}
}

func TestCutoutMarkers(t *testing.T) {
	tests := []struct{ name, spec, want string }{
		{"right", "M -20,0 h 20 v 30 h -20 z @right", "M 700,0 h 20 v 30 h -20 z"},
		{"left", "M 0,0 L 40,0 L 40,40 Z @left", "M 0,0 L 40,0 L 40,40 Z"},
		{"dp scales by density/160", "M -10,0 L 10,0 L 10,20 Z @dp", "M 345,0 L 375,0 L 375,30 Z"},
		{"horizontal and vertical", "M 0,0 H 10 V 10 Z", "M 360,0 H 370 V 10 Z"},
		{"arc offsets only its end point", "M -5,0 A 5,5 0 0 1 5,0 Z", "M 355,0 A 5,5,0,0,1,365,0 Z"},
	}
	for _, tt := range tests {
		// 720 wide at density 240 makes 1dp = 1.5px.
		got := CutoutsFromSpec(tt.spec, 720, 1600, 240)
		if len(got) != 1 || got[0].Path != tt.want {
			t.Errorf("%s: got %+v, want %q", tt.name, got, tt.want)
		}
	}
}

func TestBottomCutoutIsAnchoredToTheBottomEdge(t *testing.T) {
	got := CutoutsFromSpec("M -10,0 L 10,0 L 10,20 Z @bottom M -10,0 L 10,0 L 10,-20 Z", 720, 1600, 280)
	if len(got) != 2 || got[0].Name != "camera" || got[1].Name != "bottom" {
		t.Fatalf("got %+v", got)
	}
	if got[1].Path != "M 350,1600 L 370,1600 L 370,1580 Z" {
		t.Errorf("bottom path %q", got[1].Path)
	}
}

func TestNoCutoutAndBadSpecs(t *testing.T) {
	for _, spec := range []string{"", "   ", "10,20", "M a,b", "X 1,2"} {
		if got := CutoutsFromSpec(spec, 720, 1600, 280); len(got) != 0 {
			t.Errorf("spec %q gave %+v", spec, got)
		}
	}
}

func TestToGmobileRendersWhatGmobileReads(t *testing.T) {
	g := ToGmobile("Motorola Moto G Play (2024)", 720, 1600, 68, 151, AndroidDisplay{
		Cutout: "M -35,0 L 35,0 L 35,80 L -35,80 Z", CornerPx: 42, DensityDPI: 280,
	})
	want := `{
  "name": "Motorola Moto G Play (2024)",
  "x-res": 720,
  "y-res": 1600,
  "border-radius": 42,
  "width": 68,
  "height": 151,
  "cutouts": [
    {
      "name": "camera",
      "path": "M 325,0 L 395,0 L 395,80 L 325,80 Z"
    }
  ]
}
`
	if got := g.JSON(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestBorderRadiusPrefersTheDeviceSpecificValue(t *testing.T) {
	both := ToGmobile("x", 720, 1600, 0, 0, AndroidDisplay{CornerPx: 42, RealPx: 62})
	if both.BorderRadius != 62 {
		t.Errorf("with both, border-radius = %d, want 62", both.BorderRadius)
	}
	frameworkOnly := ToGmobile("x", 720, 1600, 0, 0, AndroidDisplay{CornerPx: 42})
	if frameworkOnly.BorderRadius != 42 {
		t.Errorf("framework only, border-radius = %d, want 42", frameworkOnly.BorderRadius)
	}
}

func TestSizeFromDiagonal(t *testing.T) {
	// fogona: 6.52in at 720x1600 is 68.0 x 151.0mm, matching a ruler.
	if w, h := SizeFromDiagonal(6.52, 720, 1600); w != 68 || h != 151 {
		t.Errorf("6.52in 720x1600 = %dx%d, want 68x151", w, h)
	}
}

func TestDiagonalFromNames(t *testing.T) {
	names := []string{
		"etc/motorola/12m/2kHz_Mono_1s.wav",
		"etc/motorola/12m/chipone-tm_icnl9916c_720x1600_652_vid-primary-fogona.ini",
		"etc/media_codecs_khaje_v0.xml",
	}
	if d, f, ok := DiagonalFromNames(names, 720, 1600); !ok || d != 6.52 || !strings.HasPrefix(f, "chipone-tm_") {
		t.Errorf("got %v %q %v", d, f, ok)
	}
	if _, _, ok := DiagonalFromNames(names, 1080, 2400); ok {
		t.Error("a file for another resolution must not match")
	}
	conflict := append(names, "etc/motorola/x/other_panel_720x1600_655_vid.ini")
	if _, _, ok := DiagonalFromNames(conflict, 720, 1600); ok {
		t.Error("disagreeing diagonals must not produce an answer")
	}
	same := append(names, "etc/motorola/x/another-tm_icnl9916c_720x1600_652_vid.dtsi")
	if d, _, ok := DiagonalFromNames(same, 720, 1600); !ok || d != 6.52 {
		t.Errorf("agreeing files: %v %v", d, ok)
	}
}

func TestPackageGmobileSizePrecedence(t *testing.T) {
	p := Package{
		Props:       map[string]string{"ro.product.vendor.manufacturer": "motorola", "ro.product.vendor.device": "fogona", "ro.product.vendor.model": "moto g play - 2024"},
		DT:          DT{Panels: []Panel{{Name: "a", W: 720, H: 1600, MMW: 70, MMH: 156}}},
		Display:     &AndroidDisplay{CornerPx: 42, DensityDPI: 280},
		VendorFiles: []string{"etc/motorola/12m/chipone-tm_icnl9916c_720x1600_652_vid-primary-fogona.ini"},
	}
	// The name's diagonal beats the device tree.
	_, g, notes, _ := p.Gmobile()
	if g.Width != 68 || g.Height != 151 || !strings.Contains(strings.Join(notes, "\n"), "6.52-inch") {
		t.Errorf("from the file name: %dx%d, notes %q", g.Width, g.Height, notes)
	}
	// An explicit size beats both.
	p.SizeMM = [2]int{69, 152}
	_, g, notes, _ = p.Gmobile()
	if g.Width != 69 || g.Height != 152 || strings.Contains(strings.Join(notes, "\n"), "width and height") {
		t.Errorf("explicit: %dx%d, notes %q", g.Width, g.Height, notes)
	}
	// With neither, the device tree's, flagged.
	p.SizeMM, p.VendorFiles = [2]int{}, nil
	_, g, notes, _ = p.Gmobile()
	if g.Width != 70 || g.Height != 156 || !strings.Contains(strings.Join(notes, "\n"), "--size-mm") {
		t.Errorf("device tree: %dx%d, notes %q", g.Width, g.Height, notes)
	}
}

func TestPackageGmobileSizeFromDeviceTreeUnlessGiven(t *testing.T) {
	p := Package{
		Props:   map[string]string{"ro.product.vendor.manufacturer": "motorola", "ro.product.vendor.device": "fogona", "ro.product.vendor.model": "moto g play - 2024"},
		DT:      DT{Panels: []Panel{{Name: "a", W: 720, H: 1600, MMW: 70, MMH: 156}, {Name: "b", W: 720, H: 1600, MMW: 70, MMH: 156}}},
		Display: &AndroidDisplay{Cutout: "M -35,0 L 35,0 L 35,80 L -35,80 Z", CornerPx: 42, RealPx: 62, DensityDPI: 280},
	}
	file, g, notes, ok := p.Gmobile()
	if !ok || file != "motorola,fogona.json" {
		t.Fatalf("ok=%v file=%q", ok, file)
	}
	if g.Width != 70 || g.Height != 156 {
		t.Errorf("default should be the device tree's declared size, got %dx%d", g.Width, g.Height)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "--size-mm") {
		t.Errorf("notes should offer --size-mm when the size came from the device tree: %q", notes)
	}

	p.SizeMM = [2]int{68, 151}
	_, g, notes, _ = p.Gmobile()
	if g.Width != 68 || g.Height != 151 || g.BorderRadius != 62 {
		t.Errorf("got %dx%d radius %d, want 68x151 radius 62", g.Width, g.Height, g.BorderRadius)
	}
	if strings.Contains(strings.Join(notes, "\n"), "--size-mm") {
		t.Errorf("no size note expected once it is given: %q", notes)
	}
}

func TestToGmobileOmitsAbsentFields(t *testing.T) {
	j := ToGmobile("x", 720, 1600, 0, 0, AndroidDisplay{}).JSON()
	for _, k := range []string{"border-radius", "width", "height", "cutouts"} {
		if strings.Contains(j, k) {
			t.Errorf("%q should be omitted:\n%s", k, j)
		}
	}
}

// testdata/display-*.apk are built by aapt2 from the matching .xml (see
// internal/arsc's test for the commands): a framework-like base and an overlay.
func loadAPK(t *testing.T, name string) *arsc.Table {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := arsc.OpenAPK(b)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestReadAndroidDisplayOverlaysReplaceTheBase(t *testing.T) {
	base, over := loadAPK(t, "display-base.apk"), loadAPK(t, "display-overlay.apk")

	d := ReadAndroidDisplay(280, base, nil, nil)
	if d.Cutout != "" || d.CornerPx != 42 || d.RealPx != 0 {
		t.Errorf("base only: %+v (24dp at 280dpi is 42px)", d)
	}

	d = ReadAndroidDisplay(280, base, map[string]*arsc.Table{"MotoOverlay": over}, []string{"MotoOverlay"})
	if d.Cutout != "M -35,0 L 35,0 L 35,80 L -35,80 Z" || d.Source["cutout"] != "MotoOverlay" {
		t.Errorf("overlay cutout not applied: %+v", d)
	}
	if d.CornerPx != 42 || d.Source["rounded_corner_radius"] != "framework-res" {
		t.Errorf("framework corner should survive an overlay that does not set it: %+v", d)
	}
	if d.RealPx != 62 {
		t.Errorf("real corner = %v, want 62", d.RealPx)
	}
}

func TestFileName(t *testing.T) {
	if got := GmobileFile("Motorola", "fogona"); got != "motorola,fogona.json" {
		t.Errorf("got %q", got)
	}
}
