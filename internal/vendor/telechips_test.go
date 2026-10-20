package vendor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Telechips boot stage is named from its wrapper, and reported on in full, by
// the telechips driver (a platform of its own, not Hyundai's): recon and ls hardcode nothing of it.
func TestTelechipsStageIsRecognizedBehindTheSeam(t *testing.T) {
	img := make([]byte, 0x2000)
	copy(img, "CERT")
	copy(img[0x100:], "HDR\x00")
	img[0x104], img[0x105], img[0x106] = 0x00, 0x04, 0x00 // payload 0x400
	img[0x109] = 0x10                                     // offset 0x1000
	copy(img[0x110:], "803xA53-BL3")
	copy(img[0x120:], "0.0.0")
	copy(img[0x1000+0x90:], "U-Boot 2020.01 (Jan 07 2026 - 17:20:41 +0900)\x00bootdelay=0\x00")
	info, ok := RecognizeArtifact(nil, "bl3_ca53", img[:8192])
	if !ok || info.Label != "Telechips boot stage" || info.Detail != "803xA53-BL3 0.0.0" {
		t.Fatalf("%+v %v", info, ok)
	}
	p := filepath.Join(t.TempDir(), "bl3")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}
	var joined string
	for _, l := range ArtifactReport(p, img[:8192]) {
		joined += l + "\n"
	}
	if !strings.Contains(joined, "Bootloader: U-Boot 2020.01 (Jan 07 2026") || !strings.Contains(joined, "bootdelay=0") {
		t.Errorf("report:\n%s", joined)
	}
	if lines := ArtifactReport(p, []byte("not an image")); lines != nil {
		t.Errorf("a report for something else: %v", lines)
	}
}

// Qualcomm's own images are recognised behind the seam, not by the neutral
// filetype detector.
func TestQualcommImagesAreRecognizedBehindTheSeam(t *testing.T) {
	for name, tc := range map[string]struct {
		head  []byte
		label string
	}{
		"mbn":       {[]byte{0xd1, 0xdc, 0x4b, 0x84, 0xff, 0x00}, "Qualcomm MBN"},
		"partition": {[]byte{0x9a, 0x1b, 0x7d, 0xaa, 0x00, 0x00}, "Qualcomm partition table"},
	} {
		if info, ok := RecognizeArtifact(nil, "x.mbn", tc.head); !ok || info.Label != tc.label {
			t.Errorf("%s: %+v %v", name, info, ok)
		}
	}
	if _, ok := RecognizeArtifact(nil, "x", []byte{0xd1, 0xdc}); ok {
		t.Error("two bytes were recognised")
	}
}
