package vendor

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/recognize"
)

var (
	_ recognize.Recognizer = MotorolaRecognizer{}
	_ recognize.Recognizer = HKMCRecognizer{}
	_ recognize.Recognizer = TelechipsArtifactRecognizer{}
	_ recognize.Recognizer = FSGRecognizer{}
	_ recognize.Recognizer = QcomRecognizer{}
	_ recognize.Recognizer = MediatekRecognizer{}
	_ recognize.Recognizer = SamsungPITRecognizer{}
)

func TestMotorolaRecognizer(t *testing.T) {
	head := CIDBuild(0x0032)
	r := MotorolaRecognizer{}
	if !r.Claims("cid", head) {
		t.Fatal("should claim a v0 CID image")
	}
	if got := r.Label("cid", head); got != "Motorola CID" {
		t.Errorf("label %q", got)
	}
	if got := r.Summary("cid", head, nil); got != " — v0 template, channel 0x0032" {
		t.Errorf("summary without catalog: %q", got)
	}
	if got := r.Report("x", "cid", head, nil); got != nil {
		t.Errorf("report: %+v", got)
	}

	// ActiveCatalog hook: wires the carrier-name lookup the way cmd_recon.go
	// will at startup.
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	ActiveCatalog = func() *catalog.Catalog { return cat }
	defer func() { ActiveCatalog = nil }()
	if got := r.Summary("cid", head, nil); !strings.Contains(got, "US retail") {
		t.Errorf("summary with catalog hook: %q", got)
	}
	if r.Claims("x", []byte("not a motorola file")) {
		t.Error("should not claim unrelated data")
	}
}

func TestHKMCRecognizer(t *testing.T) {
	conb := make([]byte, 0x28)
	copy(conb, "ConB")
	conb = append(conb, 'M', 0, 'D', 0, '.', 0, 'x', 0, 0, 0)

	r := HKMCRecognizer{}
	if !r.Claims("x.bin", conb) {
		t.Fatal("should claim a ConB header")
	}
	if got := r.Label("x.bin", conb); got != "navi config (ConB)" {
		t.Errorf("label %q", got)
	}
	if got := r.Summary("x.bin", conb, nil); got != " — MD.x" {
		t.Errorf("summary %q", got)
	}
	if got := r.Report("x", "x.bin", conb, nil); got != nil {
		t.Errorf("ConB has no ArtifactReporter output: %+v", got)
	}

	// PRNM (.npkg): same one-section header hkmc_artifact_test.go builds, so
	// ArtifactReport's section table is exercised against a known-good fixture.
	prnm := make([]byte, 0x30)
	copy(prnm, "PRNM")
	binary.LittleEndian.PutUint32(prnm[4:], 1000)
	binary.LittleEndian.PutUint32(prnm[8:], 1)
	copy(prnm[0x0C:], "2025/11/26 09:05:00")
	binary.LittleEndian.PutUint32(prnm[0x24:], 0x2c)
	binary.LittleEndian.PutUint32(prnm[0x28:], uint32(len(prnm))-0x2c)

	if !r.Claims("x.npkg", prnm) {
		t.Fatal("should claim a PRNM header")
	}
	if got := r.Label("x.npkg", prnm); got != "navi package (PRNM)" {
		t.Errorf("label %q", got)
	}
	if got := r.Summary("x.npkg", prnm, nil); got != "" {
		t.Errorf("PRNM has no inline detail, it's all in Report: %q", got)
	}
	path := filepath.Join(t.TempDir(), "x.npkg")
	if err := os.WriteFile(path, prnm, 0o644); err != nil {
		t.Fatal(err)
	}
	lines := r.Report(path, "x.npkg", prnm, nil)
	if len(lines) != 2 || !strings.Contains(lines[0], "1 section") || !strings.Contains(lines[1], "tag 0x00000000") {
		t.Errorf("report %+v", lines)
	}
}

func TestTelechipsArtifactRecognizer(t *testing.T) {
	img := bootStage(testBootcmd)
	r := TelechipsArtifactRecognizer{}
	if !r.Claims("bl3_ca53", img) {
		t.Fatal("should claim a Telechips boot stage")
	}
	if got := r.Label("bl3_ca53", img); got != "Telechips boot stage" {
		t.Errorf("label %q", got)
	}
	if got := r.Summary("bl3_ca53", img, nil); got != " — 803xA53-BL3 0.0.0" {
		t.Errorf("summary %q", got)
	}
	path := filepath.Join(t.TempDir(), "bl3_ca53")
	if err := os.WriteFile(path, img, 0o644); err != nil {
		t.Fatal(err)
	}
	var joined string
	for _, l := range r.Report(path, "bl3_ca53", img, nil) {
		joined += l + "\n"
	}
	if !strings.Contains(joined, "Bootloader: U-Boot 2020.01") {
		t.Errorf("report:\n%s", joined)
	}
	if r.Claims("x", []byte("not an image")) {
		t.Error("should not claim unrelated data")
	}
}

func TestFSGRecognizer(t *testing.T) {
	img := make([]byte, 8+2*64)
	copy(img, "FSGADAPT")
	for i, id := range []string{"P89990AA1", "P89990AA1_2"} {
		o := 8 + i*64
		copy(img[o:], "FSG_000"+string(rune('1'+i)))
		copy(img[o+8:], id+"      ")
	}
	r := FSGRecognizer{}
	if !r.Claims("fs_image.tar.gz.mbn.img", img) {
		t.Fatal("should claim an FSGADAPT image")
	}
	if got := r.Label("x", img); got != "modem EFS (FSG) image" {
		t.Errorf("label %q", got)
	}
	if got := r.Summary("x", img, nil); !strings.Contains(got, "2 board variant(s)") {
		t.Errorf("summary %q", got)
	}
	if got := r.Report("x", "x", img, nil); got != nil {
		t.Errorf("report: %+v", got)
	}
	if r.Claims("x", []byte("not an fsg image")) {
		t.Error("should not claim unrelated data")
	}
}

func TestQcomRecognizer(t *testing.T) {
	r := QcomRecognizer{}
	for name, tc := range map[string]struct {
		head  []byte
		label string
	}{
		"mbn":       {[]byte{0xd1, 0xdc, 0x4b, 0x84, 0xff, 0x00}, "Qualcomm MBN"},
		"partition": {[]byte{0x9a, 0x1b, 0x7d, 0xaa, 0x00, 0x00}, "Qualcomm partition table"},
	} {
		if !r.Claims("x.mbn", tc.head) {
			t.Fatalf("%s: should claim", name)
		}
		if got := r.Label("x.mbn", tc.head); got != tc.label {
			t.Errorf("%s: label %q", name, got)
		}
		if got := r.Summary("x.mbn", tc.head, nil); got != "" {
			t.Errorf("%s: summary %q, want \"\"", name, got)
		}
	}
	if r.Claims("x", []byte{0xd1, 0xdc}) {
		t.Error("two bytes were recognised")
	}
}

func TestMediatekRecognizer(t *testing.T) {
	img := append(append(mtkPart("md1rom", 100, false), mtkPart("cert1", 16, false)...), mtkPart("cert2", 33, true)...)
	r := MediatekRecognizer{}
	if !r.Claims("x", img) {
		t.Fatal("should claim a MediaTek image")
	}
	if got := r.Label("x", img); got != "MediaTek image" {
		t.Errorf("label %q", got)
	}
	if got := r.Summary("x", img, nil); got != " — md1rom + cert1 + cert2" {
		t.Errorf("summary %q", got)
	}
	if got := r.Report("x", "x", img, nil); got != nil {
		t.Errorf("report: %+v", got)
	}
}

func TestSamsungPITRecognizer(t *testing.T) {
	data := make([]byte, pitHeader+pitEntry)
	copy(data, pitMagic)
	binary.LittleEndian.PutUint32(data[4:], 1) // one entry
	copy(data[16:24], "SM6350")

	r := SamsungPITRecognizer{}
	if !r.Claims("x.pit", data) {
		t.Fatal("should claim a PIT")
	}
	if got := r.Label("x.pit", data); got != "Samsung PIT" {
		t.Errorf("label %q", got)
	}
	if got := r.Summary("x.pit", data, nil); got != " — 1 partitions" {
		t.Errorf("summary %q", got)
	}
	if got := r.Report("x", "x.pit", data, nil); got != nil {
		t.Errorf("report: %+v", got)
	}
	if r.Claims("x", []byte("not a pit")) {
		t.Error("should not claim unrelated data")
	}
}
