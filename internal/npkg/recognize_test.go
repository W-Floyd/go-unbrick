package npkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/pkg/analysis/recognize"
)

var _ recognize.Recognizer = Recognizer{}

func TestRecognizer(t *testing.T) {
	h := decode(t, oneSectionHex)
	r := Recognizer{}

	if !r.Claims("oem_nimo_language.npkg", h) {
		t.Fatal("should claim a real PRNM header")
	}
	if r.Claims("x", []byte("not a package")) {
		t.Error("should not claim non-PRNM bytes")
	}
	if got := r.Label("oem_nimo_language.npkg", h); got != "navi package (PRNM)" {
		t.Errorf("label %q", got)
	}
	if s := r.Summary("x", h, nil); s != "" {
		t.Errorf("summary should be empty, got %q", s)
	}

	// Report re-reads the whole file, so it needs a real one on disk: the
	// one-section fixture's declared sections must cover it exactly to EOF.
	dir := t.TempDir()
	path := filepath.Join(dir, "oem_nimo_language.npkg")
	full := append(append([]byte{}, h...), make([]byte, 11708400)...)
	if err := os.WriteFile(path, full, 0o644); err != nil {
		t.Fatal(err)
	}
	lines := r.Report(path, "oem_nimo_language.npkg", h, nil)
	if len(lines) == 0 || !strings.Contains(lines[0], "PRNM v1000") {
		t.Errorf("report %+v", lines)
	}
	if len(lines) != 2 || !strings.Contains(lines[1], "section 0") {
		t.Errorf("report sections %+v", lines)
	}
}

func TestRecognizerReportBadFile(t *testing.T) {
	h := decode(t, oneSectionHex)
	r := Recognizer{}
	if lines := r.Report("/no/such/file", "x", h, nil); lines != nil {
		t.Errorf("unreadable path should report nothing, got %+v", lines)
	}
}
