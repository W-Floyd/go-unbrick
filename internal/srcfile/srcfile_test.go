package srcfile

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func writeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	return p
}

func TestOpenZipAndPlain(t *testing.T) {
	zp := writeZip(t, map[string]string{"radio.img": "RADIO", "vbmeta.img": "VB"})
	if !IsZip(zp) {
		t.Fatal("IsZip false for a zip")
	}
	member, data, err := Open(zp, "radio.img", "NON-HLOS.bin")
	if err != nil || member != "radio.img" || string(data) != "RADIO" {
		t.Fatalf("zip open: %q %q %v", member, data, err)
	}
	if _, _, err := Open(zp, "missing.img"); err == nil {
		t.Error("expected error for absent member")
	}
	// Plain file: names ignored, bytes returned.
	pf := filepath.Join(t.TempDir(), "vbmeta.img")
	os.WriteFile(pf, []byte("PLAIN"), 0o644)
	if IsZip(pf) {
		t.Error("IsZip true for a plain file")
	}
	member, data, err = Open(pf, "radio.img")
	if err != nil || string(data) != "PLAIN" || member != "vbmeta.img" {
		t.Fatalf("plain open: %q %q %v", member, data, err)
	}
	names, _ := Glob(zp, "*.img")
	if len(names) != 2 {
		t.Errorf("Glob *.img: %v", names)
	}
}
