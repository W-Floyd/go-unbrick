package srcfile

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
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

func writeTar(t *testing.T, name string, gz bool, files map[string][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var w io.Writer = f
	if gz {
		zw := gzip.NewWriter(f)
		defer zw.Close()
		w = zw
	}
	tw := tar.NewWriter(w)
	defer tw.Close()
	tw.WriteHeader(&tar.Header{Name: "rom/images/", Typeflag: tar.TypeDir, Mode: 0o755})
	for _, n := range []string{"rom/images/vbmeta.img", "rom/images/super.img", "rom/flash_all.sh"} {
		body, ok := files[n]
		if !ok {
			continue
		}
		tw.WriteHeader(&tar.Header{Name: n, Size: int64(len(body)), Mode: 0o644, Typeflag: tar.TypeReg})
		tw.Write(body)
	}
	return p
}

func TestTarAndTGZ(t *testing.T) {
	big := bytes.Repeat([]byte("S"), tgzKeep+1) // past the in-memory cap: re-streamed
	files := map[string][]byte{
		"rom/images/vbmeta.img": []byte("AVB0vbmeta"),
		"rom/images/super.img":  big,
		"rom/flash_all.sh":      []byte("fastboot flash"),
	}
	for _, tc := range []struct {
		name string
		gz   bool
	}{{"rom.tar", false}, {"rom.tgz", true}} {
		p := writeTar(t, tc.name, tc.gz, files)
		if !IsArchive(p) || IsZip(p) {
			t.Fatalf("%s: IsArchive=%v IsZip=%v", tc.name, IsArchive(p), IsZip(p))
		}
		ms, err := Members(p, 4)
		if err != nil || len(ms) != 3 {
			t.Fatalf("%s: Members = %v, %v", tc.name, ms, err)
		}
		if string(ms[0].Head) != "AVB0" || ms[1].Size != uint64(len(big)) {
			t.Errorf("%s: member 0 head %q, member 1 size %d", tc.name, ms[0].Head, ms[1].Size)
		}
		if names, _ := Glob(p, "*.img"); len(names) != 2 {
			t.Errorf("%s: Glob *.img = %v", tc.name, names)
		}
		if _, data, err := Open(p, "missing.img", "flash_all.sh"); err != nil || string(data) != "fastboot flash" {
			t.Errorf("%s: Open flash_all.sh = %q, %v", tc.name, data, err)
		}
		if _, data, err := Open(p, "super.img"); err != nil || !bytes.Equal(data, big) {
			t.Errorf("%s: Open super.img: %d bytes, %v", tc.name, len(data), err)
		}
	}
}
