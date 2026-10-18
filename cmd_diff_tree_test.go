package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTar(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for n, c := range files {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c))})
		tw.Write([]byte(c))
	}
	tw.Close()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiffContainers(t *testing.T) {
	a := writeTar(t, "a.tar", map[string]string{
		"same.txt": "same", "size.txt": "short", "bytes.txt": "abcd", "gone.txt": "x", "d.joined": "1",
	})
	b := writeTar(t, "b.tar", map[string]string{
		"same.txt": "same", "size.txt": "longer", "bytes.txt": "abce", "new.txt": "y", "d.joined": "2",
	})
	var ok bool
	out, err := captureStdout(func() error {
		var err error
		ok, err = diffContainers(a, b, 3, false)
		return err
	})
	if !ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	for _, want := range []string{"~ size.txt", "~ bytes.txt", "- gone.txt", "+ new.txt", "2 changed, 1 added, 1 removed, 1 unchanged"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "same.txt") || strings.Contains(out, ".joined") {
		t.Errorf("listed an unchanged or derived member:\n%s", out)
	}
}

func TestDiffContainersFallsBackForNonContainers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.bin")
	os.WriteFile(p, []byte("plain bytes, not a container"), 0o644)
	if ok, _ := diffContainers(p, p, 3, false); ok {
		t.Error("treated a plain file as a container")
	}
}
