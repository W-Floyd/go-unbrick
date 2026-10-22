package analysis

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
)

func TestFindKeyFiles(t *testing.T) {
	known := bytes.Repeat([]byte{0xAB}, 16)
	fresh := bytes.Repeat([]byte{0xCD}, 16)
	old := aeskeys.Secrets()
	aeskeys.Set([]aeskeys.Secret{{Name: "ev6-image", Key: known}})
	t.Cleanup(func() { aeskeys.Set(old) })

	dir := t.TempDir()
	put := func(name string, data []byte) {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("sys/etc/image.dat", []byte(hex.EncodeToString(known)+"\n"))
	put("other/iv.dat", fresh) // raw bytes, not text
	put("notes.txt", []byte("not a key"))
	put("deep/notiv.dat", []byte("x")) // name must be exactly iv.dat / image.dat
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte(hex.EncodeToString(fresh))
	tw.WriteHeader(&tar.Header{Name: "enc/etc/iv.dat", Mode: 0o644, Size: int64(len(body))})
	tw.Write(body)
	tw.Close()
	put("pkg.tar", buf.Bytes())

	var opened int
	var last string
	got, err := FindKeyFiles(context.Background(), dir, 3, func(o, f int, at string) { opened, last = o, at })
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]KeyFile{}
	for _, k := range got {
		byPath[k.Path] = k
	}
	if len(got) != 3 {
		t.Fatalf("found %d files, want 3: %+v", len(got), got)
	}
	if k := byPath["sys/etc/image.dat"]; k.Known != "ev6-image" || k.Value != hex.EncodeToString(known) {
		t.Errorf("a loaded key: %+v", k)
	}
	if k := byPath["other/iv.dat"]; k.Known != "" || k.Size != 16 {
		t.Errorf("a new raw IV: %+v", k)
	}
	if k := byPath["pkg.tar/enc/etc/iv.dat"]; k.Known != "" || k.Value != hex.EncodeToString(fresh) {
		t.Errorf("one inside a container: %+v", k)
	}
	if opened != 1 || last != "pkg.tar" {
		t.Errorf("progress said %d containers opened, last %q", opened, last)
	}
	// Depth 0 does not open containers.
	got, _ = FindKeyFiles(context.Background(), dir, 0, nil)
	for _, k := range got {
		if k.Path == "pkg.tar/enc/etc/iv.dat" {
			t.Error("depth 0 opened a container")
		}
	}
	// A cancelled search says so.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FindKeyFiles(ctx, dir, 3, nil); err == nil {
		t.Error("a cancelled search did not say so")
	}
}
