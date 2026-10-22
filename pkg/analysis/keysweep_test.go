package analysis

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyMatcherScan(t *testing.T) {
	key := randBytes(1, 16)
	iv := randBytes(2, 16)
	m := newKeyMatcher([]KeyValue{
		{Name: "k", Bytes: key},
		{Name: "iv", Bytes: iv},
		{Name: "zero", Bytes: make([]byte, 16)}, // a uniform value is not searched for
	})
	if len(m.pats) != 6 { // two values, each raw, hex and HEX
		t.Fatalf("%d patterns", len(m.pats))
	}
	data := randBytes(3, 9<<20)
	// One at the very start, one straddling the 4 MiB read boundary, one at the very end.
	hexKey := []byte(hex.EncodeToString(key))
	copy(data, key)
	copy(data[4<<20-5:], iv)
	copy(data[len(data)-len(hexKey):], bytes.ToUpper(hexKey))
	var got []keyHit
	if err := m.scan(bytes.NewReader(data), func(h keyHit) { got = append(got, h) }); err != nil {
		t.Fatal(err)
	}
	want := map[int64]string{0: "raw", 4<<20 - 5: "raw", int64(len(data) - len(hexKey)): "HEX"}
	if len(got) != len(want) {
		t.Fatalf("hits %v", got)
	}
	for _, h := range got {
		if want[h.off] != h.pat.enc {
			t.Errorf("hit at %d as %s", h.off, h.pat.enc)
		}
	}
}

func TestKeyMatcherSequentialIVNeedsBoundaries(t *testing.T) {
	seq := make([]byte, 16)
	for i := range seq {
		seq[i] = byte(i)
	}
	m := newKeyMatcher([]KeyValue{{Name: "iv", Bytes: seq}})
	hexSeq := hex.EncodeToString(seq)
	count := func(data []byte) int {
		n := 0
		if err := m.scan(bytes.NewReader(data), func(keyHit) { n++ }); err != nil {
			t.Fatal(err)
		}
		return n
	}
	table := []byte("xx" + hexSeq + "101112131415161718191a1b1c1d1e1f")
	if n := count(table); n != 0 {
		t.Errorf("start of a hex table: %d hits", n)
	}
	if n := count([]byte(hexSeq + "\n")); n != 1 {
		t.Errorf("the value as a file's whole content: %d hits", n)
	}
	if n := count(append([]byte("iv="), hexSeq...)); n != 1 {
		t.Errorf("the value at the end of the data: %d hits", n)
	}
	// Alone, but with the read boundary one byte before it.
	data := bytes.Repeat([]byte{'z'}, 8<<20)
	copy(data[4<<20-1:], hexSeq)
	if n := count(data); n != 1 {
		t.Errorf("across a read boundary: %d hits", n)
	}
	if n := count(seq); n != 0 {
		t.Errorf("raw sequential bytes: %d hits", n)
	}
}

func TestSweepKeysDirectory(t *testing.T) {
	key := randBytes(7, 16)
	dir := t.TempDir()
	write := func(name string, b []byte) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/image.dat", []byte(hex.EncodeToString(key)+"\n"))
	write("lib/blob.bin", append(randBytes(8, 1000), key...))
	write("skipme/blob.bin", key)
	write("other.bin", randBytes(9, 5000))

	var live []KeyHit
	progressed := false
	res, err := SweepKeys(context.Background(), dir, KeySweepOptions{
		Values:     []KeyValue{{Name: "image_key", Bytes: key}},
		Skip:       func(name string) bool { return name == "skipme" },
		Known:      func(path string) bool { return filepath.Base(path) == "image.dat" },
		OnHit:      func(h KeyHit) { live = append(live, h) },
		OnProgress: func(KeySweepProgress) { progressed = true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 2 || len(live) != 2 {
		t.Fatalf("hits %+v", res.Hits)
	}
	byPath := map[string]KeyHit{}
	for _, h := range res.Hits {
		byPath[h.Path] = h
	}
	if h := byPath["etc/image.dat"]; h.Encoding != "hex" || !h.Known || h.Name != "image_key" {
		t.Errorf("image.dat: %+v", byPath)
	}
	if h := byPath["lib/blob.bin"]; h.Encoding != "raw" || h.Offset != 1000 || h.Known {
		t.Errorf("blob.bin: %+v", byPath)
	}
	if res.Files != 3 || !progressed {
		t.Errorf("files %d, progress %v", res.Files, progressed)
	}
}

func TestSweepKeysCancelled(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), randBytes(1, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SweepKeys(ctx, dir, KeySweepOptions{Values: []KeyValue{{Name: "k", Bytes: randBytes(2, 16)}}}); err == nil {
		t.Error("a cancelled sweep reported no error")
	}
}

func TestSweepKeysNothingToSearchFor(t *testing.T) {
	if _, err := SweepKeys(context.Background(), t.TempDir(), KeySweepOptions{Values: []KeyValue{{Name: "z", Bytes: make([]byte, 16)}}}); err == nil {
		t.Error("only a uniform value, yet no error")
	}
}
