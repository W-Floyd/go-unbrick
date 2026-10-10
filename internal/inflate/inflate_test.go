package inflate

import (
	"bytes"
	"compress/flate"
	"io"
	"math/rand"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/inflate/pigztest"
)

// sample is compressible but not trivially so: words drawn at random, with
// incompressible runs that a compressor stores.
func sample(n int) []byte {
	rng := rand.New(rand.NewSource(1))
	words := []string{"fastboot ", "flash ", "super ", "vbmeta ", "\x00\x00\x00\x00", "abl ", "partition "}
	var b bytes.Buffer
	for b.Len() < n {
		if rng.Intn(20000) == 0 {
			r := make([]byte, 40<<10)
			rng.Read(r)
			b.Write(r)
			continue
		}
		b.WriteString(words[rng.Intn(len(words))])
	}
	return b.Bytes()[:n]
}

// compress deflates data, sync-flushing every flushEvery bytes as pigz does.
func compress(t *testing.T, data []byte, level, flushEvery int) []byte {
	var out bytes.Buffer
	w, err := flate.NewWriter(&out, level)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(data); i += flushEvery {
		w.Write(data[i:min(i+flushEvery, len(data))])
		w.Flush()
	}
	w.Close()
	return out.Bytes()
}

func readAll(t *testing.T, d *Decoder) []byte {
	b, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFromStart(t *testing.T) {
	data := sample(3 << 20)
	for _, level := range []int{flate.NoCompression, flate.HuffmanOnly, 1, 6, 9} {
		comp := compress(t, data, level, 128<<10)
		d := NewExact(bytes.NewReader(comp), 0, nil)
		if got := readAll(t, d); !bytes.Equal(got, data) {
			t.Fatalf("level %d: output differs", level)
		}
		if end := (d.Bit() + 7) / 8; end != int64(len(comp)) {
			t.Errorf("level %d: end at %d, stream is %d", level, end, len(comp))
		}
	}
}

// Every byte ReadMask calls known is exact, including those before the
// decoder settles; and some before it are unknown, or the test shows nothing.
func TestMask(t *testing.T) {
	data := sample(2 << 20)
	comp := pigzRaw(data)
	var at, out int64 = -1, 0
	d := NewExact(bytes.NewReader(comp), 0, nil)
	d.OnBoundary = func(bit, o int64) {
		if at < 0 && o > 300<<10 {
			at, out = bit, o
		}
	}
	readAll(t, d)
	u := NewUnknown(bytes.NewReader(comp), at)
	got, unk := make([]byte, len(data)), make([]bool, len(data))
	n, err := u.ReadMask(got, unk)
	if err != io.EOF || int64(n) != int64(len(data))-out {
		t.Fatalf("ReadMask: %d, %v", n, err)
	}
	unknown := 0
	for i := 0; i < n; i++ {
		if unk[i] {
			unknown++
		} else if got[i] != data[out+int64(i)] {
			t.Fatalf("byte %d marked known but wrong", i)
		}
	}
	if unknown == 0 {
		t.Fatal("no byte depended on the missing history")
	}
}

func TestMidStream(t *testing.T) {
	data := sample(4 << 20)
	comp := pigzRaw(data)
	type point struct{ comp, out int64 }
	var points []point
	d := NewExact(bytes.NewReader(comp), 0, nil)
	d.OnBoundary = func(c, o int64) { points = append(points, point{c, o}) }
	readAll(t, d)
	if len(points) < 20 {
		t.Fatalf("only %d boundaries", len(points))
	}
	for _, p := range points[5:8] {
		d := NewUnknown(bytes.NewReader(comp), p.comp)
		got := readAll(t, d)
		if !d.Settled() {
			t.Fatalf("never settled from %d", p.comp)
		}
		want := data[p.out:]
		if len(got) != len(want) {
			t.Fatalf("from %d: %d bytes, want %d", p.comp, len(got), len(want))
		}
		x := d.ExactFrom()
		if x == 0 || x > 1<<20 {
			t.Errorf("from %d: exact only after %d bytes", p.comp, x)
		}
		if !bytes.Equal(got[x:], want[x:]) {
			t.Fatalf("from %d: exact region differs", p.comp)
		}
		// With the true history, everything is exact.
		d = NewExact(bytes.NewReader(comp), p.comp, data[max(0, p.out-winSize):p.out])
		if got := readAll(t, d); !bytes.Equal(got, want) || d.ExactFrom() != 0 {
			t.Fatalf("from %d with history: wrong output", p.comp)
		}
	}
}

func TestTooFarFromStart(t *testing.T) {
	data := sample(1 << 20)
	comp := pigzRaw(data)
	var mid int64
	d := NewExact(bytes.NewReader(comp), 0, nil)
	d.OnBoundary = func(c, o int64) {
		if mid == 0 && o > 200<<10 {
			mid = c
		}
	}
	readAll(t, d)
	// Claiming the stream starts mid-way is caught by the first reference back.
	if _, err := io.ReadAll(NewExact(bytes.NewReader(comp), mid, nil)); err == nil {
		t.Fatal("want an error decoding mid-stream as if from the start")
	}
}

func TestTruncated(t *testing.T) {
	comp := compress(t, sample(1<<20), 6, 128<<10)
	if _, err := io.ReadAll(NewExact(bytes.NewReader(comp[:len(comp)/2]), 0, nil)); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated stream: %v", err)
	}
}

func deflate(t *testing.T, data []byte, level int) []byte {
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, level)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	w.Close()
	return b.Bytes()
}

func TestFind(t *testing.T) {
	data := sample(4 << 20)
	// Stored blocks whose payload is itself deflate data, as an APK inside a
	// system image is: the inner blocks parse, but are not where to enter.
	nested := append(sample(100<<10), deflate(t, data, 6)...)
	streams := map[string]struct{ data, comp []byte }{
		"pigz":   {data, pigzRaw(data)},
		"nested": {nested, deflate(t, nested, flate.NoCompression)},
	}
	for name, s := range streams {
		data, comp := s.data, s.comp
		starts := map[int64]int64{}
		d := NewExact(bytes.NewReader(comp), 0, nil)
		d.OnBoundary = func(bit, out int64) { starts[bit] = out }
		readAll(t, d)
		if len(starts) < 4 {
			t.Fatalf("%s: only %d blocks", name, len(starts))
		}
		for _, from := range []int64{1000, int64(len(comp)) / 3, int64(len(comp)) / 2} {
			bit, err := Find(bytes.NewReader(comp), from, int64(len(comp)), 16<<20)
			if err != nil {
				t.Fatalf("%s from %d: %v", name, from, err)
			}
			out, ok := starts[bit]
			if !ok {
				t.Fatalf("%s from %d: bit %d is not a block start", name, from, bit)
			}
			u := NewUnknown(bytes.NewReader(comp), bit)
			got := readAll(t, u)
			if x := u.ExactFrom(); !bytes.Equal(got[x:], data[out+x:]) {
				t.Fatalf("%s from %d: wrong output", name, from)
			}
		}
	}
	// Without stored blocks nothing confirms a parse, so nothing is offered.
	plain := deflate(t, data, 6)
	if _, err := Find(bytes.NewReader(plain), 1000, int64(len(plain)), 16<<20); err != ErrNoBlock {
		t.Fatalf("plain deflate: %v, want ErrNoBlock", err)
	}
}

// pigzRaw is the raw deflate stream of a pigz-shaped gzip.
func pigzRaw(data []byte) []byte {
	gz := pigztest.Gzip(data, 128<<10)
	return gz[10 : len(gz)-8]
}
