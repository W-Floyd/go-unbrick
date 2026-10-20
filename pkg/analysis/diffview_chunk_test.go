package analysis

import (
	"fmt"
	"strings"
	"testing"
)

// A small file with a few scattered edits is mostly shared. With chunks of
// about 4 KiB it was about 92% "unique": one or two chunks, each holding a change.
func TestASmallFileWithScatteredEditsIsMostlyShared(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 230; i++ {
		fmt.Fprintf(&a, "ro.prop.%03d=value-%03d-padding\n", i, i)
		if i%23 == 5 { // ten lines changed, same length
			fmt.Fprintf(&b, "ro.prop.%03d=value-%03d-PADDING\n", i, i+500)
			continue
		}
		fmt.Fprintf(&b, "ro.prop.%03d=value-%03d-padding\n", i, i)
	}
	o := Compare([]byte(a.String()), []byte(b.String()))
	if o.SizeA != o.SizeB || o.SizeA < 6<<10 || o.SizeA > 8<<10 {
		t.Fatalf("test file is %d bytes", o.SizeA)
	}
	if o.Differing < 20 || o.Differing > 100 {
		t.Fatalf("%d bytes differ; the test means about 70", o.Differing)
	}
	if o.Chunk != 0 {
		t.Errorf("a %d byte file, alike on both sides, was measured in chunks of %d: it should be byte for byte", o.SizeA, o.Chunk)
	}
	uniquePct := 100 * float64(o.UniqueA()) / float64(o.SizeA)
	if uniquePct > 3 { // 80 of 6900 bytes differ: about 1%
		t.Errorf("%.1f%% of a is unique though only %d of %d bytes differ", uniquePct, o.Differing, o.SizeA)
	}
	// It cannot claim less is unique than actually differs.
	if o.UniqueA() < o.Differing || o.UniqueB() < o.Differing {
		t.Errorf("unique %d / %d is less than the %d bytes that differ", o.UniqueA(), o.UniqueB(), o.Differing)
	}
	// And the other end of it: a file with every line changed is nearly all unique.
	var c strings.Builder
	for i := 0; i < 230; i++ {
		fmt.Fprintf(&c, "completely.different.%03d=%03d-other\n", i*7, i*13)
	}
	if o := Compare([]byte(a.String()), []byte(c.String())); float64(o.SharedA)/float64(o.SizeA) > 0.2 {
		t.Errorf("an unrelated file shares %d of %d bytes", o.SharedA, o.SizeA)
	}
}

// Past the size measured byte for byte, chunks, small enough for the file: ten
// one-byte edits in 200 KiB are a few percent unique, not most of it.
func TestAMidSizeFileIsMeasuredInChunksOfItsOwnScale(t *testing.T) {
	a := randBytes(41, 200<<10)
	b := append([]byte(nil), a...)
	for i := 0; i < 10; i++ {
		b[i*20000+500] ^= 0xff
	}
	o := Compare(a, b)
	if o.Chunk < 512 || o.Chunk > 2048 {
		t.Errorf("chunks of about %d bytes for 200 KiB, want 1 KiB or so", o.Chunk)
	}
	if pct := 100 * float64(o.UniqueA()) / float64(o.SizeA); pct > 25 || o.Differing != 10 {
		t.Errorf("%.1f%% unique for 10 one-byte edits in 200 KiB (%d bytes differ)", pct, o.Differing)
	}
	if o.UniqueA() < o.Differing {
		t.Errorf("unique %d is less than the %d bytes that differ", o.UniqueA(), o.Differing)
	}
}

// Exactness does not make unrelated files look alike, or cost a slow diff.
func TestSmallUnrelatedFilesStayUnrelated(t *testing.T) {
	o := Compare(randBytes(51, 50<<10), randBytes(52, 50<<10))
	if o.SharedA != 0 || o.SharedB != 0 {
		t.Errorf("unrelated random data shares %d / %d bytes", o.SharedA, o.SharedB)
	}
	if o.Chunk == 0 {
		t.Error("files with nothing in common were run through the exact diff")
	}
}

func TestChunkSizeScalesWithTheFile(t *testing.T) {
	for _, c := range []struct{ size, want int }{
		{0, 64}, {1 << 10, 64}, {6 << 10, 64}, {16 << 10, 64}, {17 << 10, 128},
		{400 << 10, 2048}, {1 << 20, 4096}, {22 << 20, 4096}, {1 << 30, 4096},
	} {
		got := chunkerFor(c.size)
		if got.avg != c.want {
			t.Errorf("chunkerFor(%d).avg = %d, want %d", c.size, got.avg, c.want)
		}
		if got.min < 16 || got.min > got.avg || got.max < got.avg {
			t.Errorf("chunkerFor(%d) = %+v: min and max must bracket the average", c.size, got)
		}
		if got.mask != uint64(got.avg-1) {
			t.Errorf("chunkerFor(%d).mask = %x, want a mask for %d", c.size, got.mask, got.avg)
		}
	}
	// What is reported is what was used.
	if o := Compare(randBytes(1, 5<<20), randBytes(1, 5<<20)); o.Chunk != 4096 {
		t.Errorf("a 5 MiB comparison reports chunks of %d", o.Chunk)
	}
}

// Both sides are cut the same way, whichever is the larger, or identical content
// would not match.
func TestBothSidesAreChunkedAlike(t *testing.T) {
	a := randBytes(7, 40<<10)
	b := append(append([]byte(nil), a...), randBytes(8, 200<<10)...) // b is far larger
	o := Compare(a, b)
	if frac := float64(o.SharedA) / float64(o.SizeA); frac < 0.9 {
		t.Errorf("only %.0f%% of a is found in b, which contains all of it", 100*frac)
	}
}
