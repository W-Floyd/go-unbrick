package main

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// A stretch with nothing shared is drawn as a low bar, not left blank: a blank
// cell reads as "no data" rather than "only in this file".
func TestMapBarDrawsUnsharedCells(t *testing.T) {
	got := plain(mapBar([]float64{0, 1, 0.6, 0.2, 0}))
	if got != "▁█▅▂▁" {
		t.Errorf("mapBar = %q, want %q", got, "▁█▅▂▁")
	}
	if strings.Contains(got, " ") {
		t.Errorf("a cell was left blank: %q", got)
	}
	// And the legend says what the colours and heights mean, blank not among them.
	out := plain(renderOverlap(analysis.Compare([]byte("a"), []byte("b")), false, false))
	for _, want := range []string{"tall green = shared", "yellow = partly", "low red = only in this one"} {
		if !strings.Contains(out, want) {
			t.Errorf("the legend lacks %q:\n%s", want, out)
		}
	}
}

// A count of bytes carries its own unit, so it cannot be read as the size beside it.
func TestByteCountsSayBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 bytes", 1: "1 byte", 2: "2 bytes", 31: "31 bytes", 103: "103 bytes"} {
		if got := byteCount(n); got != want {
			t.Errorf("byteCount(%d) = %q, want %q", n, got, want)
		}
	}
	// 31 differing bytes outside 21.1 MiB of non-string bytes, as in a kernel image.
	got := plain(verdictLine(detailOf(append(make([]byte, 100), 1, 2, 3), append(make([]byte, 100), 1, 2, 4))))
	if !strings.Contains(got, "1 byte of the") || !strings.Contains(got, "differs too") {
		t.Errorf("verdict: %q", got)
	}
	long := make([]byte, 3<<20) // 3 MiB outside strings; 31 bytes of them differ
	other := append([]byte(nil), long...)
	for i := 0; i < 31; i++ {
		other[i*1000] = 1
	}
	got = plain(verdictLine(detailOf(long, other)))
	if !strings.Contains(got, "31 bytes of the 3.0 MiB outside printable strings differ too") {
		t.Errorf("a count beside a size must say bytes: %q", got)
	}
	// And the overlap line.
	o := plain(renderOverlap(analysis.Compare([]byte("abcdefgh"), []byte("abcdefgX")), false, false))
	if !strings.Contains(o, "1 byte differs at the same offset") {
		t.Errorf("overlap: %s", o)
	}
}

func detailOf(a, b []byte) *analysis.Detail {
	return analysis.Analyse(a, b, int64(len(a)), int64(len(b)), analysis.Options{})
}
