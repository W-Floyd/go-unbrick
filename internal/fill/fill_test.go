package fill

import (
	"bytes"
	"strings"
	"testing"
)

func TestPeriod(t *testing.T) {
	for name, tc := range map[string]struct {
		data []byte
		want int
	}{
		"zeros":      {make([]byte, 4096), 1},
		"ff":         {bytes.Repeat([]byte{0xff}, 1024), 1},
		"four bytes": {bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 300), 4},
		"odd period": {bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7}, 200), 7},
		"too short":  {make([]byte, 100), 0},
		"one off":    {append(make([]byte, 1000), 1), 0},
		"sentence":   {bytes.Repeat([]byte("hello world, this is text. "), 100), 27}, // a repeated sentence is a fill too
		"ten":        {bytes.Repeat([]byte("0123456789"), 100)[:999], 10},
	} {
		if got := Period(tc.data); got != tc.want {
			t.Errorf("%s: period %d, want %d", name, got, tc.want)
		}
	}
	if Period(bytes.Repeat([]byte{1, 2, 3}, 400)[:1000]) != 3 {
		t.Error("a pattern cut mid-repeat is still the pattern")
	}
}

func scan(t *testing.T, data []byte) Result {
	t.Helper()
	head := data[:min(len(data), 8192)]
	res, err := Scan(bytes.NewReader(data[len(head):]), head, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestScanWholeFile(t *testing.T) {
	zeros := make([]byte, 3<<20+17)
	if r := scan(t, zeros); !r.Whole || r.Describe() != "every byte is 0x00 (zeros)" {
		t.Errorf("zeros: %+v %s", r, r.Describe())
	}
	pat := bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 600000)
	if r := scan(t, pat); !r.Whole || !strings.Contains(r.Describe(), "4-byte pattern repeated: de ad be ef") {
		t.Errorf("pattern: %+v %s", r, r.Describe())
	}
	// A pattern whose phase at the end of the head is not zero.
	odd := bytes.Repeat([]byte{1, 2, 3}, 1<<19)
	if r := scan(t, odd); !r.Whole {
		t.Errorf("odd phase: %+v", r)
	}
}

func TestScanStopsAtTheFirstDeviation(t *testing.T) {
	data := make([]byte, 5<<20)
	data[3<<20+5] = 1
	r := scan(t, data)
	if r.Whole || r.Break != 3<<20+5 {
		t.Errorf("%+v", r)
	}
	// A head that is no fill reads nothing more.
	if r, err := Scan(&failReader{}, []byte("not a fill at all"), 1<<30); err != nil || r.Pattern != nil || r.Whole {
		t.Errorf("%+v %v", r, err)
	}
	// A file that is only its head.
	if r := scan(t, make([]byte, 2048)); !r.Whole {
		t.Errorf("head only: %+v", r)
	}
}

type failReader struct{}

func (*failReader) Read([]byte) (int, error) { panic("read a file that cannot be a fill") }
