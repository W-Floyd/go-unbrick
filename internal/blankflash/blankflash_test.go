package blankflash

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
)

func orderedNames(blob []byte) []string {
	recs, err := Parse(blob)
	if err != nil {
		panic(err)
	}
	var out []string
	for _, r := range recs {
		if r.Name != Trailer {
			out = append(out, r.Name)
		}
	}
	return out
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestRoundtripSynthetic(t *testing.T) {
	recs := WithTrailer([]Record{
		{Name: "index.xml", Data: []byte("<index/>")},
		{Name: "programmer.elf", Data: append([]byte("\x7fELF"), make([]byte, 5000)...)},
		{Name: "xbl.elf", Data: randBytes(0x1000)}, // already page-aligned
		{Name: "gpt.bin", Data: randBytes(123)},
	})
	blob, err := Build(recs)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(recs) {
		t.Fatalf("record count: got %d want %d", len(back), len(recs))
	}
	for i := range recs {
		if back[i].Name != recs[i].Name {
			t.Errorf("record %d name: got %q want %q", i, back[i].Name, recs[i].Name)
		}
		if !bytes.Equal(back[i].Data, recs[i].Data) {
			t.Errorf("record %d data differs", i)
		}
	}
	// rebuilding the parsed records is a fixed point
	rebuilt, err := Build(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt, blob) {
		t.Error("rebuild is not a fixed point")
	}
}

func TestHeaderLayout(t *testing.T) {
	blob, err := Build(WithTrailer([]Record{{Name: "programmer.elf", Data: []byte("abc")}}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[:16], Magic) {
		t.Fatalf("magic mismatch")
	}
	// first record header sits at 0x100; name at 0, size u64 at 0xf8
	if !bytes.Equal(blob[0x100:0x100+14], []byte("programmer.elf")) {
		t.Errorf("name not at 0x100")
	}
	if got := binary.LittleEndian.Uint64(blob[0x100+0xF8:]); got != 3 {
		t.Errorf("size field: got %d want 3", got)
	}
	if !bytes.Equal(blob[0x200:0x203], []byte("abc")) {
		t.Errorf("content not at 0x200")
	}
}

func TestForgeShape(t *testing.T) {
	donor := &Donor{
		Programmer: append([]byte("\x7fELF"), bytes.Repeat([]byte("L"), 1000)...),
		Recipes:    map[string][]byte{},
		CPUName:    "SM_DIVAR",
		Storage:    "UFS",
	}
	target := &Target{
		Parts:    map[string][]byte{"xbl.elf": bytes.Repeat([]byte("x"), 200), "abl.elf": bytes.Repeat([]byte("a"), 200)},
		FlashMap: map[string]string{"xbl": "xbl.elf", "abl": "abl.elf"},
		GPT:      bytes.Repeat([]byte("g"), 500),
		Storage:  "emmc",
	}
	res, err := Forge(donor, target, "a", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	names := orderedNames(res.Singleimage)
	want := []string{"index.xml", "pkg.xml", "default.xml", "programmer.elf"}
	for i, w := range want {
		if names[i] != w {
			t.Fatalf("names[%d]: got %q want %q", i, names[i], w)
		}
	}
	idx := Index(mustParse(t, res.Singleimage))
	if _, ok := idx["gpt.bin"]; !ok {
		t.Error("missing gpt.bin")
	}
	if _, ok := idx["xbl.elf"]; !ok {
		t.Error("missing xbl.elf")
	}
	recipe := string(idx["default.xml"])
	if !strings.Contains(recipe, `MemoryName="emmc"`) {
		t.Errorf("target storage should win over donor UFS; recipe=%s", recipe)
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "storage") {
			warned = true
		}
	}
	if !warned {
		t.Error("emmc vs UFS mismatch not flagged")
	}
}

func mustParse(t *testing.T, blob []byte) []Record {
	t.Helper()
	recs, err := Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestPadNonNegative(t *testing.T) {
	for _, n := range []int{0, 1, 0xfff, 0x1000, 0x1001, 123456} {
		p := pad(n)
		if p < 0 || p >= page {
			t.Errorf("pad(%d)=%d out of range", n, p)
		}
		if (n+p)%page != 0 {
			t.Errorf("pad(%d)=%d does not align", n, p)
		}
	}
}

// FuzzRoundtrip: any set of records survives Build->Parse->Build byte-exact.
func FuzzRoundtrip(f *testing.F) {
	f.Add([]byte("index.xml"), []byte("abc"), uint16(0))
	f.Add([]byte("x"), []byte(""), uint16(0x1000))
	f.Fuzz(func(t *testing.T, name, data []byte, extra uint16) {
		n := string(name)
		if len(n) == 0 || len(n) > 247 || strings.ContainsRune(n, 0) || n == Trailer {
			t.Skip()
		}
		d := append(append([]byte{}, data...), make([]byte, int(extra)%0x2000)...)
		recs := WithTrailer([]Record{{Name: n, Data: d}})
		blob, err := Build(recs)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(blob)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, err := Build(back)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rebuilt, blob) {
			t.Fatalf("not a fixed point for name=%q len(data)=%d", n, len(d))
		}
	})
}
