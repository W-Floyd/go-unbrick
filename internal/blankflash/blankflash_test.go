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

// A forged recipe must carry the donor's backup/restore directives. Every
// genuine Motorola blankflash brackets the flash with them to preserve the
// partitions holding per-device state; a package that drops them can lose that
// state when the GPT it flashes moves those partitions.
func TestForgeCarriesDonorBackupDirectives(t *testing.T) {
	donorRecipe := []byte(`<?xml version="1.0" ?>
<recipe>
	<backup name="cid"/>
	<backup name="frp"/>
	<backup name="utags"/>
	<backup name="xbl_a"        skip="true"/>
	<backup commit="1"/>
	<configure MemoryName="UFS" SkipStorageInit="1"/>
	<flash partition="xbl_a" filename="xbl.elf" verbose="true"/>
	<restore dummy="foo"/>
</recipe>`)
	d := &Donor{
		Programmer: []byte("LOADER"),
		Recipes:    map[string][]byte{"default.xml": donorRecipe},
	}
	tgt := &Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("XBL")},
		FlashMap: map[string]string{"xbl": "xbl.elf"},
		GPT:      []byte("GPT"),
		Storage:  "ufs",
	}
	res, err := Forge(d, tgt, "a", "ufs", nil)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := Parse(res.Singleimage)
	if err != nil {
		t.Fatal(err)
	}
	var recipe string
	for _, r := range recs {
		if r.Name == "default.xml" {
			recipe = string(r.Data)
		}
	}
	if recipe == "" {
		t.Fatal("no default.xml in the forged package")
	}
	for _, want := range []string{
		`<backup name="cid"/>`,
		`<backup name="frp"/>`,
		`<backup name="utags"/>`,
		`<backup commit="1"/>`,
		`<restore dummy="foo"/>`,
	} {
		if !strings.Contains(recipe, want) {
			t.Errorf("forged recipe dropped %s\n%s", want, recipe)
		}
	}
	// Backups must precede the flash steps, and the restore must follow them.
	if strings.Index(recipe, `<backup name="cid"/>`) > strings.Index(recipe, "<flash ") {
		t.Error("backups must come before the flash steps")
	}
	if strings.Index(recipe, "<restore") < strings.LastIndex(recipe, "<flash ") {
		t.Error("restore must come after the flash steps")
	}
}

// A donor with no recipe must be reported, not silently forged without the
// protection.
func TestForgeWarnsWhenDonorHasNoBackups(t *testing.T) {
	d := &Donor{Programmer: []byte("LOADER")}
	tgt := &Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("XBL")},
		FlashMap: map[string]string{"xbl": "xbl.elf"},
		GPT:      []byte("GPT"),
	}
	res, err := Forge(d, tgt, "a", "emmc", nil)
	if err != nil {
		t.Fatal(err)
	}
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "<backup>") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected a warning about missing backup directives, got %v", res.Warnings)
	}
}

// Which partitions a device flashes varies by SoC. Validating 113 forged
// packages against their genuine counterparts found a fixed list silently
// omitting aop on 65 devices, cmnlib/cmnlib64 on 34, cpucp/shrm on 28 and
// more, so the device's own recipe order is what must drive the flash steps.
func TestForgeFlashesEverySoCPartition(t *testing.T) {
	order := []string{"abl", "cmnlib", "cmnlib64", "devcfg", "aop", "xbl"}
	tgt := &Target{
		Parts: map[string][]byte{
			"abl.elf": []byte("A"), "cmnlib.mbn": []byte("C"), "cmnlib64.mbn": []byte("C6"),
			"devcfg.mbn": []byte("D"), "aop.mbn": []byte("AO"), "xbl.elf": []byte("X"),
		},
		FlashMap: map[string]string{
			"abl": "abl.elf", "cmnlib": "cmnlib.mbn", "cmnlib64": "cmnlib64.mbn",
			"devcfg": "devcfg.mbn", "aop": "aop.mbn", "xbl": "xbl.elf",
		},
		FlashOrder: order,
		GPT:        []byte("GPT"),
	}
	res, err := Forge(&Donor{Programmer: []byte("L")}, tgt, "a", "ufs", nil)
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := Parse(res.Singleimage)
	var recipe string
	names := map[string]bool{}
	for _, r := range recs {
		names[r.Name] = true
		if r.Name == "default.xml" {
			recipe = string(r.Data)
		}
	}
	// Every mapped partition must be both flashed and carried.
	for _, label := range order {
		fn := tgt.FlashMap[label]
		if !strings.Contains(recipe, `partition="`+label+`_a"`) {
			t.Errorf("recipe does not flash %s", label)
		}
		if !names[fn] {
			t.Errorf("package does not carry %s", fn)
		}
	}
	// And in the device's own order, not the fallback's.
	if i, j := strings.Index(recipe, `"cmnlib_a"`), strings.Index(recipe, `"devcfg_a"`); i > j {
		t.Error("flash order should follow the device's recipe")
	}
}

// With no recipe to go on, the fallback list still produces a usable package.
func TestForgeFallsBackWithoutFlashOrder(t *testing.T) {
	tgt := &Target{
		Parts:    map[string][]byte{"xbl.elf": []byte("X"), "abl.elf": []byte("A")},
		FlashMap: map[string]string{"xbl": "xbl.elf", "abl": "abl.elf"},
		GPT:      []byte("GPT"),
	}
	res, err := Forge(&Donor{Programmer: []byte("L")}, tgt, "a", "emmc", nil)
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := Parse(res.Singleimage)
	var recipe string
	for _, r := range recs {
		if r.Name == "default.xml" {
			recipe = string(r.Data)
		}
	}
	for _, want := range []string{`partition="abl_a"`, `partition="xbl_a"`} {
		if !strings.Contains(recipe, want) {
			t.Errorf("fallback recipe missing %s", want)
		}
	}
	// xbl is flashed last in Motorola's order; the fallback must keep that.
	if strings.Index(recipe, `"xbl_a"`) < strings.Index(recipe, `"abl_a"`) {
		t.Error("xbl should be flashed last")
	}
}
