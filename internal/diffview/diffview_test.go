package diffview

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestIsText(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty", nil, true},
		{"ascii", []byte("hello\nworld\n"), true},
		{"utf8", []byte("héllo wörld ✓\n"), true},
		{"nul", []byte("abc\x00def"), false},
		{"binary", []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, false},
		{"latin1", []byte("caf\xe9 au lait"), false},
		{"controls", bytes.Repeat([]byte{1, 2, 3, 'a'}, 100), false},
	}
	for _, c := range cases {
		if got := IsText(c.in); got != c.want {
			t.Errorf("%s: IsText = %v, want %v", c.name, got, c.want)
		}
	}
	// A multi-byte character cut by the 64 KiB sample is still text.
	cut := append(bytes.Repeat([]byte("a"), 64<<10-1), []byte("✓ and more")...)
	if !IsText(cut) {
		t.Error("a character cut by the sample made text binary")
	}
}

func TestTextDiff(t *testing.T) {
	var a, b strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&a, "line %d\n", i)
		switch i {
		case 10:
			fmt.Fprintf(&b, "line ten\n")
		case 50:
			// deleted
		default:
			fmt.Fprintf(&b, "line %d\n", i)
		}
		if i == 80 {
			fmt.Fprintf(&b, "inserted after 80\n")
		}
	}
	lines, st, trunc := TextDiff([]byte(a.String()), []byte(b.String()), 2)
	if trunc {
		t.Fatal("truncated")
	}
	if st.Removed != 2 || st.Added != 2 || st.Same != 98 {
		t.Errorf("stats %+v, want 2 removed, 2 added, 98 same", st)
	}
	var hunks, minus, plus int
	for _, l := range lines {
		switch l.Op {
		case '@':
			hunks++
		case '-':
			minus++
		case '+':
			plus++
		}
	}
	if hunks != 3 {
		t.Errorf("%d hunks, want 3 (changes at 10, 50 and 80 are far apart)", hunks)
	}
	if minus != 2 || plus != 2 {
		t.Errorf("%d removed %d added lines shown", minus, plus)
	}
	// Context is limited: far from any change nothing is shown.
	for _, l := range lines {
		if l.Text == "line 30" || l.Text == "line 95" {
			t.Errorf("%q shown, nowhere near a change", l.Text)
		}
	}
	// Line numbers on each side.
	for _, l := range lines {
		if l.Op == '-' && l.Text == "line 50" && l.A != 50 {
			t.Errorf("removed line 50 numbered %d", l.A)
		}
		if l.Op == '+' && l.Text == "inserted after 80" && l.B != 80 {
			t.Errorf("inserted line numbered %d, want 80 in b", l.B)
		}
	}
	if lines[0].Op != '@' || !strings.HasPrefix(lines[0].Text, "@@ -8,") {
		t.Errorf("first hunk header %q", lines[0].Text)
	}
}

func TestTextDiffIdenticalAndNoTrailingNewline(t *testing.T) {
	if lines, st, _ := TextDiff([]byte("same\n"), []byte("same\n"), 3); lines != nil || st.Added+st.Removed != 0 {
		t.Errorf("identical text produced %v %+v", lines, st)
	}
	lines, st, _ := TextDiff([]byte("a\nb"), []byte("a\nc"), 1)
	if st.Added != 1 || st.Removed != 1 {
		t.Errorf("no trailing newline: %+v %v", st, lines)
	}
}

func TestStrings(t *testing.T) {
	data := []byte("\x00\x01ab\x00hello world\x00\x02\x03short\x00")
	data = append(data, 0xff, 0xfe)
	for _, c := range "wide string" { // UTF-16LE
		data = append(data, byte(c), 0)
	}
	data = append(data, 0, 0, 0x01)
	got := Strings(data, 6)
	want := []string{"hello world", "wide string"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Strings = %q, want %q", got, want)
	}
	if got := Strings([]byte("ab\x00cd"), 6); len(got) != 0 {
		t.Errorf("short runs kept: %q", got)
	}
}

func TestStringDiffFindsTextAddedToABinary(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	body := make([]byte, 5000)
	r.Read(body)
	for i, b := range body { // keep it free of accidental strings
		if b >= 0x20 && b < 0x7f {
			body[i] = 0
		}
	}
	a := append(append([]byte("version=1.0.0\x00"), body...), "build: alpha-release\x00"...)
	b := append(append([]byte("version=1.0.1\x00"), body...), "build: alpha-release\x00feature flag enabled\x00"...)
	lines, st, _ := StringDiff(a, b, 6, 1)
	var minus, plus []string
	for _, l := range lines {
		switch l.Op {
		case '-':
			minus = append(minus, l.Text)
		case '+':
			plus = append(plus, l.Text)
		}
	}
	if st.Removed != 1 || st.Added != 2 || minus[0] != "version=1.0.0" || plus[0] != "version=1.0.1" || plus[1] != "feature flag enabled" {
		t.Errorf("-%q +%q %+v", minus, plus, st)
	}
}

func randBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func TestOverlapIdentical(t *testing.T) {
	a := randBytes(1, 200<<10)
	o := Compare(a, a)
	if o.SharedA != o.SizeA || o.SharedB != o.SizeB || o.UniqueA() != 0 || o.Differing != 0 || o.FirstDiff != -1 || o.Prefix != o.SizeA {
		t.Errorf("identical: %+v", o)
	}
	for i, v := range o.MapA {
		if v != 1 {
			t.Fatalf("map cell %d = %v, want fully shared", i, v)
		}
	}
}

func TestOverlapUnrelated(t *testing.T) {
	o := Compare(randBytes(1, 200<<10), randBytes(2, 200<<10))
	if o.SharedA != 0 || o.SharedB != 0 {
		t.Errorf("unrelated random data shares %d / %d bytes", o.SharedA, o.SharedB)
	}
	if o.Differing < 150<<10 {
		t.Errorf("differing %d bytes of 200 KiB random", o.Differing)
	}
}

// An insertion shifts everything after it; fixed-offset comparison calls the
// rest different, content-defined chunks still find it shared.
func TestOverlapSurvivesAnInsertion(t *testing.T) {
	a := randBytes(3, 400<<10)
	ins := randBytes(4, 3000)
	b := append(append(append([]byte(nil), a[:100<<10]...), ins...), a[100<<10:]...)
	o := Compare(a, b)
	if frac := float64(o.SharedA) / float64(o.SizeA); frac < 0.95 {
		t.Errorf("only %.0f%% of a is found in b after a 3 KB insertion", 100*frac)
	}
	if u := o.UniqueB(); u < 2000 || u > 40<<10 {
		t.Errorf("unique to b = %d bytes, want about the 3000 inserted (plus chunk edges)", u)
	}
	if o.Prefix != 100<<10 {
		t.Errorf("common prefix %d, want %d", o.Prefix, 100<<10)
	}
	if o.Differing != -1 {
		t.Errorf("Differing = %d for unequal sizes, want -1", o.Differing)
	}
	// The map shows the insert as the one unshared stretch of b.
	low := 0
	for _, v := range o.MapB {
		if v < 0.5 {
			low++
		}
	}
	if low < 1 || low > 4 {
		t.Errorf("%d unshared cells in b's map, want the inserted stretch only", low)
	}
}

func TestOverlapEqualSizeOneByteChanged(t *testing.T) {
	a := randBytes(5, 100<<10)
	b := append([]byte(nil), a...)
	b[70000] ^= 0xff
	o := Compare(a, b)
	if o.Differing != 1 || o.FirstDiff != 70000 || o.Prefix != 70000 || o.Suffix != int64(len(a))-70001 {
		t.Errorf("%+v", o)
	}
	if frac := float64(o.SharedA) / float64(o.SizeA); frac < 0.8 {
		t.Errorf("only %.0f%% shared after a one-byte change", 100*frac)
	}
}

func TestOverlapEmpty(t *testing.T) {
	o := Compare(nil, randBytes(6, 5000))
	if o.SizeA != 0 || o.SharedB != 0 || o.UniqueB() != 5000 {
		t.Errorf("%+v", o)
	}
}

func utf16le(s string) []byte {
	var b []byte
	for _, c := range s {
		b = append(b, byte(c), 0)
	}
	return b
}

func TestStringsOnly(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	body := func(n int) []byte { // random, with nothing printable in it
		b := make([]byte, n)
		r.Read(b)
		for i, c := range b {
			if c >= 0x20 && c < 0x7f {
				b[i] = 0x01
			}
		}
		return b
	}
	head, tail := body(3000), body(3000)
	build := func(strs ...string) []byte {
		// Strings sit NUL-terminated and back to back, as in a string table.
		out := append(append([]byte(nil), head...), 0x01)
		for _, s := range strs {
			out = append(out, s...)
			out = append(out, 0)
		}
		return append(out, tail...)
	}

	cases := []struct {
		name string
		a, b []byte
		only bool
	}{
		{"same-length string changed", build("version=1.0.0", "keep this one"), build("version=1.0.1", "keep this one"), true},
		{"string grew", build("name=short"), build("name=much much longer value"), true},
		{"string removed", build("first string", "second string"), build("first string"), true},
		{"string added", build("only" + " one!"), build("only one!", "and a brand new one"), true},
		{"identical", build("same string"), build("same string"), false},
		{"non-string byte changed", append(build("x string"), 0x09, 0x01), append(build("x string"), 0x0a, 0x01), false},
		{"string and non-string both changed", func() []byte { a := build("version=1.0.0"); return a }(), func() []byte { b := build("version=1.0.1"); b[100] ^= 0xff; return b }(), false},
		{"run too short to be a string differs", append(build("long enough string"), 'a', 'b', 0), append(build("long enough string"), 'a', 'c', 0), false},
		{"utf-16 string changed", append(append([]byte(nil), head...), utf16le("wide version 1")...), append(append([]byte(nil), head...), utf16le("wide version 2")...), true},
	}
	for _, c := range cases {
		v := StringsOnly(c.a, c.b, 6)
		if v.Only != c.only {
			t.Errorf("%s: Only = %v, want %v (%+v)", c.name, v.Only, c.only, v)
		}
		if c.only && v.ResidueDiffering != 0 {
			t.Errorf("%s: residue differs by %d though only strings differ", c.name, v.ResidueDiffering)
		}
	}

	// The numbers: bytes inside strings vs outside, and how many outside differ.
	v := StringsOnly(build("version=1.0.0"), build("version=1.0.0", "a second string"), 6)
	// The added string and its NUL are inside strings; nothing else moved.
	if v.StringBytesB-v.StringBytesA != int64(len("a second string"))+1 || v.ResidueA != v.ResidueB {
		t.Errorf("accounting: %+v", v)
	}
	a := build("x string here")
	b := append([]byte(nil), a...)
	b[10] ^= 0xff
	b[20] ^= 0xff
	if v := StringsOnly(a, b, 6); v.Only || v.ResidueDiffering != 2 {
		t.Errorf("two non-string bytes changed: %+v", v)
	}
	// Different sizes outside strings: not comparable byte for byte.
	if v := StringsOnly(a, append(append([]byte(nil), a...), 0x01), 6); v.Only || v.ResidueDiffering != -1 {
		t.Errorf("extra trailing byte: %+v", v)
	}
}

// What Residue removes is what Strings lists: the two cannot disagree.
func TestResidueRemovesExactlyTheStrings(t *testing.T) {
	data := append([]byte("\x01\x02hello world\x00\x03"), utf16le("wide text")...)
	data = append(data, 0x04, 'a', 'b', 0x05) // too short to count
	res := Residue(data, 6)
	// "hello world" goes with the NUL that ends it; the short "ab" stays.
	if string(res) != "\x01\x02\x03\x04ab\x05" {
		t.Errorf("residue %q", res)
	}
	got := Strings(data, 6)
	if len(got) != 2 || got[0] != "hello world" || got[1] != "wide text" {
		t.Errorf("strings %q", got)
	}
}
