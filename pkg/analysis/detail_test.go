package analysis

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAnalyseText(t *testing.T) {
	a, b := []byte("one\nlet x = price;\n"), []byte("one\nlet x = cost;\n")
	d := Analyse(a, b, int64(len(a)), int64(len(b)), Options{Words: true})
	if !d.Text || d.Diff == nil || d.Diff.Stats.Added != 1 || d.Verdict != nil || d.Overlap != nil {
		t.Fatalf("%+v", d)
	}
	marked := 0
	for _, l := range d.Diff.Lines {
		if len(l.Hi) > 0 {
			marked++
		}
	}
	if marked != 2 {
		t.Errorf("%d lines have marked words, want 2", marked)
	}
	if plain := Analyse(a, b, 100, 1, Options{}); plain.Diff.Lines[2].Hi != nil || !plain.A.Truncated {
		t.Errorf("without words: %+v, truncated=%v", plain.Diff.Lines, plain.A.Truncated)
	}
}

func TestAnalyseBinaryAutoShowsOverlapHexAndStrings(t *testing.T) {
	a := bytes.Repeat([]byte{0, 1, 2, 3}, 500)
	b := append([]byte(nil), a...)
	b[40], b[41] = 0xde, 0xad
	d := Analyse(a, b, 2000, 2000, Options{})
	if d.Text || d.Verdict == nil || d.Overlap == nil || d.Hex == nil || d.Strings == nil || !d.StringsPeek {
		t.Fatalf("%+v", d)
	}
	h := d.Hex.Hunks[0]
	if d.Hex.Total != 2 || h.OffA != 40 || h.A.Offset != 32 || h.A.From != 8 || h.A.To != 10 || len(h.A.Bytes) != 16 || h.B.Bytes[8] != 0xde {
		t.Errorf("hex: %+v", d.Hex)
	}
	// Many differing bytes: unasked, no hex; asked for, a budget of them.
	a = bytes.Repeat([]byte{0, 1, 2, 3}, 2000)
	many := append([]byte(nil), a...)
	for i := 0; i < len(many); i += 16 {
		many[i] ^= 0xff
	}
	if d := Analyse(a, many, 8000, 8000, Options{}); d.Hex != nil {
		t.Error("unasked hex for many differing bytes")
	}
	hx := Analyse(a, many, 8000, 8000, Options{View: ViewHex, HexBudget: 100})
	if hx.Hex == nil || hx.Hex.More == 0 || len(hx.Hex.Hunks) == 0 || hx.Overlap != nil {
		t.Errorf("hex view: %+v", hx.Hex)
	}
	if _, err := json.Marshal(hx); err != nil {
		t.Errorf("not JSON-serialisable: %v", err)
	}
}

func TestAnalyseViewsAreSelfContained(t *testing.T) {
	a, b := []byte("\x00\x01hello world\x00"), []byte("\x00\x01hello there\x00")
	if d := Analyse(a, b, 14, 14, Options{View: ViewOverlap}); d.Overlap == nil || d.Strings != nil || d.Hex != nil {
		t.Errorf("overlap view: %+v", d)
	}
	if d := Analyse(a, b, 14, 14, Options{View: ViewStrings}); d.Strings == nil || d.StringsPeek || d.Overlap != nil {
		t.Errorf("strings view: %+v", d)
	}
}

// A page asks the length of these, so they are JSON arrays even when empty.
func TestEmptyListsAreNotNullInJSON(t *testing.T) {
	d := Analyse([]byte("same\n"), []byte("same\n"), 5, 5, Options{})
	b, _ := json.Marshal(d)
	if !bytes.Contains(b, []byte(`"lines":[]`)) || bytes.Contains(b, []byte(`null`)) {
		t.Errorf("%s", b)
	}
	m, _ := json.Marshal(CompareMeta(nil, nil))
	if bytes.Contains(m, []byte(`null`)) {
		t.Errorf("%s", m)
	}
}
