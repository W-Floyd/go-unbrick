package analysis

import (
	"encoding/hex"
	"encoding/json"
)

// Seg is a stretch of a line's text, marked when it is one of the words that
// differ from the line it is paired with.
type Seg struct {
	T    string `json:"t"`
	Mark bool   `json:"mark,omitempty"`
}

// Segments cuts the line's text at the ranges in Hi.
func (l Line) Segments() []Seg {
	if len(l.Hi) == 0 {
		return []Seg{{T: l.Text}}
	}
	var out []Seg
	at := 0
	for _, r := range l.Hi {
		if r[0] > at {
			out = append(out, Seg{T: l.Text[at:r[0]]})
		}
		out = append(out, Seg{T: l.Text[r[0]:r[1]], Mark: true})
		at = r[1]
	}
	if at < len(l.Text) {
		out = append(out, Seg{T: l.Text[at:]})
	}
	return out
}

// MarshalJSON writes a line as {op, a, b, text}, with segs (the text cut at the
// marked words) when words are marked; op is the character: " ", "-", "+" or "@".
func (l Line) MarshalJSON() ([]byte, error) {
	v := struct {
		Op   string `json:"op"`
		A    int    `json:"a"`
		B    int    `json:"b"`
		Text string `json:"text"`
		Segs []Seg  `json:"segs,omitempty"`
	}{Op: string(rune(l.Op)), A: l.A, B: l.B, Text: l.Text}
	if len(l.Hi) > 0 {
		v.Segs = l.Segments()
	}
	return json.Marshal(v)
}

// MarshalJSON writes the bytes as a hex string, which a page reads without
// decoding base64.
func (r HexRow) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Offset int    `json:"offset"`
		Hex    string `json:"hex"`
		From   int    `json:"from"`
		To     int    `json:"to"`
	}{r.Offset, hex.EncodeToString(r.Bytes), r.From, r.To})
}
