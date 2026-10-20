package analysis

import "bytes"

// View selects what Analyse reports about two byte strings.
type View string

const (
	ViewAuto    View = "auto"    // a line diff for text; for a binary, overlap, bytes and a peek at strings
	ViewStrings View = "strings" // a diff of the printable strings in each side
	ViewOverlap View = "overlap" // shared and unique bytes
	ViewHex     View = "hex"     // the bytes that differ outside strings
)

// NoContext is Options.Context for a diff with no unchanged lines around changes.
const NoContext = -1

// Options tunes Analyse. The zero value is the usual: every field has a default.
type Options struct {
	View       View
	Context    int  // unchanged lines around a change (default 3; NoContext for none)
	StringsMin int  // shortest printable run that counts as a string (default 6)
	Words      bool // mark the words that differ within changed lines
	HexBudget  int  // differing bytes the hex view lists (default 4 KiB)
	HexAuto    int  // differing bytes up to which a binary's auto view lists them (default 256)
	StringPeek int  // lines of the strings diff the auto view shows (default 60)
}

func (o Options) withDefaults() Options {
	if o.View == "" {
		o.View = ViewAuto
	}
	switch {
	case o.Context == 0:
		o.Context = 3
	case o.Context < 0:
		o.Context = 0
	}
	if o.StringsMin == 0 {
		o.StringsMin = 6
	}
	if o.HexBudget == 0 {
		o.HexBudget = 4 << 10
	}
	if o.HexAuto == 0 {
		o.HexAuto = 256
	}
	if o.StringPeek == 0 {
		o.StringPeek = 60
	}
	return o
}

// Side is how much of one input was analysed.
type Side struct {
	Size      int64 `json:"size"`      // its whole size
	Read      int   `json:"read"`      // the bytes analysed
	Truncated bool  `json:"truncated"` // only the start of it was read
}

// LineDiff is a unified diff: of the lines of text, or of the strings of a binary.
type LineDiff struct {
	Lines     []Line `json:"lines"`
	Stats     Stats  `json:"stats"`
	Truncated bool   `json:"truncated"` // cut off at a limit
}

// HexRow is the bytes of one side around one hunk: a 16-aligned window that holds
// it, of which [From, To) is the hunk itself.
type HexRow struct {
	Offset int    `json:"offset"` // where the window starts in the input
	Bytes  []byte `json:"bytes"`
	From   int    `json:"from"` // the hunk, as offsets into Bytes
	To     int    `json:"to"`
}

// HexHunkView is one place two binaries differ, with the bytes around it.
type HexHunkView struct {
	OffA int    `json:"offA"`
	OffB int    `json:"offB"`
	LenA int    `json:"lenA"`
	LenB int    `json:"lenB"`
	A    HexRow `json:"a"`
	B    HexRow `json:"b"`
}

// HexReport is where two binaries differ outside their printable strings.
type HexReport struct {
	Hunks       []HexHunkView `json:"hunks"` // as many as the budget allows
	Places      int           `json:"places"`
	Total       int           `json:"total"`       // differing bytes in all
	Unavailable bool          `json:"unavailable"` // too large, and of different sizes, to find them
	More        int           `json:"more"`        // places left out of Hunks for the budget
}

// Detail is what differs between two byte strings, as data: a UI draws it.
type Detail struct {
	A         Side       `json:"a"`
	B         Side       `json:"b"`
	Identical bool       `json:"identical"` // the bytes analysed are equal
	Text      bool       `json:"text"`      // both are text: Diff is set
	Verdict   *Verdict   `json:"verdict,omitempty"`
	Diff      *LineDiff  `json:"diff,omitempty"`    // text: a line diff
	Strings   *LineDiff  `json:"strings,omitempty"` // a diff of the strings: all of it in the strings view, a peek in auto
	Overlap   *Overlap   `json:"overlap,omitempty"`
	Hex       *HexReport `json:"hex,omitempty"`
	// StringsPeek is set when Strings is a cut-down peek, so a UI can point to the
	// strings view for the rest.
	StringsPeek bool `json:"stringsPeek,omitempty"`
}

// Verdict says whether two binaries differ only in their printable strings.
type Verdict = StringsVerdict

// Analyse compares a and b (the whole of each, or the start: sizeA and sizeB are
// their real sizes) in the way opts.View asks. It is pure, and safe for any
// number of callers at once.
func Analyse(a, b []byte, sizeA, sizeB int64, opts Options) *Detail {
	o := opts.withDefaults()
	d := &Detail{
		A:         Side{sizeA, len(a), int64(len(a)) < sizeA},
		B:         Side{sizeB, len(b), int64(len(b)) < sizeB},
		Identical: bytes.Equal(a, b),
		Text:      IsText(a) && IsText(b),
	}
	if !d.Text {
		v := StringsOnly(a, b, o.StringsMin)
		d.Verdict = &v
	}
	switch o.View {
	case ViewOverlap:
		ov := Compare(a, b)
		d.Overlap = &ov
	case ViewHex:
		d.Hex = hexReport(a, b, o.StringsMin, o.HexBudget, true)
	case ViewStrings:
		d.Strings = stringsDiff(a, b, o.StringsMin, o.Context, 0)
	default:
		if d.Text {
			d.Diff = textDiff(a, b, o.Context, o.Words)
			break
		}
		ov := Compare(a, b)
		d.Overlap = &ov
		if h := hexReport(a, b, o.StringsMin, o.HexAuto, false); h != nil {
			d.Hex = h
		}
		d.Strings = stringsDiff(a, b, o.StringsMin, 1, o.StringPeek)
		d.StringsPeek = true
	}
	return d
}

func textDiff(a, b []byte, context int, words bool) *LineDiff {
	lines, st, trunc := TextDiff(a, b, context)
	if lines == nil {
		lines = []Line{} // a JSON array, not null
	}
	if words {
		lines = MarkWords(lines)
	}
	return &LineDiff{lines, st, trunc}
}

// stringsDiff is the diff of the strings; peek, when positive, cuts it to that
// many lines.
func stringsDiff(a, b []byte, min, context, peek int) *LineDiff {
	lines, st, trunc := StringDiff(a, b, min, context)
	if lines == nil {
		lines = []Line{}
	}
	if peek > 0 && len(lines) > peek {
		lines, trunc = lines[:peek], true
	}
	return &LineDiff{lines, st, trunc}
}

// hexReport lists where a and b differ outside strings. explicit is a request for
// the hex view; otherwise it is the unasked section of the auto view, which is nil
// unless every differing byte fits the budget.
func hexReport(a, b []byte, min, budget int, explicit bool) *HexReport {
	hunks, total, ok := HexDiffOutsideStrings(a, b, min)
	switch {
	case !ok:
		if explicit {
			return &HexReport{Unavailable: true}
		}
		return nil
	case total == 0 && !explicit:
		return nil
	case !explicit && total > budget:
		return nil
	}
	r := &HexReport{Places: len(hunks), Total: total, Hunks: []HexHunkView{}}
	shown := 0
	for i, h := range hunks {
		if shown >= budget {
			r.More = len(hunks) - i
			break
		}
		shown += h.Len()
		r.Hunks = append(r.Hunks, HexHunkView{
			OffA: h.OffA, OffB: h.OffB, LenA: len(h.A), LenB: len(h.B),
			A: hexWindow(a, h.OffA, len(h.A)), B: hexWindow(b, h.OffB, len(h.B)),
		})
	}
	return r
}

// hexWindow is the 16-byte rows of data that hold [off, off+n).
func hexWindow(data []byte, off, n int) HexRow {
	if n == 0 {
		return HexRow{Offset: off}
	}
	from := off / 16 * 16
	to := min((off+n+15)/16*16, len(data))
	return HexRow{Offset: from, Bytes: data[from:to], From: off - from, To: off + n - from}
}
