package imgdiff

// Analyzers recognize the contents of a segment and compare two of them in
// their own terms, so this package -- and everything above it -- compares
// firmware without knowing which formats exist.
//
// A byte diff cannot say anything useful about a payload that was relaid out,
// recompressed or re-signed. An analyzer that understands the format can: the
// device-config analyzer compares properties, the UEFI one compares modules.
// Teaching the tool a new format means registering one here, not editing the
// diff logic or the command that prints it.

// Chunk is one segment handed to an analyzer: its bytes, and the address the
// image loads them at, which in-payload pointers are relative to.
type Chunk struct {
	Data  []byte
	Paddr uint64
}

// Report is an analyzer's finding, in a shape the caller can print without
// knowing what was analyzed.
type Report struct {
	// Kind names the format, e.g. "device config" or "UEFI".
	Kind string
	// Unit names what was counted, singular, e.g. "value" or "module".
	Unit string
	// Equivalent is true when the analyzer found no difference in its own
	// terms, whatever the bytes did.
	Equivalent bool
	// Compared is how many units (properties, modules) were present in both
	// and compared, so a caller can say how much the verdict covers.
	Compared int
	// Differing is how many of those differed.
	Differing int
	// Detail holds one line per finding, already formatted.
	Detail []string
}

// Summary is a one-line description of the finding.
func (r Report) Summary() string {
	unit := r.Unit
	if unit == "" {
		unit = "item"
	}
	if r.Equivalent {
		return plural(r.Compared, unit) + ", all match"
	}
	verb := " differ"
	if r.Differing == 1 {
		verb = " differs"
	}
	return itoa(r.Differing) + " of " + plural(r.Compared, unit) + verb
}

// Analyzer recognizes one payload format and compares two of them.
type Analyzer interface {
	// Kind names the format this analyzer understands.
	Kind() string
	// Detect reports whether a segment is this analyzer's format. It is what
	// lets a segment be identified in one image independently of the other,
	// so images whose layouts do not correspond can still be compared.
	Detect(c Chunk) bool
	// Compare reports on two segments, or returns false when it cannot read
	// them after all. Declining is better than asserting an empty comparison:
	// the byte-level findings should stand instead.
	Compare(a, b Chunk) (Report, bool)
}

// analyzers is the registry consulted for every differing payload segment.
// Order decides which analyzer claims a segment when more than one could.
var analyzers = []Analyzer{
	devCfgAnalyzer{},
	efiAnalyzer{},
}

// Register adds an analyzer, for formats defined outside this package.
func Register(a Analyzer) { analyzers = append(analyzers, a) }

// analyze runs the registry over one pair of segments, returning every report
// produced. A segment can legitimately yield more than one.
func analyze(a, b Chunk) []Report { return analyzeWith(analyzers, a, b) }

func analyzeWith(as []Analyzer, a, b Chunk) []Report {
	var out []Report
	for _, an := range as {
		if !an.Detect(a) || !an.Detect(b) {
			continue
		}
		if r, ok := an.Compare(a, b); ok {
			out = append(out, r)
		}
	}
	return out
}

// analyzeImages pairs segments up by format rather than by position, for images
// whose segment layouts do not correspond -- different devices, or builds far
// enough apart that segments moved. Each analyzer takes the first segment it
// recognizes on either side.
func analyzeImages(a, b []Chunk) []Report { return analyzeImagesWith(analyzers, a, b) }

func analyzeImagesWith(as []Analyzer, a, b []Chunk) []Report {
	var out []Report
	for _, an := range as {
		x, okA := firstMatch(an, a)
		y, okB := firstMatch(an, b)
		if !okA || !okB {
			continue
		}
		if r, ok := an.Compare(x, y); ok {
			out = append(out, r)
		}
	}
	return out
}

func firstMatch(an Analyzer, cs []Chunk) (Chunk, bool) {
	for _, c := range cs {
		if an.Detect(c) {
			return c, true
		}
	}
	return Chunk{}, false
}

func plural(n int, unit string) string {
	s := itoa(n) + " " + unit
	if n != 1 {
		s += "s"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
