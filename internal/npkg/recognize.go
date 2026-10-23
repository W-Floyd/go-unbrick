package npkg

import "github.com/W-Floyd/go-unbrick/internal/infile"

// Recognizer adapts this package to pkg/analysis/recognize.Recognizer, the
// same shape as internal/androidkeys/recognize.go. Report re-reads the whole
// file (head alone can't prove the sections tile to EOF, Parse's one
// structural check) rather than trusting a head-only Parse the way
// internal/vendor/hkmc_artifact.go's own ArtifactReport already does.
type Recognizer struct{}

func (Recognizer) Name() string { return "npkg" }

func (Recognizer) Version() int { return 1 }

func (Recognizer) Claims(name string, head []byte) bool { return Is(head) }

func (Recognizer) Label(name string, head []byte) string { return "navi package (PRNM)" }

// Summary is "": hkmc_artifact.go's own npkg.Is case sets no Detail today
// (Report below prints the validated Summary and section table, so a teaser
// here would just repeat its first line).
func (Recognizer) Summary(name string, head, data []byte) string { return "" }

func (Recognizer) Report(path, name string, head, data []byte) []string {
	if !Is(head) {
		return nil
	}
	b, err := infile.ReadFile(path)
	if err != nil {
		return nil
	}
	p, err := Parse(b, int64(len(b)))
	if err != nil {
		return nil
	}
	return p.Report()
}
