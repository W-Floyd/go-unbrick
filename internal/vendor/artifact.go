package vendor

// Content recognition for vendor file formats that have no neutral magic the
// generic filetype detector handles. Kept behind the vendor seam so the recon
// command never hardcodes vendor magics; it just asks RecognizeArtifact.

import (
	"fmt"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
)

// ArtifactInfo is a vendor-recognized file: a short type label and optional detail.
type ArtifactInfo struct {
	Label  string
	Detail string
}

// RecognizeArtifact identifies a vendor-specific file from its name and bytes.
// cat may be nil; name may be "" where no filename is in scope (only the
// name-blind checks then apply). Returns ok=false if no vendor format matches.
func RecognizeArtifact(cat *catalog.Catalog, name string, data []byte) (ArtifactInfo, bool) {
	if info, ok := motorolaArtifact(cat, name, data); ok {
		return info, true
	}
	if info, ok := hkmcArtifact(name, data); ok {
		return info, true
	}
	if info, ok := tccArtifact(data); ok {
		return info, true
	}
	if info, ok := fsgArtifact(data); ok {
		return info, true
	}
	if info, ok := qcomArtifact(data); ok {
		return info, true
	}
	if info, ok := mediatekArtifact(data); ok {
		return info, true
	}
	if p, err := ParsePIT(data); err == nil {
		return ArtifactInfo{Label: "Samsung PIT", Detail: fmt.Sprintf("%d partitions", len(p.Entries))}, true
	}
	return ArtifactInfo{}, false
}

// ArtifactReporter is an optional Driver capability: a longer report on a file
// RecognizeArtifact identified, as lines of text (what the file says about
// itself), for recon to print under the one-line recognition. head is the start of
// the file; a reporter reads the rest through path if it needs it. nil when it has
// nothing to add for this file.
type ArtifactReporter interface {
	ArtifactReport(path string, head []byte) []string
}

// ArtifactReport asks every registered driver for a report on the file at path.
func ArtifactReport(path string, head []byte) []string {
	for _, d := range Drivers() {
		if r, ok := d.(ArtifactReporter); ok {
			if lines := r.ArtifactReport(path, head); len(lines) > 0 {
				return lines
			}
		}
	}
	return nil
}
