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
	if info, ok := fsgArtifact(data); ok {
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
