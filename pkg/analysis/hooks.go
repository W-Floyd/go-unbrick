package analysis

import (
	"fmt"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
)

// The comparison engine reaches its host through these, so an embedding tool can
// say how inputs are opened (which expanders and secrets apply) and how files are
// named by type. The defaults are the plain ones.
var (
	// OpenRoot opens an input that is not a directory: a file, an image, a package.
	OpenRoot = func(input string) (*carve.Node, error) { return carve.Open(input) }
	// TypeLabel names what a file is, from its name and first bytes, for telling
	// whether two files are alike.
	TypeLabel = func(name string, head []byte) string { return string(filetype.Detect(head)) }
)

// HumanBytes is a size as "1.5 MiB".
func HumanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func humanBytes(n int64) string { return HumanBytes(n) }
