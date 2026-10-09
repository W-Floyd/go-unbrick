package vendor

import (
	"fmt"
	"io/fs"

	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// maxStandalone bounds the single-file content checks in CanIngest. What they
// look for — a loader, a signed ELF, a scatter or PIT file — is small; a
// multi-GB package that is not a zip (a fastboot .tgz) is left to its own
// archive checks rather than read into memory.
const maxStandalone = 64 << 20

func readStandalone(path string, fi fs.FileInfo) ([]byte, error) {
	if fi.Size() > maxStandalone {
		return nil, fmt.Errorf("%s: too large to be a standalone image", infile.Base(path))
	}
	return infile.ReadFile(path)
}
