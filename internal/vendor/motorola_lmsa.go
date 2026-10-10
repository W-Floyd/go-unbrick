package vendor

import (
	"os"
	"path"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/lenovo"
)

// LMSAPasswordEnv overrides the LMSA ROM decryption password. The recovered
// default (lenovo.DefaultPassword, "OSD") decrypts every package seen so far, so
// this is only needed if Lenovo ever rotates it. See internal/lenovo.
const LMSAPasswordEnv = "LMSA_ROM_PASSWORD"

// CarveExpanders lets `ls`/`extract` see through LMSA's encrypted ROM files: a
// scatter or rawprogram XML renamed foo.t / foo.x, which decrypt to foo.txt /
// foo.xml. Motorola is the Lenovo-family vendor, and LMSA is the Lenovo/Motorola
// tool, so the format lives here rather than among the neutral carve formats.
func (motorola) CarveExpanders() []carve.Expander {
	return []carve.Expander{{
		Kind:   "lmsa-rom",
		Match:  func(n *carve.Node, _ []byte) bool { return lmsaOutName(n.Name) != "" },
		Expand: expandLMSAROM,
	}}
}

// lmsaOutName returns the decrypted name for an LMSA ROM file, or "" if name is
// not one. The extension alone identifies these; the ciphertext has no magic
// (its first bytes are a random IV and salt).
func lmsaOutName(name string) string {
	switch {
	case strings.HasSuffix(strings.ToLower(name), ".t"):
		return name + "xt"
	case strings.HasSuffix(strings.ToLower(name), ".x"):
		return name + "ml"
	default:
		return ""
	}
}

func expandLMSAROM(n *carve.Node) ([]*carve.Node, error) {
	pw := lenovo.DefaultPassword
	if env := os.Getenv(LMSAPasswordEnv); env != "" {
		pw = env
	}
	src, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	out, err := lenovo.DecryptROM(src, pw)
	if err != nil {
		return nil, err
	}
	return []*carve.Node{carve.FromBytes(lmsaOutName(path.Base(n.Name)), out)}, nil
}
