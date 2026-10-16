package vendor

import (
	"os"
	"path"

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
		Match:  func(n *carve.Node, head []byte) bool { return lenovo.IsROM(n.Name, head) },
		Expand: expandLMSAROM,
	}}
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
	return []*carve.Node{carve.FromBytes(lenovo.OutName(path.Base(n.Name)), out)}, nil
}
