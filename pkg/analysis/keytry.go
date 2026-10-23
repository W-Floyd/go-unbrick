package analysis

import (
	"context"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
)

// Candidate is a key, and the IV it is used with, to try on encrypted members without loading it: what someone
// has sent in and a reviewer wants to check before it is used. Mode is "" for CBC under IV, "ecb", or "prefix"
// (CBC, the first block of the member is the IV).
type Candidate struct {
	Key, IV []byte
	Mode    string
}

// TryCandidates looks through input as ScanKeys does, and tries each candidate on the head of every enc_ member it
// finds, whether or not a loaded secret opens it. It returns how many encrypted members there are and the paths
// of those some candidate opens: the proof that a key is for this input. A key is proven whatever the IV, since in
// CBC a wrong IV spoils only the first block; an IV alone cannot be checked this way. It does not go into the encrypted
// images. It stops, with what it has, when ctx ends; progress, if set, is told after each container is opened.
func TryCandidates(ctx context.Context, input string, depth int, skip []string, cands []Candidate, progress func(opened int, at string)) (encrypted int, opened []string, err error) {
	secrets := make([]aeskeys.Secret, len(cands))
	for i, c := range cands {
		secrets[i] = aeskeys.Secret{Key: c.Key, IV: c.IV, Mode: c.Mode}
	}
	top, err := OpenInput(input, nil)
	if err != nil {
		return 0, nil, err
	}
	n := 0
	var walk func(l *BrowseLevel, depth int)
	walk = func(l *BrowseLevel, depth int) {
		for _, e := range l.Entries {
			if ctx.Err() != nil {
				return
			}
			if SkipPath(skip, e.Path) {
				continue
			}
			dir := e.Dir || e.Group != nil
			if !dir && strings.HasPrefix(e.Name, "enc_") {
				encrypted++
				if head, _, err := ReadEntry(e, 8192); err == nil {
					for _, s := range secrets {
						if s.Opens(head) {
							opened = append(opened, e.Path)
							break
						}
					}
				}
				continue
			}
			if !dir {
				if e.Text || e.Image || (e.OSPath == "" && !e.Container) || depth <= 0 || IsKeyFile(e.Path) {
					continue
				}
			}
			next := depth
			if !dir {
				next--
			}
			sub, err := openRaw(e, nil)
			if err != nil {
				continue
			}
			sub.setPaths(e.Path + "/")
			if !dir {
				n++
				if progress != nil {
					progress(n, e.Path)
				}
			}
			walk(sub, next)
		}
	}
	walk(top, depth)
	return encrypted, opened, ctx.Err()
}
