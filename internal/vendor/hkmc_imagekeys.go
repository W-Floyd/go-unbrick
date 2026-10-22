package vendor

import (
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// ImageIV and ImageKey are etc/iv.dat and etc/image.dat inside the decrypted system
// image: the secrets an on-device updater would use for the next package's enc_ members,
// recorded so a package that opens can seed a secrets directory for later ones.
var (
	ImageIV  = facts.Key[string]("image_iv")
	ImageKey = facts.Key[string]("image_key")
)

// imageDatRoots are where /etc sits under an enc_system.ext4 member: the decrypted
// filesystem itself, or the system.ext4 it wraps.
var imageDatRoots = []string{"/etc", "/system.ext4/etc"}

// learnImageDat reads etc/iv.dat and etc/image.dat from the decrypted system image.
func learnImageDat(pkg PackageAccess, bag *facts.Bag) {
	if !pkg.Decrypts() {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(pkg.Names)) {
		if name != "enc_system.ext4" && !strings.HasSuffix(name, "/enc_system.ext4") {
			continue
		}
		for _, root := range imageDatRoots {
			found := false
			for file, key := range map[string]facts.Fact[string]{"iv.dat": ImageIV, "image.dat": ImageKey} {
				p := name + root + "/" + file
				b := pkg.Read(p)
				if len(b) == 0 {
					continue
				}
				found = true
				facts.Set(bag, key, describeDat(b), facts.Provenance{Source: p, Authority: facts.Attested})
			}
			if found {
				return
			}
		}
	}
}

// describeDat shows a key file's content: its text if it is one line of text, else hex.
func describeDat(b []byte) string {
	if t := strings.TrimSpace(string(b)); len(t) > 0 && len(b) <= 256 && !strings.ContainsFunc(t, func(r rune) bool { return r < ' ' || r > '~' }) {
		return fmt.Sprintf("%s (%d bytes, text)", t, len(b))
	}
	h := hex.EncodeToString(b[:min(len(b), 64)])
	if len(b) > 64 {
		h += "…"
	}
	return fmt.Sprintf("%s (%d bytes)", h, len(b))
}

// DatBytes is the key or IV a describeDat value holds: its hex, whether shown as hex or
// as the text of a hex file. Nil if it is neither.
func DatBytes(s string) []byte {
	s, _, _ = strings.Cut(s, " (")
	b, err := hex.DecodeString(strings.TrimSuffix(s, "…"))
	if err != nil {
		return nil
	}
	return b
}
