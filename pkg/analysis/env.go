package analysis

import (
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
	"github.com/W-Floyd/go-unbrick/internal/zippasswords"
)

// What a program that embeds the engine gets by default is the plain way of opening inputs.
// The unbrick command also opens them through the vendors' container formats and with the keys
// the user keeps; these do the same for an embedding program. Call them before the first input
// is opened.

var (
	vendorsOnce sync.Once
	secretsOnce sync.Once
)

// UseVendors has inputs open through the vendors' container formats, and with the passwords a
// vendor derives for its zips (a head-unit package's encrypted OTA inside its notice zip, whose
// key is the package's date): without it those members are listed as opaque files.
func UseVendors() {
	vendorsOnce.Do(func() {
		carve.Register(vendor.CarveExpanders()...)
		carve.ZipPasswords = zippasswords.WithVendor(vendor.ZipPasswords)
		// A zip given directly as the input, not nested inside another
		// container, is read through srcfile instead -- no vendor derivation
		// there (no container to read a sibling inventory file from), just
		// the user-supplied list.
		srcfile.ZipPasswords = func(string) []string { return zippasswords.Passwords() }
	})
}

// LoadSecrets loads everything a secrets directory can hold: AES keys and IVs
// (hex files, a *key* and *iv* in the name saying which), so images encrypted
// with them (an enc_*.ext4 or enc_boot.img in a package) open; and zip
// passwords (*password*/*passwd*/*wordlist* files, one candidate per line),
// tried against an encrypted zip member after whatever a vendor derives for
// its own formats. Both as the command's --secrets. It returns how many AES
// key/IV candidates were loaded (zippasswords.Count has the password side),
// and replaces any of either loaded before. Call UseVendors first, so the
// vendors' formats are tried ahead of this.
//
// The plaintext of what they open is as readable as any other file: a program that serves
// the engine's pages to others serves it to them too.
func LoadSecrets(dir string) (int, error) {
	if err := aeskeys.Load(dir); err != nil {
		return 0, err
	}
	if err := zippasswords.Load(dir); err != nil {
		return 0, err
	}
	secretsOnce.Do(func() { carve.Register(aeskeys.Expander()) })
	return aeskeys.Count(), nil
}
