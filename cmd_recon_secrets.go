package main

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
	"github.com/W-Floyd/go-unbrick/internal/zippasswords"
)

// A secrets directory holds hex files: *key* (AES key) and *iv* (16-byte IV), found by the
// underscore/dash/dot-separated words in the file name. A member that is neither a known format
// nor readable text is tried against every key and IV pair, as continuous AES-CBC over its head,
// and labelled only if the plaintext is a format typeLabel recognises.
//
// The same directory also holds *password*/*passwd*/*wordlist* files (internal/zippasswords):
// plain-text lists, one candidate per line, tried against an encrypted zip member after whatever
// a vendor derives for its own formats.
//
// The keys, and what they open, are in internal/aeskeys (an embedding program loads them through
// pkg/analysis); this is what recon does with them.

var inDecrypt bool

// loadSecrets loads everything a secrets directory can hold: AES keys/IVs
// (internal/aeskeys) and zip passwords (internal/zippasswords), both found by
// file name convention, so one --secrets directory covers both without the
// caller needing to know which it has.
func loadSecrets(dir string) error {
	if err := aeskeys.Load(dir); err != nil {
		return err
	}
	return zippasswords.Load(dir)
}
func findSecrets(dir string) string     { return aeskeys.Find(dir) }
func encryptedExpander() carve.Expander { return aeskeys.Expander() }
func secretsLoaded() int                { return aeskeys.Count() }
func proven(plain []byte) bool          { return aeskeys.Proven(plain) }
func nameAffinity(a, b string) int      { return aeskeys.NameAffinity(a, b) }
func decryptedReaderAt(ra io.ReaderAt, size int64, head []byte) (*aeskeys.Reader, string, bool) {
	return aeskeys.DecryptedReaderAt(ra, size, head)
}

// decryptLabel decrypts head under each loaded secret and returns the label
// of the first plaintext typeLabel can name.
func decryptLabel(head []byte) (string, bool) {
	if secretsLoaded() == 0 || inDecrypt || len(head) < 2*aes.BlockSize {
		return "", false
	}
	inDecrypt = true
	defer func() { inDecrypt = false }()
	for _, s := range aeskeys.Secrets() {
		blk, err := aes.NewCipher(s.Key)
		if err != nil {
			continue
		}
		plain := s.DecryptHead(blk, head)
		if plain == nil {
			continue
		}
		l := typeLabel("", plain)
		switch {
		case bytes.HasPrefix(plain, []byte("ANDROID@")):
			l = "LK bootloader"
		case bytes.HasPrefix(plain, []byte("splash\x00")):
			l = "splash image"
		case l == "unknown" && !highEntropy(plain):
			// A wrong key leaves uniform noise; structure after decrypting is the
			// key's proof even where the format has no signature here.
			l = "data"
		}
		if l != "unknown" && l != "encrypted or compressed" && l != "text" {
			return "encrypted " + l, true
		}
	}
	return "", false
}

// printEncryptedFS walks a filesystem inside an encrypted member through a
// range-decrypting reader: the build's identity from its build.prop, then the
// top-level directory counts. False when no secret opens it or it is not
// seekable.
// openEncryptedFS opens an encrypted tar member as a filesystem, trying every
// loaded secret (see decryptedReaderAt) and letting carve pick ext4 vs erofs
// from the decrypted content. Shared by the display path (printEncryptedFS)
// and the fact-extraction path (encryptedSystemProps), so a key loaded once
// serves both.
func openEncryptedFS(path string, m srcfile.Member) (fs.FS, string, bool) {
	if secretsLoaded() == 0 {
		return nil, "", false
	}
	n, err := carvePath(path, m.Name)
	if err != nil || !n.RandomAccess() {
		return nil, "", false
	}
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, "", false
	}
	dec, key, ok := decryptedReaderAt(ra, int64(m.Size), m.Head)
	if !ok {
		return nil, "", false
	}
	fsys, err := carve.FromReaderAt("", dec, dec.Size()).FS()
	if err != nil {
		return nil, "", false
	}
	return fsys, key, true
}

func printEncryptedFS(path string, m srcfile.Member, indent string, clear func()) bool {
	fsys, key, ok := openEncryptedFS(path, m)
	if !ok {
		return false
	}
	clear()
	// Its identity already printed up top (learnSystemProps feeds the same
	// build.prop into the bag before the member loop reaches here) — this is
	// just the layout.
	fmt.Printf("%s%-26s [encrypted filesystem, opened with %s]  %s\n", indent, filepath.Base(m.Name), key, humanBytes(int64(m.Size)))
	count := map[string]int{}
	var dirs []string
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		top, _, found := strings.Cut(p, "/")
		if !found {
			top = "."
		}
		if count[top] == 0 {
			dirs = append(dirs, top)
		}
		count[top]++
		return nil
	})
	sort.Strings(dirs)
	for _, d := range dirs {
		fmt.Printf("%s  %-24s %d files\n", indent, d+"/", count[d])
	}
	return true
}

// knownSecret names the loaded secret whose key or IV is b.
func knownSecret(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	for _, s := range aeskeys.Secrets() {
		if bytes.Equal(s.Key, b) || bytes.Equal(s.IV, b) {
			return strings.TrimSuffix(s.Name, " (zero IV)"), true
		}
	}
	return "", false
}

// datStatus marks a value from the package as known (and as which secret) or as new.
func datStatus(v string) string {
	if name, ok := knownSecret(vendor.DatBytes(v)); ok {
		return v + " — known: " + name
	}
	return render(styleGood.Bold(true), v+" — NEW")
}

// hexValue is the bytes of a file that is one hex string of a key or IV length
// (iv.dat, image.dat), with ok false for anything else.
func hexValue(head []byte) ([]byte, bool) {
	t := strings.TrimSpace(string(head))
	if len(t) != 32 && len(t) != 48 && len(t) != 64 {
		return nil, false
	}
	b, err := hex.DecodeString(t)
	return b, err == nil
}

// hexValueLabel names such a file by what its length makes it.
func hexValueLabel(b []byte) string {
	return fmt.Sprintf("hex key or IV (%d bytes)", len(b))
}
