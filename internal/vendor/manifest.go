package vendor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
)

// FileClaim is what a vendor manifest says one file's content hashes to.
// Path is relative to the package root, slash-separated. Algo names the digest
// *including* any vendor quirk, so two claims compare only when their Algo is
// equal; Sum is its lowercase hex. Size is -1 when the manifest does not give
// one.
type FileClaim struct {
	Path string
	Size int64
	Algo string
	Sum  string
}

// ManifestReader is an optional Driver capability: reading this OEM's
// manifests (a listing of files with hashes) out of a package's top-level
// members, so a comparison can take the vendor's word for a file's identity
// instead of reading the file. A package that is not the vendor's yields
// nothing. The claims are unverified; whoever trusts them decides when to.
type ManifestReader interface {
	Manifests(pkg PackageAccess) []FileClaim
}

// Manifests gathers every registered driver's claims about pkg's files.
func Manifests(pkg PackageAccess) []FileClaim {
	var out []FileClaim
	for _, d := range Drivers() {
		if m, ok := d.(ManifestReader); ok {
			out = append(out, m.Manifests(pkg)...)
		}
	}
	return out
}

// Hasher is an optional Driver capability: computing the digests its
// manifests state, which can be vendor-specific (see HyundaiSHA224), so a file
// without a manifest can be compared with one that has.
type Hasher interface {
	// Hasher returns the function for algo, or nil if this vendor does not
	// define it.
	Hasher(algo string) func(io.Reader) (string, error)
}

// HasherFor returns the function computing algo's digest of a stream: a
// neutral algorithm, or one a driver defines. nil when nobody knows it.
func HasherFor(algo string) func(io.Reader) (string, error) {
	switch algo {
	case "sha256":
		return func(r io.Reader) (string, error) {
			h := sha256.New()
			if _, err := io.Copy(h, r); err != nil {
				return "", err
			}
			return hex.EncodeToString(h.Sum(nil)), nil
		}
	case "crc32":
		return func(r io.Reader) (string, error) {
			h := crc32.NewIEEE()
			if _, err := io.Copy(h, r); err != nil {
				return "", err
			}
			return fmt.Sprintf("%08x", h.Sum32()), nil
		}
	}
	for _, d := range Drivers() {
		if h, ok := d.(Hasher); ok {
			if f := h.Hasher(algo); f != nil {
				return f
			}
		}
	}
	return nil
}
