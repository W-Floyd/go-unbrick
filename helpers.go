package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/bootelf"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// addFullDownload gives a command that reads http(s) inputs --full-download.
func addFullDownload(c *cobra.Command) *cobra.Command {
	c.Flags().BoolVar(&infile.FullDownload, "full-download", false, "fetch in full what an http(s) input needs more of than ranges give: a member too big for memory (a compressed super image) is unpacked to a temporary file. Only that member's bytes are fetched, not the whole archive")
	return c
}

// carveSecrets is the --secrets directory of a command that opens inputs through
// carve; empty leaves the sibling ./secrets or ../secrets lookup to carveRoot.
var carveSecrets string

// addSecrets gives a command that reads encrypted members --secrets.
func addSecrets(c *cobra.Command) *cobra.Command {
	c.Flags().StringVar(&carveSecrets, "secrets", "", "directory of hex key (*key*) and IV (*iv*) files tried on encrypted members, and *password*/*passwd*/*wordlist* files (one candidate per line) tried on encrypted zip members; default: ./secrets or ../secrets beside the input")
	return addBruteforce(c)
}

// bruteforceZip and its tuning flags are --bruteforce-zip-passwords' own,
// read by carveRoot into the matching internal/carve.Bruteforce* vars.
var (
	bruteforceZip             bool
	bruteforceMaxLen          int
	bruteforceCharset         string
	bruteforceMaxDeflateLen   int
	bruteforceMaxDeflateBytes int64
	bruteforceMaxNumericLen   int
)

// addBruteforce gives a command --bruteforce-zip-passwords: when no password
// (a vendor's or a --secrets wordlist's) opens an encrypted zip member, try
// every short one instead of giving up, starting with guesses built from the
// member's and its siblings' own file names (cheap regardless of size),
// before the full keyspace. A hit is verified by structure (a decrypted .zip
// member starting like a zip, or a deflated member that fully inflates and
// matches its own recorded CRC32), not the cipher's own 1-in-256 header
// check alone -- a search this size would otherwise false-positive
// constantly. Any password found is kept (internal/zippasswords' cache) so
// it costs nothing on a later run.
func addBruteforce(c *cobra.Command) *cobra.Command {
	c.Flags().BoolVar(&bruteforceZip, "bruteforce-zip-passwords", false, "when no loaded password opens an encrypted zip member, brute-force one: filename-derived guesses first, then every password up to --bruteforce-zip-max-len built from --bruteforce-zip-charset, verified by structure rather than the cipher's own 1-in-256 header check; a password found is cached for reuse")
	c.Flags().IntVar(&bruteforceMaxLen, "bruteforce-zip-max-len", 6, "longest brute-forced password length to try against a member whose verify is cheap regardless of size (a stored member named .zip, checked by its signature); each extra length is ~60x slower")
	c.Flags().StringVar(&bruteforceCharset, "bruteforce-zip-charset", "", "characters to build brute-forced passwords from (default: upper+lower+digit)")
	c.Flags().IntVar(&bruteforceMaxDeflateLen, "bruteforce-zip-max-deflate-len", 4, "longest length tried against a *deflated* member instead of --bruteforce-zip-max-len: its only verify is a full decompress-and-CRC check, paid on every 1-in-256 header-check survivor (measured: ~72µs per survivor per 128 KiB of compressed data), so the same length costs far more than against a cheap-to-verify member")
	c.Flags().IntVar(&bruteforceMaxNumericLen, "bruteforce-zip-max-numeric-len", 10, "longest length tried for a digits-only password first, before --bruteforce-zip-charset's: 10 candidates per position instead of up to 62 reaches much further for the same cost, and a vendor's fixed password has been seen to be a plain run of digits (\"0123456789\"); still capped by --bruteforce-zip-max-deflate-len/-size against a deflated member")
	c.Flags().Int64Var(&bruteforceMaxDeflateBytes, "bruteforce-zip-max-deflate-size", 2<<20, "skip the brute force entirely (after the cheap filename guesses) for a deflated member whose compressed size, in bytes, is over this -- even --bruteforce-zip-max-deflate-len's reduced length isn't worth it past a couple MiB")
	return c
}

// readImage reads path, joining a PIL split image (.mdt with sibling .bNN
// files) into one ELF. missing lists segments whose .bNN was absent.
func readImage(path string) (data []byte, missing []int, err error) {
	data, err = infile.ReadFile(path) // a path on disk, or a member read in place (infile.RegisterVirtual)
	if err != nil || infile.IsVirtual(path) || !strings.EqualFold(filepath.Ext(path), ".mdt") || !bootelf.IsELF(data) {
		return data, nil, err
	}
	stem := strings.TrimSuffix(path, filepath.Ext(path))
	return bootelf.JoinSplit(data, func(i int) []byte {
		b, _ := os.ReadFile(fmt.Sprintf("%s.b%02d", stem, i))
		return b
	})
}

// splitNote describes a joined split image's gaps, or "" when complete.
func splitNote(missing []int) string {
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf("%d segment(s) missing, zero-filled: %v", len(missing), missing)
}

func write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s != "" {
			return s
		}
	}
	return ""
}

func mark(ok bool) string {
	if ok {
		return "yes"
	}
	return "no "
}

func yesno(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
