package carve

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/zipcrypto"
)

// ZipPasswords, when set, is how a vendor opens the encrypted members of its
// zips: it names the passwords worth trying for one member (zip is the container
// the member is in, member its name there), most likely first. A package often
// derives its password from itself (a date in its name or its inventory file), so
// the container's own place in the tree, Node.Parent, is what the vendor reads.
// Members it names no password for, or none that works, are listed as stored:
// their bytes are the ciphertext.
var ZipPasswords func(zip *Node, member string) []string

// BruteforceCharset, when non-empty, is the fallback for a member none of
// ZipPasswords' candidates open: every password of length 1..BruteforceMaxLen
// built from it is tried, verified by structure (a decrypted .zip-named
// stored member starting like a zip, or a deflated member that fully
// inflates) rather than the cipher's own 1-in-256 header check alone, so a
// hit is trustworthy even across a search space that check byte would
// otherwise false-positive on constantly. Empty (the default) disables brute
// force entirely -- it is opt-in because, unlike a vendor's or a wordlist's
// password, nothing here says the real password *is* short and alphanumeric;
// that is the search space's assumption, paid for in time if wrong.
var BruteforceCharset string

// BruteforceMaxLen bounds how long a brute-forced password is tried up to.
// 0 (with BruteforceCharset empty) disables brute force.
var BruteforceMaxLen int

// BruteforceMaxDeflateSize caps the *compressed* size of a deflated member
// the exhaustive keyspace search (as opposed to the cheap filename-derived
// guesses, tried regardless of size) is attempted against at all; above it,
// the search is skipped outright (BruteforceSkipped says so) rather than run
// at BruteforceMaxDeflateLen and still take too long. 0 means unlimited.
//
// A deflated member's only verify is a full decompress-and-CRC check -- a
// wrong key's stream has been measured to decode to completion, with the
// wrong CRC, far more often than it errors out early, so this cost is paid
// on every 1-in-256 header-check survivor, not just the rare true match.
// Measured on real data: a ~130 KiB compressed member cost ~72µs per
// survivor, so even BruteforceMaxDeflateLen's reduced length (4: ~57,700
// survivors) stays under a minute only for members up to a couple MiB; the
// default search's length 6 (tens of millions of survivors) would cost
// *hours* against the same tiny member -- which is why deflate's own length
// is capped separately from stored/zip-signature members, whose verify
// reads 4 bytes regardless of size and so pays none of this.
var BruteforceMaxDeflateSize int64

// BruteforceMaxDeflateLen bounds a deflated member's exhaustive search
// length separately from BruteforceMaxLen (effectively min of the two):
// stored/zip-signature members pay nothing per candidate and can afford
// BruteforceMaxLen's default of 6, but a deflated member's full-decompress
// verify cannot -- see BruteforceMaxDeflateSize for the measurement this
// is sized from. 0 falls back to BruteforceMaxLen.
var BruteforceMaxDeflateLen int

// BruteforceMaxNumericLen bounds a digits-only exhaustive search, tried
// before BruteforceCharset's: 10 candidates per position instead of up to
// 62, so the same length reaches ~6x further for the same cost -- a vendor's
// fixed password has been seen to be a plain run of digits ("0123456789",
// 10 characters, nowhere near reachable at BruteforceMaxLen's usual 6).
// Still subject to BruteforceMaxDeflateLen/Size against a deflated member,
// the same as the general search. 0 disables this pass specifically
// (BruteforceCharset's own search, if any, still runs).
var BruteforceMaxNumericLen int

const numericCharset = "0123456789"

// PasswordFound, when set, is told about a password brute force recovers
// (zip is the container it was found in, member its name there), so a caller
// can keep it for free next time instead of paying for the search again.
var PasswordFound func(zip *Node, member, password string)

// BruteforceSkipped, when set, is told when the exhaustive keyspace search
// is not even attempted for a member brute force was otherwise willing to
// try (BruteforceMaxDeflateSize, reason "too large to decompress per
// candidate"). The filename-derived guesses still ran regardless; this is
// only about the expensive fallback.
var BruteforceSkipped func(zip *Node, member, reason string)

// BruteforceProgress, when set, is told once per password length as the
// exhaustive search reaches it -- the only visibility into a search that can
// otherwise run for minutes between one print and the next.
var BruteforceProgress func(zip *Node, member string, length int)

// zipEncrypted says a member is encrypted with the traditional PKWARE cipher (AES,
// method 99, is not handled).
func zipEncrypted(f *zip.File) bool { return f.Flags&0x1 != 0 && f.Method != 99 }

// decryptedZipMember is the plaintext of an encrypted member, as a node that reads
// at random, if one of the vendor's passwords opens it; nil otherwise. A password
// must pass the member's header check (one in 256 wrong ones do) and, for a member
// named .zip, decrypt to something that starts like one. siblings is every member
// name in the same zip (the zip Expander already has them from its own zip.Reader;
// this is only ever a fast map lookup away from a Node's own Children, which
// decryptedZipMember cannot call -- it runs from inside that very expansion),
// for the filename-derived candidates a brute force starts with.
func decryptedZipMember(zn *Node, f *zip.File, ra io.ReaderAt, siblings []string) *Node {
	if !zipEncrypted(f) || f.Method != zip.Store && f.Method != zip.Deflate {
		return nil
	}
	var pws []string
	if ZipPasswords != nil {
		pws = ZipPasswords(zn, f.Name)
	}
	start, err := f.DataOffset()
	if err != nil {
		return nil
	}
	data := io.NewSectionReader(ra, start, int64(f.CompressedSize64))
	// With a data descriptor the check byte is the high byte of the time, else of
	// the CRC; vendors have been seen to do either, so either is accepted.
	checks := []byte{byte(f.CRC32 >> 24), byte(f.ModifiedTime >> 8)}
	if f.Flags&0x8 != 0 {
		checks[0], checks[1] = checks[1], checks[0]
	}
	plainSize := int64(f.CompressedSize64) - zipcrypto.HeaderLen
	for _, pw := range pws {
		for _, check := range checks {
			r, err := zipcrypto.NewReaderAt(data, plainSize, []byte(pw), check)
			if err != nil || !validZipMember(f, r) {
				continue
			}
			return nodeFromDecrypted(f, r)
		}
	}
	// The cheap filename pre-pass is gated on brute force being on at all
	// (Charset set), not on MaxLen: it is not the exhaustive search MaxLen
	// bounds, and should still run even where that search would do nothing
	// (MaxLen 0, or every length capped below it for a deflate member).
	if BruteforceCharset == "" {
		return nil
	}
	verify := bruteVerify(f)
	if verify == nil {
		return nil
	}
	found := func(pw string) *Node {
		if PasswordFound != nil {
			PasswordFound(zn, f.Name, pw)
		}
		for _, check := range checks {
			if r, err := zipcrypto.NewReaderAt(data, plainSize, []byte(pw), check); err == nil && validZipMember(f, r) {
				return nodeFromDecrypted(f, r)
			}
		}
		return nil
	}
	// A vendor's fixed password has been seen to simply be a truncation of one
	// of its own container's file names (case-folded), or a plain run of
	// digits ("0123456789") -- both cheap enough to try before paying for
	// the full keyspace below, size cap or not.
	cheap := append(filenameCandidates(zn, f, siblings), numericSequenceCandidates(10)...)
	if pw, ok := tryCandidates(data, plainSize, checks, verify, cheap); ok {
		return found(pw)
	}
	maxLen, numericLen, skip := bruteforceLens(f)
	if skip {
		if BruteforceSkipped != nil {
			BruteforceSkipped(zn, f.Name, "too large to decompress per candidate")
		}
		return nil
	}
	progress := func(length int) {
		if BruteforceProgress != nil {
			BruteforceProgress(zn, f.Name, length)
		}
	}
	if numericLen > 0 {
		opts := zipcrypto.BruteforceOptions{Charset: numericCharset, MaxLen: numericLen, Progress: progress}
		if pw, ok := zipcrypto.Bruteforce(data, plainSize, checks, verify, opts); ok {
			return found(pw)
		}
	}
	if maxLen > 0 {
		opts := zipcrypto.BruteforceOptions{Charset: BruteforceCharset, MaxLen: maxLen, Progress: progress}
		if pw, ok := zipcrypto.Bruteforce(data, plainSize, checks, verify, opts); ok {
			return found(pw)
		}
	}
	return nil
}

// bruteforceLens resolves how long the general and the digits-only
// exhaustive searches run against f, both capped the same way by
// BruteforceMaxDeflateLen/Size for a deflated member (skip true means even
// that cap isn't worth it: don't run either search at all).
func bruteforceLens(f *zip.File) (generalLen, numericLen int, skip bool) {
	generalLen, numericLen = BruteforceMaxLen, BruteforceMaxNumericLen
	if f.Method != zip.Deflate {
		return generalLen, numericLen, false
	}
	if BruteforceMaxDeflateSize > 0 && int64(f.CompressedSize64) > BruteforceMaxDeflateSize {
		return 0, 0, true
	}
	if BruteforceMaxDeflateLen > 0 {
		if BruteforceMaxDeflateLen < generalLen {
			generalLen = BruteforceMaxDeflateLen
		}
		if BruteforceMaxDeflateLen < numericLen {
			numericLen = BruteforceMaxDeflateLen
		}
	}
	return generalLen, numericLen, false
}

// tryCandidates attempts each of pws (in order) against data/checks, the same
// header-check-then-verify a brute force candidate must pass: unlike the
// vendor/wordlist loop above, false positives here are expected to be common
// enough (short, likely-wrong guesses) that verify is not optional.
func tryCandidates(data io.ReaderAt, plainSize int64, checks []byte, verify func(*zipcrypto.ReaderAt) bool, pws []string) (string, bool) {
	for _, pw := range pws {
		for _, check := range checks {
			r, err := zipcrypto.NewReaderAt(data, plainSize, []byte(pw), check)
			if err == nil && verify(r) {
				return pw, true
			}
		}
	}
	return "", false
}

// filenameCandidates are password guesses built from the member's own name,
// its container's, and its siblings': every non-empty prefix (a truncation)
// of each name and of that name without its extension, in its original,
// upper and lower case. A vendor's fixed password has been seen to be
// exactly this -- "FBDMI" is the first 5 letters of a sibling member,
// "fbdmisha512", upper-cased -- so these are worth trying before the brute
// force proper starts guessing blind.
func filenameCandidates(zn *Node, f *zip.File, siblings []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	addTruncations := func(name string) {
		// path.Base("") is ".", not "" -- not a real name component to guess
		// passwords from.
		if name == "" || name == "." || name == "/" {
			return
		}
		for _, s := range []string{name, strings.TrimSuffix(name, path.Ext(name))} {
			for n := 1; n <= len(s); n++ {
				t := s[:n]
				add(t)
				add(strings.ToUpper(t))
				add(strings.ToLower(t))
			}
		}
	}
	addTruncations(path.Base(f.Name))
	if zn != nil {
		addTruncations(path.Base(strings.TrimSuffix(zn.Name, "/")))
	}
	for _, s := range siblings {
		addTruncations(path.Base(s))
	}
	return out
}

// numericSequenceCandidates are direct guesses for a run of digits: ascending
// and descending sequences (wrapping through 0-9) starting at every digit,
// and single-digit repeats, for every length 1..maxLen (capped at 10, since
// a run of digits only has 10 distinct starting points worth trying before
// it repeats). Cheap regardless of maxLen or member size -- this is how
// "0123456789" is found instantly rather than needing an exhaustive search
// to reach length 10.
func numericSequenceCandidates(maxLen int) []string {
	if maxLen <= 0 || maxLen > 10 {
		maxLen = 10
	}
	seen := make(map[string]bool, maxLen*30)
	var out []string
	add := func(b []byte) {
		s := string(b)
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for start := 0; start < 10; start++ {
		asc := make([]byte, 0, maxLen)
		desc := make([]byte, 0, maxLen)
		rep := make([]byte, 0, maxLen)
		for n := 0; n < maxLen; n++ {
			asc = append(asc, '0'+byte((start+n)%10))
			desc = append(desc, '0'+byte((start-n%10+10)%10))
			rep = append(rep, '0'+byte(start))
			add(asc)
			add(desc)
			add(rep)
		}
	}
	return out
}

// validZipMember is the structural check a header-checked reader must still
// pass: a .zip-named stored member must start like a zip (one in 256 wrong
// passwords passes the header check alone); everything else is accepted on
// the header check.
func validZipMember(f *zip.File, r *zipcrypto.ReaderAt) bool {
	return f.Method != zip.Store || !strings.HasSuffix(strings.ToLower(f.Name), ".zip") || startsLikeZip(r)
}

// bruteVerify is the structural check strong enough to trust across a brute
// force's much larger candidate count than a handful of named passwords: nil
// when f's method gives no such check (brute force is not attempted).
func bruteVerify(f *zip.File) func(*zipcrypto.ReaderAt) bool {
	switch {
	case f.Method == zip.Store && strings.HasSuffix(strings.ToLower(f.Name), ".zip"):
		return startsLikeZip
	case f.Method == zip.Deflate:
		// A short deflate stream decoding without error is not rare enough on
		// its own (a handful of wrong keys away, for a small member): the
		// zip's own recorded CRC32 of the uncompressed data is what actually
		// rules out the false positive a bare "it inflated" lets through.
		return func(r *zipcrypto.ReaderAt) bool {
			fr := flate.NewReader(io.NewSectionReader(r, 0, r.Size()))
			defer fr.Close()
			h := crc32.NewIEEE()
			n, err := io.Copy(h, fr)
			return err == nil && uint64(n) == f.UncompressedSize64 && h.Sum32() == f.CRC32
		}
	default:
		return nil
	}
}

// nodeFromDecrypted builds the node a decrypted member becomes, once r
// (already password-checked and structurally validated) is in hand.
func nodeFromDecrypted(f *zip.File, r *zipcrypto.ReaderAt) *Node {
	var k *Node
	size := int64(f.UncompressedSize64)
	if f.Method == zip.Store {
		persistCheckpoints(r)
		k = FromReaderAt(f.Name, r, size)
	} else {
		persistCheckpoints(r)
		k = FromStream(f.Name, size, func() (io.ReadCloser, error) {
			return flate.NewReader(io.NewSectionReader(r, 0, r.Size())), nil
		})
	}
	k.Modified = f.Modified
	return withClaim(k, "crc32", fmtCRC(f.CRC32), size)
}

func fmtCRC(c uint32) string { return fmt.Sprintf("%08x", c) }

func startsLikeZip(r *zipcrypto.ReaderAt) bool {
	var b [4]byte
	if _, err := r.ReadAt(b[:], 0); err != nil {
		return false
	}
	return string(b[:]) == "PK\x03\x04" || string(b[:]) == "PK\x05\x06"
}

// persistCheckpoints keeps an opened member's cipher checkpoints in the user cache,
// so reopening it (the next run, or a browse descending into it again) does not
// decrypt everything before the part it reads.
func persistCheckpoints(r *zipcrypto.ReaderAt) {
	d, err := os.UserCacheDir()
	if err != nil {
		return
	}
	r.Persist(filepath.Join(d, "go-unbrick", "zipcrypto", r.ID()))
}
