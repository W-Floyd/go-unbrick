package carve

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"io"
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

// zipEncrypted says a member is encrypted with the traditional PKWARE cipher (AES,
// method 99, is not handled).
func zipEncrypted(f *zip.File) bool { return f.Flags&0x1 != 0 && f.Method != 99 }

// decryptedZipMember is the plaintext of an encrypted member, as a node that reads
// at random, if one of the vendor's passwords opens it; nil otherwise. A password
// must pass the member's header check (one in 256 wrong ones do) and, for a member
// named .zip, decrypt to something that starts like one.
func decryptedZipMember(zn *Node, f *zip.File, ra io.ReaderAt) *Node {
	if ZipPasswords == nil || !zipEncrypted(f) || f.Method != zip.Store && f.Method != zip.Deflate {
		return nil
	}
	pws := ZipPasswords(zn, f.Name)
	if len(pws) == 0 {
		return nil
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
			if err != nil {
				continue
			}
			var k *Node
			size := int64(f.UncompressedSize64)
			if f.Method == zip.Store {
				if strings.HasSuffix(strings.ToLower(f.Name), ".zip") && !startsLikeZip(r) {
					continue
				}
				k = FromReaderAt(f.Name, r, size)
			} else {
				k = FromStream(f.Name, size, func() (io.ReadCloser, error) {
					return flate.NewReader(io.NewSectionReader(r, 0, r.Size())), nil
				})
			}
			k.Modified = f.Modified
			return withClaim(k, "crc32", fmtCRC(f.CRC32), size)
		}
	}
	return nil
}

func fmtCRC(c uint32) string { return fmt.Sprintf("%08x", c) }

func startsLikeZip(r io.ReaderAt) bool {
	var b [4]byte
	if _, err := r.ReadAt(b[:], 0); err != nil {
		return false
	}
	return string(b[:]) == "PK\x03\x04" || string(b[:]) == "PK\x05\x06"
}
