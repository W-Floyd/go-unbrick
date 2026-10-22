// Package zipcrypto reads zip members encrypted with the traditional PKWARE
// cipher ("ZipCrypto"): the weak stream cipher the format shipped with. It is not
// security; vendors use it to keep a package from being opened by accident, with a
// password they derive from the package itself.
package zipcrypto

import (
	"errors"
	"hash/crc32"
	"io"
	"sync"
)

// HeaderLen is the random bytes in front of an encrypted member's data.
const HeaderLen = 12

// ErrPassword is the answer for a password the member's header check refutes.
var ErrPassword = errors.New("zipcrypto: wrong password")

type keys struct{ k0, k1, k2 uint32 }

func newKeys(password []byte) keys {
	k := keys{0x12345678, 0x23456789, 0x34567890}
	for _, c := range password {
		k.update(c)
	}
	return k
}

// crcTable is the CRC-32 table: the cipher's state updates are single CRC steps,
// with no pre- or post-inversion, so they are done by hand (crc32.Update inverts
// around every call, and per byte that is the slow part).
var crcTable = crc32.MakeTable(crc32.IEEE)

func crcStep(crc uint32, b byte) uint32 { return crcTable[byte(crc)^b] ^ (crc >> 8) }

func (k *keys) update(c byte) {
	k.k0 = crcStep(k.k0, c)
	k.k1 = (k.k1+(k.k0&0xff))*134775813 + 1
	k.k2 = crcStep(k.k2, byte(k.k1>>24))
}

func (k *keys) stream() byte {
	t := k.k2 | 2
	return byte((t * (t ^ 1)) >> 8)
}

func (k *keys) decrypt(c byte) byte {
	p := c ^ k.stream()
	k.update(p)
	return p
}

func (k *keys) encrypt(p byte) byte {
	c := p ^ k.stream()
	k.update(p)
	return c
}

// Encrypt encrypts plaintext for a member whose header check byte is check (the
// high byte of its CRC-32, or of its DOS time when it has a data descriptor), with
// a header of random bytes (fixed here: the cipher does not need them random). Used
// to make test archives.
func Encrypt(plaintext, password []byte, check byte) []byte {
	k := newKeys(password)
	out := make([]byte, 0, HeaderLen+len(plaintext))
	hdr := []byte{0x5a, 0x17, 0x2b, 0x91, 0x04, 0xe7, 0x3c, 0x68, 0xd2, 0x0f, 0xa1, check}
	for _, b := range hdr {
		out = append(out, k.encrypt(b))
	}
	for _, b := range plaintext {
		out = append(out, k.encrypt(b))
	}
	return out
}

// Check says whether password opens a member: the last byte of the decrypted
// header must be check. One in 256 wrong passwords passes, so the caller checks
// the content too when it can.
func Check(header []byte, password []byte, check byte) bool {
	if len(header) < HeaderLen {
		return false
	}
	k := newKeys(password)
	var last byte
	for _, c := range header[:HeaderLen] {
		last = k.decrypt(c)
	}
	return last == check
}

// checkpointEvery is the plaintext bytes between saved cipher states. The cipher
// has no way to start in the middle, so reading at random means decrypting forward
// from the nearest state at or before the offset.
//
// Small, because a random read costs up to this much decrypting and, over a network,
// fetching: 256 KiB is 12 bytes of state per 256 KiB of member, and a read in the
// middle of a payload costs a block or two rather than megabytes.
const checkpointEvery = 256 << 10

// ReaderAt decrypts a member at random. The first read far into it decrypts
// everything before it (once, the states along the way kept); after that any
// offset costs at most checkpointEvery bytes of decrypting.
type ReaderAt struct {
	src  io.ReaderAt // the member's data from its 12-byte header
	size int64       // plaintext bytes

	ext sync.Mutex // one pass extending the checkpoints at a time
	mu  sync.Mutex // guards cps and cursor
	cps []keys     // cps[i]: the state after decrypting plaintext [0, i*checkpointEvery)
	// file and saved are Persist's: where the checkpoints are kept, and how many are there.
	file  string
	saved int
	// cursor is the state after the last byte read: where a sequential reader is.
	cursor struct {
		pos int64
		k   keys
		ok  bool
	}
}

// NewReaderAt opens a member: src is its data starting at the 12-byte header, size
// its plaintext length. It fails with ErrPassword if the header refutes the
// password.
func NewReaderAt(src io.ReaderAt, size int64, password []byte, check byte) (*ReaderAt, error) {
	hdr := make([]byte, HeaderLen)
	if _, err := src.ReadAt(hdr, 0); err != nil {
		return nil, err
	}
	k := newKeys(password)
	var last byte
	for _, c := range hdr {
		last = k.decrypt(c)
	}
	if last != check {
		return nil, ErrPassword
	}
	return &ReaderAt{src: src, size: size, cps: []keys{k}}, nil
}

// Size is the plaintext length.
func (r *ReaderAt) Size() int64 { return r.size }

// extend saves states up to the checkpoint at index i, decrypting forward from the
// last one saved. The caller does not hold mu: the pass takes it only to read and
// to save a state, so a reader that needs an earlier checkpoint is not kept
// waiting behind a pass over the whole member.
func (r *ReaderAt) extend(i int) error {
	r.ext.Lock()
	defer r.ext.Unlock()
	defer r.save(true)
	buf := make([]byte, 1<<20)
	for {
		r.mu.Lock()
		n := len(r.cps) - 1
		if n >= i {
			r.mu.Unlock()
			return nil
		}
		k := r.cps[n]
		r.mu.Unlock()
		pos := int64(n) * checkpointEvery
		end := pos + checkpointEvery
		for pos < end {
			want := min(int64(len(buf)), end-pos)
			got, err := r.src.ReadAt(buf[:want], HeaderLen+pos)
			k.decryptBuf(buf[:got])
			pos += int64(got)
			if got < int(want) {
				if err == nil || err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return err
			}
		}
		r.mu.Lock()
		if len(r.cps)-1 == n { // a reader passing it may have saved it already
			r.cps = append(r.cps, k)
		}
		r.mu.Unlock()
	}
}

// record saves the state at plaintext offset pos if it is the next checkpoint not
// yet known.
func (r *ReaderAt) record(pos int64, k keys) {
	if pos%checkpointEvery != 0 {
		return
	}
	r.mu.Lock()
	if int(pos/checkpointEvery) == len(r.cps) {
		r.cps = append(r.cps, k)
	}
	r.mu.Unlock()
}

// decryptAt decrypts data, which sits at plaintext offset at, in place, saving the
// state at each checkpoint it passes: a reader going on from the last one finds
// the checkpoints made as it went, not by a pass of their own.
func (r *ReaderAt) decryptAt(k *keys, data []byte, at int64) {
	for len(data) > 0 {
		n := int64(len(data))
		if next := checkpointEvery - at%checkpointEvery; next < n {
			n = next
		}
		k.decryptBuf(data[:n])
		at += n
		data = data[n:]
		r.record(at, *k)
	}
}

// ReadAt implements io.ReaderAt.
func (r *ReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("zipcrypto: negative offset")
	}
	defer r.save(false)
	if off >= r.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	short := false
	if off+want > r.size {
		want, short = r.size-off, true
	}
	idx := int(off / checkpointEvery)
	var k keys
	var pos int64
	r.mu.Lock()
	known := min(idx, len(r.cps)-1)
	switch {
	case r.cursor.ok && r.cursor.pos <= off && r.cursor.pos >= int64(known)*checkpointEvery:
		// Carrying on from where the last read ended: no checkpoint to go back to, and
		// none to build first (they are made as the reads pass them).
		k, pos = r.cursor.k, r.cursor.pos
	default:
		r.mu.Unlock()
		if err := r.extend(idx); err != nil {
			return 0, err
		}
		r.mu.Lock()
		known = min(idx, len(r.cps)-1)
		k, pos = r.cps[known], int64(known)*checkpointEvery
	}
	r.mu.Unlock()
	// Decrypt forward to off, then the bytes asked for.
	buf := make([]byte, 1<<20)
	for pos < off {
		n := min(int64(len(buf)), off-pos)
		got, err := r.src.ReadAt(buf[:n], HeaderLen+pos)
		r.decryptAt(&k, buf[:got], pos)
		pos += int64(got)
		if int64(got) < n {
			return 0, errOr(err)
		}
	}
	got, err := r.src.ReadAt(p[:want], HeaderLen+off)
	r.decryptAt(&k, p[:got], off)
	r.mu.Lock()
	r.cursor.pos, r.cursor.k, r.cursor.ok = off+int64(got), k, true
	r.mu.Unlock()
	if err == io.EOF {
		err = nil
	}
	if err == nil && short {
		err = io.EOF
	}
	return got, err
}

func errOr(err error) error {
	if err == nil || err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// decryptBuf decrypts data in place: decrypt per byte, with the state in
// registers, which is most of the cipher's speed.
func (k *keys) decryptBuf(data []byte) {
	k0, k1, k2 := k.k0, k.k1, k.k2
	for i, c := range data {
		t := k2 | 2
		p := c ^ byte((t*(t^1))>>8)
		k0 = crcTable[byte(k0)^p] ^ (k0 >> 8)
		k1 = (k1+(k0&0xff))*134775813 + 1
		k2 = crcTable[byte(k2)^byte(k1>>24)] ^ (k2 >> 8)
		data[i] = p
	}
	k.k0, k.k1, k.k2 = k0, k1, k2
}
