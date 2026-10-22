package zipcrypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
)

// ID names a member's cipher stream: the state after its header (which holds the
// password and the header's random bytes) and its length. Equal IDs have equal
// checkpoints.
func (r *ReaderAt) ID() string {
	r.mu.Lock()
	k := r.cps[0]
	r.mu.Unlock()
	var b [28]byte
	binary.BigEndian.PutUint32(b[0:], k.k0)
	binary.BigEndian.PutUint32(b[4:], k.k1)
	binary.BigEndian.PutUint32(b[8:], k.k2)
	binary.BigEndian.PutUint64(b[12:], uint64(r.size))
	binary.BigEndian.PutUint64(b[20:], checkpointEvery)
	sum := sha256.Sum256(b[:])
	return hex.EncodeToString(sum[:16])
}

// Persist keeps the checkpoints in file, so a member decrypted once, up to the
// end of a zip's central directory say, costs one checkpoint's worth of
// decrypting on every later open instead of a pass over everything before it. A
// file that does not fit this member is ignored; one that cannot be written is
// not an error, the checkpoints are just not kept.
func (r *ReaderAt) Persist(file string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.file = file
	data, err := os.ReadFile(file)
	if err != nil || len(data)%12 != 0 || len(data) == 0 {
		return
	}
	cps := make([]keys, len(data)/12)
	for i := range cps {
		d := data[i*12:]
		cps[i] = keys{binary.BigEndian.Uint32(d), binary.BigEndian.Uint32(d[4:]), binary.BigEndian.Uint32(d[8:])}
	}
	if cps[0] != r.cps[0] || int64(len(cps)-1)*checkpointEvery > r.size {
		return
	}
	if len(cps) > len(r.cps) {
		r.cps = cps
	}
	r.saved = len(r.cps)
}

// saveEvery is the new checkpoints worth rewriting the file for, when a pass is not over.
const saveEvery = 64

// save writes the checkpoints if there are more than the file holds; unless forced,
// only once saveEvery are new.
func (r *ReaderAt) save(force bool) {
	r.mu.Lock()
	if r.file == "" || len(r.cps) <= r.saved || !force && len(r.cps)-r.saved < saveEvery {
		r.mu.Unlock()
		return
	}
	data := make([]byte, 0, len(r.cps)*12)
	for _, k := range r.cps {
		data = binary.BigEndian.AppendUint32(data, k.k0)
		data = binary.BigEndian.AppendUint32(data, k.k1)
		data = binary.BigEndian.AppendUint32(data, k.k2)
	}
	n, file := len(r.cps), r.file
	r.mu.Unlock()
	if os.MkdirAll(filepath.Dir(file), 0o755) != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".cp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr != nil || cerr != nil || os.Rename(tmp.Name(), file) != nil {
		os.Remove(tmp.Name())
		return
	}
	r.mu.Lock()
	r.saved = max(r.saved, n)
	r.mu.Unlock()
}
