package vendor

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"go-unbrick/internal/unlock"
)

// Motorola's DBVAL bootloader-unlock scheme (FUN_0004bec0 in MotoBootModule.efi),
// ported from the fogona-abl-notes unlock_code_verify.py. The code check is
// H(salt || H(code[:20])) == target, where salt and target come from an RSA-signed
// record in the cid partition; version <2 uses SHA-1 / header base 0x28, version
// >=2 uses SHA-256 / base 0x2a. See docs/motorola/README.md §3.5.

// motoCodePrefix is how many leading code bytes the firmware hashes (w2=0x14).
const motoCodePrefix = 20

// motoTargetRel is the target digest's offset from the record header base.
const motoTargetRel = 0x26

// motoHash selects the digest primitive and length for a record version.
func motoHash(version int) (unlock.HashFunc, int) {
	if version < 2 {
		return func(b []byte) []byte { s := sha1.Sum(b); return s[:] }, 20
	}
	return func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }, 32
}

// motoHeaderBase is the record-relative header offset (FUN_0004d0f0).
func motoHeaderBase(version int) int {
	if version < 2 {
		return 0x28
	}
	return 0x2a
}

// motoRec holds the parsed DBVAL fields before they become an unlock.Record.
type motoRec struct {
	id      []byte
	serial  string
	salt    []byte
	target  []byte
	version int
}

// record turns the parsed fields into an unlock.Record: display fields plus a
// Check closure that runs Motorola's salted double-hash.
func (m motoRec) record() *unlock.Record {
	fields := []unlock.Field{{Key: "version", Value: strconv.Itoa(m.version)}}
	if m.serial != "" {
		fields = append(fields, unlock.Field{Key: "serial", Value: m.serial})
	}
	if len(m.id) > 0 {
		fields = append(fields, unlock.Field{Key: "id", Value: hex.EncodeToString(m.id)})
	}
	fields = append(fields,
		unlock.Field{Key: "salt", Value: hex.EncodeToString(m.salt)},
		unlock.Field{Key: "target", Value: hex.EncodeToString(m.target)},
	)
	h, _ := motoHash(m.version)
	salt, target := m.salt, m.target
	return &unlock.Record{
		Scheme: "moto-dbval",
		Fields: fields,
		Check: func(code string) bool {
			return bytes.Equal(unlock.SaltedDoubleHash(h, motoCodePrefix, salt, code), target)
		},
	}
}

// ParseUnlock implements UnlockVerifier for Motorola: a get_unlock_data wire
// string (Text with '#') or a raw DBVAL record blob (Blob).
func (motorola) ParseUnlock(src UnlockSource) (*unlock.Record, error) {
	switch {
	case strings.Contains(src.Text, "#"):
		m, err := parseMotoWire(src.Text)
		if err != nil {
			return nil, err
		}
		return m.record(), nil
	case len(src.Blob) > 0:
		m, err := parseMotoRecord(src.Blob)
		if err != nil {
			return nil, err
		}
		return m.record(), nil
	default:
		return nil, fmt.Errorf("motorola: no unlock source (need a get_unlock_data wire string or a record blob)")
	}
}

// parseMotoWire parses Motorola's '#'-separated ASCII-hex get_unlock_data
// challenge: id(8) # serial+model(20) # target # salt(16). The version is
// inferred from the target length (32 => v2/SHA-256, else v1).
func parseMotoWire(wire string) (motoRec, error) {
	fields := strings.Split(wire, "#")
	if len(fields) < 4 {
		return motoRec{}, fmt.Errorf("motorola: unlock wire has %d fields, want 4 (id#serial#target#salt)", len(fields))
	}
	parts := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(fields[i]), " ", ""))
		if err != nil {
			return motoRec{}, fmt.Errorf("motorola: unlock wire field %d not hex: %w", i, err)
		}
		parts[i] = b
	}
	target, salt := parts[2], parts[3]
	if len(salt) > 16 {
		salt = salt[:16]
	}
	version := 1
	if len(target) == 32 {
		version = 2
	}
	serial := parts[1]
	if i := bytes.IndexByte(serial, 0x00); i >= 0 {
		serial = serial[:i]
	}
	return motoRec{id: parts[0], serial: string(serial), salt: salt, target: target, version: version}, nil
}

// parseMotoRecord parses a raw DBVAL record (e.g. read from the cid partition):
// u16be version at 0x02, 16-byte salt at 0x08, target at headerBase+0x26. The
// serial is not recoverable from the blob alone.
func parseMotoRecord(blob []byte) (motoRec, error) {
	if len(blob) < 4 {
		return motoRec{}, fmt.Errorf("motorola: unlock record is %d bytes, too short for a version", len(blob))
	}
	version := int(binary.BigEndian.Uint16(blob[2:4]))
	_, dlen := motoHash(version)
	off := motoHeaderBase(version) + motoTargetRel
	if len(blob) < 24 || len(blob) < off+dlen {
		return motoRec{}, fmt.Errorf("motorola: unlock record is %d bytes, too short for v%d salt/target", len(blob), version)
	}
	return motoRec{
		salt:    append([]byte{}, blob[8:24]...),
		target:  append([]byte{}, blob[off:off+dlen]...),
		version: version,
	}, nil
}
