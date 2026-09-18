// Package unlock verifies bootloader-unlock codes offline against a device's
// signed unlock record.
//
// A vendor implements a single interface — the parser (vendor.UnlockVerifier) —
// which turns an unlock source into a Record. A Record is plain data plus a Check
// closure, so how a vendor decides a code (salted double-hash for Motorola DBVAL,
// or RSA / a stored constant for another OEM) is captured in the closure, not in
// a second interface to implement. See docs/motorola/README.md §3.5.
//
// Verification is offline-checkable but not offline-solvable: you can test a
// vendor-issued code, but recovering one needs a hash preimage and/or the
// vendor's private signing key.
package unlock

// HashFunc is a one-shot digest (init/update/final), returning the raw digest.
// It exists for vendors whose scheme is hash-based; others ignore it.
type HashFunc func([]byte) []byte

// Field is a labelled record value, for display by callers (e.g. `unlock show`).
type Field struct{ Key, Value string }

// Record is a parsed unlock record: the scheme name, human-readable fields, and a
// Check that reports whether a code is accepted. It is plain data — the vendor
// builds Check to capture whatever state its algorithm needs.
type Record struct {
	Scheme string
	Fields []Field
	Check  func(code string) bool
}

// Verify reports whether code would be accepted for this record.
func (r *Record) Verify(code string) bool {
	return r.Check != nil && r.Check(code)
}

// SaltedDoubleHash computes H(salt || H(code[:prefix])) — the shared construction
// a vendor whose scheme is built this way (Motorola DBVAL) uses inside its Check.
func SaltedDoubleHash(h HashFunc, prefix int, salt []byte, code string) []byte {
	c := []byte(code)
	if len(c) > prefix {
		c = c[:prefix]
	}
	d1 := h(c)
	return h(append(append([]byte{}, salt...), d1...))
}
