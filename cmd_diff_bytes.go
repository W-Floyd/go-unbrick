package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/hashcache"
)

const (
	probeBlock = 64 << 10 // read from each end first
	lockstep   = 1 << 20  // then both files together, a chunk at a time
)

// sameBytes reports whether two members hold the same bytes, doing the
// cheapest check that can decide and stopping at the first difference:
//
//  1. sizes, when both are known;
//  2. digests already in the cache for both;
//  3. the first and last probeBlock bytes of each, where they read at random;
//  4. both read together, chunk by chunk, stopping at the first chunk that
//     differs.
//
// Only a pair that is equal all the way through gets past step 4, and then the
// digests of both are known and cached. A pair that differs early costs a few
// blocks, however large.
func sameBytes(a, b *carve.Node) (bool, error) {
	if a.Size >= 0 && b.Size >= 0 && a.Size != b.Size {
		return false, nil
	}
	ka, kb := cacheKey(a, "sha256"), cacheKey(b, "sha256")
	if ha, ok := hashcache.Get(ka, a.Size, diffTrust); ok {
		if hb, ok := hashcache.Get(kb, b.Size, diffTrust); ok {
			return ha == hb, nil
		}
	}
	if same, decided, err := probeEnds(a, b); err != nil || decided && !same {
		return false, err
	}
	return readTogether(a, b, ka, kb)
}

// probeEnds compares the first and last block of two nodes that read at random.
// decided is false when it could not look; a mismatch is decisive, a match is not.
func probeEnds(a, b *carve.Node) (same, decided bool, err error) {
	if a.Size < 0 || a.Size != b.Size || !a.RandomAccess() || !b.RandomAccess() {
		return false, false, nil
	}
	ra, err := a.ReaderAt()
	if err != nil {
		return false, false, nil
	}
	rb, err := b.ReaderAt()
	if err != nil {
		return false, false, nil
	}
	n := min(a.Size, probeBlock)
	bufA, bufB := make([]byte, n), make([]byte, n)
	for _, off := range []int64{0, a.Size - n} {
		if _, err := ra.ReadAt(bufA, off); err != nil && err != io.EOF {
			return false, false, nil
		}
		if _, err := rb.ReadAt(bufB, off); err != nil && err != io.EOF {
			return false, false, nil
		}
		if !bytes.Equal(bufA, bufB) {
			return false, true, nil
		}
	}
	return true, true, nil
}

// readTogether reads both nodes in step and stops at the first differing chunk.
// Reaching the end of both with every chunk equal records their SHA-256, which
// the same pass computed, under ka and kb.
func readTogether(a, b *carve.Node, ka, kb string) (bool, error) {
	ra, err := a.Reader()
	if err != nil {
		return false, err
	}
	defer ra.Close()
	rb, err := b.Reader()
	if err != nil {
		return false, err
	}
	defer rb.Close()
	ha, hb := sha256.New(), sha256.New()
	bufA, bufB := make([]byte, lockstep), make([]byte, lockstep)
	var total int64
	for {
		na, errA := io.ReadFull(progReader{ra}, bufA)
		nb, errB := io.ReadFull(progReader{rb}, bufB)
		if na != nb || !bytes.Equal(bufA[:na], bufB[:nb]) {
			return false, nil
		}
		ha.Write(bufA[:na])
		hb.Write(bufB[:nb])
		total += int64(na)
		for _, e := range []error{errA, errB} {
			if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
				return false, e
			}
		}
		if errA != nil || errB != nil { // short read: both ended, equal so far
			break
		}
	}
	hashcache.Put(ka, total, hex.EncodeToString(ha.Sum(nil)), false)
	hashcache.Put(kb, total, hex.EncodeToString(hb.Sum(nil)), false)
	return true, nil
}
