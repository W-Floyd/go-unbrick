// Package fill finds content that is one short pattern repeated from end to end:
// zeros, 0xff (erased flash), any single byte, or a few bytes over and over (a
// 0xdeadbeef fill). A blank partition or an erased region is a common thing for a
// firmware package to hold, and "unknown" is the wrong thing to call it.
package fill

import (
	"fmt"
	"io"
)

// MinHead is how much of a file's start must be seen to call it a fill: enough
// that a repeating pattern of the longest period repeats several times.
const MinHead = 512

// MaxPeriod is the longest pattern looked for.
const MaxPeriod = 64

// Period is the shortest p (up to MaxPeriod) for which head is its first p bytes
// repeated, or 0 if head is no such fill (or too short to tell).
func Period(head []byte) int {
	if len(head) < MinHead {
		return 0
	}
	for p := 1; p <= MaxPeriod; p++ {
		ok := true
		for i := p; i < len(head); i++ {
			if head[i] != head[i-p] {
				ok = false
				break
			}
		}
		if ok {
			return p
		}
	}
	return 0
}

// Result is what a scan found.
type Result struct {
	Pattern []byte // the repeating unit
	Size    int64  // bytes scanned
	// Whole is set when the pattern runs to the end: the content is the pattern and
	// nothing else. Otherwise the first byte that breaks it is at Break.
	Whole bool
	Break int64
}

// Scan checks that r (size bytes, of which head is the start) is head's pattern all
// the way through, streaming the rest and stopping at the first byte that breaks
// it. A head that is no fill costs nothing: there is nothing to read.
func Scan(r io.Reader, head []byte, size int64) (Result, error) {
	p := Period(head)
	if p == 0 {
		return Result{}, nil
	}
	pat := append([]byte(nil), head[:p]...)
	res := Result{Pattern: pat, Size: size}
	// Where in the pattern the data after the head begins: the head's length mod p.
	phase := len(head) % p
	pos := int64(len(head))
	buf := make([]byte, 1<<20)
	// A pass over the head itself when the whole file is the head.
	for pos < size {
		n, err := r.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] != pat[(phase+i)%p] {
				res.Break = pos + int64(i)
				return res, nil
			}
		}
		phase = (phase + n) % p
		pos += int64(n)
		if err != nil {
			if err == io.EOF {
				break
			}
			return res, err
		}
	}
	res.Whole = pos >= size
	if !res.Whole {
		res.Break = pos
	}
	return res, nil
}

// Describe says what a whole-file fill is, in a line.
func (r Result) Describe() string {
	if len(r.Pattern) == 1 {
		b := r.Pattern[0]
		name := ""
		switch b {
		case 0x00:
			name = " (zeros)"
		case 0xff:
			name = " (erased flash)"
		}
		return fmt.Sprintf("every byte is 0x%02x%s", b, name)
	}
	return fmt.Sprintf("one %d-byte pattern repeated: % x", len(r.Pattern), r.Pattern)
}

// Uniform reports whether b is one byte repeated: for a file too short to call a
// pattern, but that is all of it.
func Uniform(b []byte) bool {
	for _, c := range b {
		if c != b[0] {
			return false
		}
	}
	return len(b) > 0
}
