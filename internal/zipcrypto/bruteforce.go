package zipcrypto

import (
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

// DefaultBruteforceCharset is upper+lower+digit: a vendor's fixed zip
// password is not a human's to remember, so it is rarely anything but short
// and alphanumeric. Widen this when it isn't.
const DefaultBruteforceCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// BruteforceOptions configures Bruteforce.
type BruteforceOptions struct {
	// Charset builds the passwords tried; DefaultBruteforceCharset when "".
	Charset string
	// MaxLen is the longest password length tried (1..MaxLen).
	MaxLen int
	// Progress, called once per password length right before that length's
	// search starts, is the only visibility into a running search: the
	// space (and so the time, especially under an expensive verify like a
	// full decompress) grows by len(Charset) with every extra length, so a
	// search that looked instant at one length can go quiet for minutes at
	// the next with nothing else to show for it. Optional.
	Progress func(length int)
}

// Bruteforce tries every password of length 1..opts.MaxLen built from
// opts.Charset against src (an encrypted member's data, header included;
// size its plaintext length), parallel across the CPUs, stopping at the
// first candidate whose header check byte matches one of checks and whose
// opened reader passes verify.
//
// verify decides how expensive each header-check survivor is: it should read
// only as much of the member as it needs to tell a real match from the
// 1-in-256 of a wrong password that merely passes the header check (a fixed
// signature costs nothing; a full decompress-and-CRC check, the only way to
// confirm a deflate member, costs as much as decompressing it once per
// survivor -- a wrong key's stream has been seen to decode to completion far
// more often than it errors out early, so this is not rare enough to ignore).
// That cost, multiplied by how many candidates reach verify at all, is the
// caller's to bound -- by MaxLen, and by not calling this past some size of
// member it isn't prepared to pay for.
//
// Returns the password and true on the first verified match; false if every
// candidate up to opts.MaxLen was tried and none passed.
func Bruteforce(src io.ReaderAt, size int64, checks []byte, verify func(*ReaderAt) bool, opts BruteforceOptions) (string, bool) {
	charset := opts.Charset
	if charset == "" {
		charset = DefaultBruteforceCharset
	}
	var found atomic.Bool
	var result string
	var resultMu sync.Mutex

	trial := func(pw []byte) bool {
		for _, c := range checks {
			r, err := NewReaderAt(src, size, pw, c)
			if err != nil {
				continue
			}
			if verify(r) {
				return true
			}
		}
		return false
	}

	var enumerate func(prefix []byte, remaining int)
	enumerate = func(prefix []byte, remaining int) {
		if found.Load() {
			return
		}
		if remaining == 0 {
			if trial(prefix) {
				resultMu.Lock()
				if !found.Load() {
					result = string(prefix)
					found.Store(true)
				}
				resultMu.Unlock()
			}
			return
		}
		buf := append(prefix, 0)
		for i := 0; i < len(charset); i++ {
			buf[len(buf)-1] = charset[i]
			enumerate(buf, remaining-1)
			if found.Load() {
				return
			}
		}
	}

	for l := 1; l <= opts.MaxLen && !found.Load(); l++ {
		if opts.Progress != nil {
			opts.Progress(l)
		}
		workers := runtime.GOMAXPROCS(0)
		jobs := make(chan int, len(charset))
		for i := 0; i < len(charset); i++ {
			jobs <- i
		}
		close(jobs)
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for first := range jobs {
					if found.Load() {
						return
					}
					prefix := make([]byte, 1, l)
					prefix[0] = charset[first]
					enumerate(prefix, l-1)
				}
			}()
		}
		wg.Wait()
	}
	return result, found.Load()
}
