package analysis

import (
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/zippasswords"
)

// ForgetOpened has inputs opened from now on start afresh. Call it after LoadSecrets changes the keys: an input
// opened before keeps what it found, including that no key opened a file, and so would stay shut to the new key.
func ForgetOpened() { carve.ForgetRoots() }

// ZipPasswordCount is how many zip password candidates LoadSecrets has loaded (LoadSecrets itself returns the AES
// key and IV candidates).
func ZipPasswordCount() int { return zippasswords.Count() }
