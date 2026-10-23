package analysis

import "github.com/W-Floyd/go-unbrick/internal/carve"

// ForgetOpened has inputs opened from now on start afresh. Call it after LoadSecrets changes the keys: an input
// opened before keeps what it found, including that no key opened a file, and so would stay shut to the new key.
func ForgetOpened() { carve.ForgetRoots() }
