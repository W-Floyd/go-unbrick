package edl

// Caching the fused chip identity across runs, so a second recon against a
// device whose loader is still running is full-fidelity without a power cycle.
//
// The identity (JTAG, OEM, OEM_PK_HASH) is read over Sahara, which is gone once
// a programmer runs. But the identity is fused — it does not change — so a run
// that finds a loader already up can show the identity the uploading run saw,
// as long as it is still the same device. The UFS hardware serial (stable
// across boots, read over Firehose) is the key that proves that; a mismatch
// drops the cached identity rather than mislabeling another device.
//
// Freshness needs no timer: if the device had power-cycled it would be back in
// Sahara offering a hello, and this run would read the identity fresh instead
// of reaching for the cache.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// sessionCache is what one loader-backed run leaves for the next.
type sessionCache struct {
	StorageSerial string    `json:"storage_serial"` // UFS serial_num, the device key ("" if the loader would not say)
	Chip          *ChipInfo `json:"chip"`
	Loader        string    `json:"loader"`
	Memory        string    `json:"memory"`
	When          time.Time `json:"when"`
}

func (r *Runner) cachePath() string { return filepath.Join(r.dir, "last-session.json") }

func (r *Runner) loadCache() *sessionCache {
	b, err := os.ReadFile(r.cachePath())
	if err != nil {
		return nil
	}
	var c sessionCache
	if json.Unmarshal(b, &c) != nil || c.Chip == nil {
		return nil
	}
	return &c
}

func (r *Runner) saveCache(c *sessionCache) {
	c.When = time.Now()
	if b, err := json.MarshalIndent(c, "", "  "); err == nil {
		_ = os.WriteFile(r.cachePath(), b, 0o644)
	}
}
