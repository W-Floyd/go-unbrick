package carve

// MaxBuffer's default follows the memory the machine has to spare, not a fixed
// figure: a multi-GB sparse image is read whole on a machine with room for it,
// and unpacked to a file (with --full-download) on one without.

const (
	minBuffer = 1 << 30  // never below 1 GiB, whatever the machine reports
	maxBuffer = 16 << 30 // a single in-memory node past this is never a good idea
)

// defaultMaxBuffer is half of the available memory, clamped. The other half is
// left for the filesystem expanders, caches and whatever else is running.
func defaultMaxBuffer() int64 {
	avail, ok := availableMemory()
	if !ok {
		return minBuffer
	}
	return clampBuffer(avail / 2)
}

func clampBuffer(n int64) int64 {
	return min(max(n, minBuffer), maxBuffer)
}
