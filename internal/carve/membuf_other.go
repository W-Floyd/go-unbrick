//go:build !linux && !darwin

package carve

// availableMemory is not known on this platform; MaxBuffer keeps its floor.
func availableMemory() (int64, bool) { return 0, false }
