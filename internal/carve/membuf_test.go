package carve

import "testing"

func TestClampBuffer(t *testing.T) {
	for _, c := range []struct{ in, want int64 }{
		{0, minBuffer}, {minBuffer / 2, minBuffer}, {4 << 30, 4 << 30}, {64 << 30, maxBuffer},
	} {
		if got := clampBuffer(c.in); got != c.want {
			t.Errorf("clampBuffer(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestAvailableMemoryIsPlausibleWhereKnown(t *testing.T) {
	avail, ok := availableMemory()
	if !ok {
		t.Skip("not known on this platform")
	}
	if avail < 64<<20 || avail > 16<<40 {
		t.Errorf("available memory %d bytes is not plausible", avail)
	}
	if MaxBuffer < minBuffer || MaxBuffer > maxBuffer {
		t.Errorf("MaxBuffer %d outside [%d, %d]", MaxBuffer, int64(minBuffer), int64(maxBuffer))
	}
}
