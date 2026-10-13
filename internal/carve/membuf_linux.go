package carve

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// availableMemory is /proc/meminfo's MemAvailable: what can be allocated
// without swapping, counting the page cache the kernel will give back.
func availableMemory() (int64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemAvailable:"); ok {
			fields := strings.Fields(rest) // "<n> kB"
			if len(fields) == 0 {
				return 0, false
			}
			kb, err := strconv.ParseInt(fields[0], 10, 64)
			return kb << 10, err == nil
		}
	}
	return 0, false
}
