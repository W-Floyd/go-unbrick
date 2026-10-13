package carve

import "golang.org/x/sys/unix"

// availableMemory is the pages macOS can hand out without paging: free,
// speculative and purgeable ones, and the file-backed cache it drops under
// pressure. "Free" alone reads near zero on a healthy machine, because macOS
// keeps its memory full of cache.
func availableMemory() (int64, bool) {
	size, err := unix.SysctlUint32("hw.pagesize")
	if err != nil || size == 0 {
		return 0, false
	}
	var pages uint64
	for _, name := range []string{"vm.page_free_count", "vm.page_speculative_count", "vm.page_purgeable_count", "vm.page_pageable_external_count"} {
		n, ok := sysctlCount(name)
		if !ok {
			return 0, false
		}
		pages += n
	}
	return int64(pages) * int64(size), true
}

// sysctlCount reads a counter whichever width the kernel gives it: most of the
// vm.page_* ones are 32-bit, vm.page_purgeable_count is 64.
func sysctlCount(name string) (uint64, bool) {
	if n, err := unix.SysctlUint32(name); err == nil {
		return uint64(n), true
	}
	n, err := unix.SysctlUint64(name)
	return n, err == nil
}
