package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go-unbrick/internal/bootelf"
)

// readImage reads path, joining a PIL split image (.mdt with sibling .bNN
// files) into one ELF. missing lists segments whose .bNN was absent.
func readImage(path string) (data []byte, missing []int, err error) {
	data, err = os.ReadFile(path)
	if err != nil || !strings.EqualFold(filepath.Ext(path), ".mdt") || !bootelf.IsELF(data) {
		return data, nil, err
	}
	stem := strings.TrimSuffix(path, filepath.Ext(path))
	return bootelf.JoinSplit(data, func(i int) []byte {
		b, _ := os.ReadFile(fmt.Sprintf("%s.b%02d", stem, i))
		return b
	})
}

// splitNote describes a joined split image's gaps, or "" when complete.
func splitNote(missing []int) string {
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf("%d segment(s) missing, zero-filled: %v", len(missing), missing)
}

func write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s != "" {
			return s
		}
	}
	return ""
}

func mark(ok bool) string {
	if ok {
		return "yes"
	}
	return "no "
}

func yesno(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
