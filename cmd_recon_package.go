package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// learnPackageFacts lets each vendor read its own package members into the bag.
func learnPackageFacts(path string, bag *facts.Bag) {
	list, err := srcfile.Names(path)
	if err != nil {
		return
	}
	names := make(map[string]bool, len(list))
	for _, n := range list {
		names[n] = true
	}
	access := vendor.PackageAccess{
		Names: names,
		Read: func(name string) []byte {
			n, err := carvePath(path, name)
			if err != nil {
				return nil
			}
			b, _ := n.Bytes()
			return b
		},
		List: func(dir string) []string {
			n, err := carvePath(path, dir)
			if err != nil {
				return nil
			}
			_, kids, err := n.Children()
			if err != nil {
				return nil
			}
			out := make([]string, len(kids))
			for i, k := range kids {
				out[i] = k.Name
			}
			return out
		},
		Decrypts: func() bool { return len(reconSecrets) > 0 },
	}
	vendor.LearnPackage(access, bag)
	if reconVerify {
		verifyUpdateInfo(access)
	}
}

// verifyUpdateInfo checks each update.info member's listed hashes (Hyundai's
// two-level SHA-224, see vendor.HyundaiSHA224) against the package's own
// members. Entries under "./system" and "./micom/..." name the decrypted
// files, which this package carries only as enc_-prefixed ciphertext (see
// vendor.ParseUpdateInfoEntries) - those just can't be found by this name
// and are silently skipped, not reported as mismatches.
func verifyUpdateInfo(pkg vendor.PackageAccess) {
	for name := range pkg.Names {
		if filepath.Base(name) != "update.info" {
			continue
		}
		data := pkg.Read(name)
		if data == nil {
			continue
		}
		var bad []string
		checked, skipped := 0, 0
		for _, e := range vendor.ParseUpdateInfoEntries(data) {
			p := strings.TrimPrefix(e.Dir, "./") + "/" + e.Name
			b := pkg.Read(p)
			if b == nil {
				skipped++
				continue
			}
			checked++
			if got, err := vendor.HyundaiSHA224(bytes.NewReader(b)); err != nil || got != e.Hash {
				bad = append(bad, p)
			}
		}
		switch {
		case len(bad) > 0:
			fmt.Printf("  %s %s hash mismatch: %s\n", cWarn("[!]"), name, strings.Join(bad, ", "))
		case checked > 0:
			fmt.Printf("  %s hash: %d file(s) verified", name, checked)
			if skipped > 0 {
				fmt.Printf(" (%d not found by name - likely pre-encryption names)", skipped)
			}
			fmt.Println()
		}
	}
}
