package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// printFjhdmiReport prints what a Fujitsu Ten OTA container (fbdmisha512 +
// update.ini + update.zip, see internal/vendor/alpine.go) says about itself,
// inline under its listing the way reconZipMember's recursive report prints
// a nested payload's own identity -- cheap facts unconditionally (update.ini
// is a handful of bytes), fbdmisha512's hashes only under --verify, since
// checking them means hashing every sibling member whole, update.zip (the
// payload) very much included.
//
// false when kids is not this container's shape (no update.ini among them):
// nothing is printed then, and the caller's own per-member listing runs as
// if this were never tried.
func printFjhdmiReport(kids []*carve.Node, indent string) bool {
	byName := make(map[string]*carve.Node, len(kids))
	for _, k := range kids {
		byName[filepath.Base(k.Name)] = k
	}
	ini, ok := byName["update.ini"]
	if !ok {
		return false
	}
	data, err := ini.Bytes()
	if err != nil {
		return false
	}
	info := vendor.ParseFjhdmiUpdateIni(data)
	if info.ModelType == "" && info.UpdateVersion == "" {
		return false
	}
	if info.ModelType != "" {
		fmt.Printf("%sModel:          %s\n", indent, info.ModelType)
	}
	if info.UpdateVersion != "" {
		fmt.Printf("%sUpdate version: %s\n", indent, info.UpdateVersion)
	}
	fmt.Printf("%sSystem update:  %s, MICOM update: %s\n", indent, yesno(info.SystemUpdate), yesno(info.MicomUpdate))
	if reconVerify {
		verifyFjhdmiManifest(byName, indent)
	}
	return true
}

// verifyFjhdmiManifest checks fbdmisha512's listed sha512 of each sibling
// member (update.ini and update.zip itself included) against what it
// actually decrypts to. A name the manifest lists but this container doesn't
// have is skipped, not reported as a mismatch -- a different release may
// list fewer or more members than this one happens to.
func verifyFjhdmiManifest(byName map[string]*carve.Node, indent string) {
	manifest, ok := byName["fbdmisha512"]
	if !ok {
		return
	}
	data, err := manifest.Bytes()
	if err != nil {
		return
	}
	var bad, checked []string
	for _, e := range vendor.ParseFjhdmiManifest(data) {
		name := strings.TrimPrefix(e.Name, "./")
		k, ok := byName[filepath.Base(name)]
		if !ok {
			continue
		}
		ra, err := k.ReaderAt()
		if err != nil {
			bad = append(bad, name)
			continue
		}
		h := sha512.New()
		if _, err := io.Copy(h, io.NewSectionReader(ra, 0, k.Size)); err != nil {
			bad = append(bad, name)
			continue
		}
		checked = append(checked, name)
		if hex.EncodeToString(h.Sum(nil)) != e.Hash {
			bad = append(bad, name)
		}
	}
	switch {
	case len(bad) > 0:
		fmt.Printf("%s%s fbdmisha512 hash mismatch: %s\n", indent, cWarn("[!]"), strings.Join(bad, ", "))
	case len(checked) > 0:
		fmt.Printf("%sfbdmisha512: %d file(s) verified\n", indent, len(checked))
	}
}
