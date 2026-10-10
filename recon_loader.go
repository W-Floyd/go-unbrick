package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/harvest"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
	"github.com/W-Floyd/go-unbrick/internal/library"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
)

// knownLoader is a Firehose programmer whose signature could authenticate on
// the device a bag describes.
type knownLoader struct {
	where     string // library path, or the index's
	held      bool   // in the library, so its identity was read from the file
	ar        uint32 // its anti-rollback version, when held
	md5       string // first 16 hex of the file's MD5, as the index keys files
	inPackage bool   // shipped in the package recon was given
	warn      string // why it may still be refused
}

// loaderLines says whether a known Firehose programmer can boot the device:
// one built for its hardware (JTAG ID) and signed under its root key. Nothing
// when the bag does not name both.
func loaderLines(b *facts.Bag) []string {
	jtags := deviceJTAGs(b)
	roots := map[string]bool{}
	for _, v := range b.Values(facts.RootKeyHash.Name()) {
		if s, ok := v.Data.(string); ok && s != "" {
			roots[strings.ToLower(s)] = true
		}
	}
	if len(jtags) == 0 || len(roots) == 0 {
		return nil
	}
	oem, _ := facts.Get(b, facts.OEMID)
	target := xblIdentity(b)

	found := packageLoaders(b, jtags, roots, target)
	held := map[string]bool{}
	for _, l := range found {
		held[l.md5] = true
	}
	for _, l := range heldLoaders(jtags, roots, target) {
		if !held[l.md5] {
			held[l.md5] = true
			found = append(found, l)
		}
	}
	found = append(found, indexedLoaders(jtags, oem, roots, held)...)

	what := strings.Join(jtags, "/")
	var root string
	for r := range roots {
		if root == "" || len(r) < len(root) {
			root = r
		}
	}
	if len(found) == 0 {
		return []string{fmt.Sprintf("Loader: none known for %s under root %s…", what, root[:16])}
	}
	out := []string{fmt.Sprintf("Loader: %d known for %s under root %s…", len(found), what, root[:16])}
	for _, l := range found {
		line := "  " + l.where
		switch {
		case l.inPackage:
			line += fmt.Sprintf(" (in this package, ARB %d)", l.ar)
		case l.held && target != nil:
			line += fmt.Sprintf(" (ARB %d)", l.ar)
		case !l.held:
			line += " (indexed, not in the library)"
		}
		if l.warn != "" {
			line += " — " + l.warn
		}
		out = append(out, line)
	}
	return out
}

// deviceJTAGs is the hardware ID a loader must be built for: the one the
// device's images are bound to, else every one the catalog records for its SoC.
func deviceJTAGs(b *facts.Bag) []string {
	if j, ok := facts.Get(b, facts.JTAGID); ok && j != "" && j != "00000000" {
		return []string{strings.ToUpper(j)}
	}
	soc, ok := facts.Get(b, facts.SoC)
	if !ok {
		return nil
	}
	return activeCatalog().JTAGsForSoC(soc)
}

// xblIdentity is the package's XBL signing identity, whose anti-rollback
// version a loader should not be below; nil when the bag holds no XBL.
func xblIdentity(b *facts.Bag) *secboot.Identity {
	data, ok := facts.Get(b, imgfacts.SourceXBL)
	if !ok {
		return nil
	}
	id, err := secboot.FromELF(data)
	if err != nil {
		return nil
	}
	return id
}

// heldLoaders checks the library's loaders of those JTAG IDs by their own
// signatures.
func heldLoaders(jtags []string, roots map[string]bool, target *secboot.Identity) []knownLoader {
	lib := library.Open(libraryDir())
	var out []knownLoader
	for _, f := range lib.Loaders() {
		if !containsFold(jtags, f.JTAGID) {
			continue
		}
		for _, ref := range lib.Builds(f) {
			p := lib.LoaderPath(ref)
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if l, ok := checkLoader(p, data, jtags, roots, target); ok {
				out = append(out, l)
			}
		}
	}
	return out
}

// packageLoaders checks the Firehose programmers the package itself ships.
func packageLoaders(b *facts.Bag, jtags []string, roots map[string]bool, target *secboot.Identity) []knownLoader {
	var out []knownLoader
	for _, v := range b.Values(imgfacts.SourceFirehose.Name()) {
		data, _ := v.Data.([]byte)
		if l, ok := checkLoader(v.Source, data, jtags, roots, target); ok {
			l.inPackage = true
			out = append(out, l)
		}
	}
	return out
}

// checkLoader reads a programmer's identity from its own signature: it must
// be signed under one of roots and not bound to other hardware. Its
// anti-rollback version is checked against target's, when known.
func checkLoader(where string, data []byte, jtags []string, roots map[string]bool, target *secboot.Identity) (knownLoader, bool) {
	id, err := secboot.FromELF(data)
	if err != nil || !roots[strings.ToLower(id.RootSHA256)] && !roots[strings.ToLower(id.RootSHA384)] {
		return knownLoader{}, false
	}
	if j := id.JTAGID; j != "" && j != "00000000" && !containsFold(jtags, j) {
		return knownLoader{}, false
	}
	sum := md5.Sum(data)
	l := knownLoader{where: where, held: true, ar: id.AntiRollback(), md5: hex.EncodeToString(sum[:8])}
	if id.Meta != nil {
		l.ar = id.Meta.AntiRollback
	}
	if target != nil {
		tg := *target
		if tg.Meta != nil {
			tg.SWID = uint64(tg.Meta.AntiRollback) << 32
		}
		ld := *id
		ld.SWID = uint64(l.ar) << 32
		if rb := secboot.ValidateRollback(&ld, &tg); rb.Status != secboot.RollbackSafe {
			l.warn = strings.Join(rb.Reasons, "; ")
		}
	}
	return l, true
}

// indexName is bkerler's loader naming: HW_ID (JTAG ID, OEM ID, model) then
// the root hash's first 8 bytes.
var indexName = regexp.MustCompile(`^([0-9a-fA-F]{8})([0-9a-fA-F]{4})[0-9a-fA-F]{4}_[0-9a-fA-F]{16}_`)

// indexedLoaders matches the catalog's loader index, for loaders the library
// does not hold (held: file MD5s). The index states each file's root hash
// (sha256/sha384, 16 hex); its hardware is known only from a bkerler-style
// name, and a name that states other hardware rules the file out.
func indexedLoaders(jtags []string, oem string, roots map[string]bool, held map[string]bool) []knownLoader {
	entries, err := harvest.ReadTemblast(filepath.Join(catalogDir(), "temblast_loaders.json"))
	if err != nil {
		return nil
	}
	rootMatch := func(pk string) bool {
		pk = strings.ToLower(pk)
		for r := range roots {
			if len(pk) == 16 && strings.HasPrefix(r, pk) {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	var out []knownLoader
	for _, e := range entries {
		md5 := strings.ToLower(e.FileMD5)
		if !rootMatch(e.SHA256) && !rootMatch(e.SHA384) || seen[md5] || held[md5] {
			continue
		}
		l := knownLoader{where: e.Path}
		if m := indexName.FindStringSubmatch(path.Base(e.Path)); m != nil {
			if !containsFold(jtags, m[1]) || oem != "" && !strings.EqualFold(m[2], oem) {
				continue
			}
		} else {
			l.warn = "hardware not stated"
		}
		if e.IsBad {
			l.warn = strings.TrimPrefix(l.warn+"; flagged bad by the index", "; ")
		}
		seen[md5] = true
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].where < out[j].where })
	return out
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
