package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/osv"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// srcdiffCVEs is set by --cves: after each comparison, list the vulnerabilities OSV
// knows for the upstream version.
var (
	srcdiffCVEs  bool
	srcdiffCited map[string]bool // CVE ids the release's notices cite; read once
)

// cvesShown bounds the CVEs listed per project, newest first.
const cvesShown = 10

// citedCVEs is every CVE id the release's notices mention.
func citedCVEs(input string) map[string]bool {
	cited := map[string]bool{}
	entries, closer, err := srcfile.Entries(input)
	if err != nil || closer == nil {
		return cited
	}
	defer closer.Close()
	for _, e := range entries {
		if !vendor.IsNoticeName(e.Name) {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		for _, id := range vendor.CitedCVEs(data) {
			cited[id] = true
		}
	}
	return cited
}

// printCVEs lists what OSV knows is wrong with repo at ref, marking those the
// release's own notices say the vendor addressed.
func printCVEs(input, repo, ref string) {
	if ref == "" {
		return
	}
	if srcdiffCited == nil {
		srcdiffCited = citedCVEs(input)
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	vulns, err := osv.New(filepath.Join(dir, "go-unbrick", "osv")).Git(repo, ref)
	if err != nil {
		fmt.Printf("  CVEs: lookup failed: %v\n", err)
		return
	}
	ids := osv.CVEIDs(vulns)
	if len(ids) == 0 {
		fmt.Printf("  CVEs: none in OSV for %s @ %s (OSV may know the project by another URL, and its coverage of old versions is incomplete)\n", strings.TrimSuffix(repo, ".git"), ref)
		return
	}
	summary := map[string]string{}
	for _, v := range vulns {
		for _, id := range v.CVEs() {
			if summary[id] == "" {
				summary[id] = v.Summary
			}
		}
	}
	// Newest first: an old version has many, and the recent ones are what an
	// update that stopped at some date left unfixed.
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })
	fmt.Printf("  CVEs in OSV for %s @ %s (may be incomplete): %d\n", strings.TrimSuffix(repo, ".git"), ref, len(ids))
	for i, id := range ids {
		if i == cvesShown {
			fmt.Printf("    ... %d more\n", len(ids)-cvesShown)
			break
		}
		line := "    " + id
		if s := summary[id]; s != "" {
			if len(s) > 80 {
				s = s[:80] + "…"
			}
			line += "  " + s
		}
		if srcdiffCited[id] {
			line += "  [the notices cite this CVE]"
		}
		fmt.Println(line)
	}
}
