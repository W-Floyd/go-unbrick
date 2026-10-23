package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/cache"
)

// runFileReconCached is runFileRecon, through pkg/analysis/cache's Recon domain:
// the same report for the same file reads from the cache instead of being
// recomputed, until either the file's own content changes (infile.Identity) or
// go-unbrick's recognizers do (cache.Versions) -- see that package's doc for
// what "the same report" is allowed to mean across a version bump.
//
// Bypassed (falls straight through to runFileRecon, uncached) whenever this
// recon has a side effect beyond the printed report: --carve writes files,
// --learn writes to the knowledge store, and neither should be skipped just
// because an earlier, textually identical report is on file.
func runFileReconCached(path string) error {
	if reconCarveDir != "" || reconLearn {
		return runFileRecon(path)
	}
	key := reconCacheKey(path)
	if key == "" { // identity unavailable (e.g. an http input with no ETag/Last-Modified): can't cache safely
		return runFileRecon(path)
	}
	if text, ok := cache.Get(cache.Recon, key); ok {
		fmt.Print(text)
		return nil
	}
	text, err := captureStdout(func() error { return runFileRecon(path) })
	fmt.Print(text) // print what was captured either way, success or not, same as if this call had not been cached
	if err == nil {
		cache.Put(cache.Recon, key, text)
	}
	return err
}

// reconCacheKey names everything a cached recon report depends on besides the
// recognizers themselves (cache.Recon's Version already covers those): the
// file's own content, which secrets are loaded to decrypt it (a report with
// and without them differs), and the request-shaping flags that change what
// is printed. "" when the file's identity can't be determined, so the caller
// knows not to cache this one at all rather than under a key that might
// collide with an unrelated input.
func reconCacheKey(path string) string {
	id := infile.Identity(path)
	if id == "" {
		return ""
	}
	var secretNames []string
	for _, s := range aeskeys.Secrets() {
		secretNames = append(secretNames, s.Name)
	}
	sort.Strings(secretNames)
	return strings.Join([]string{
		id,
		"secrets=" + strings.Join(secretNames, ","),
		fmt.Sprintf("verify=%v", reconVerify),
		fmt.Sprintf("with=%s", reconWith), // the request, not yet resolved -- "", "none", or a path all mean different things
		fmt.Sprintf("depth=%d", reconDepth),
		fmt.Sprintf("why=%s", reconWhy),
	}, "\x00")
}
