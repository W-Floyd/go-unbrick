package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/aeskeys"
	"github.com/W-Floyd/go-unbrick/internal/hashcache"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/cache"
)

// runFileReconCached is runFileRecon's printed report, straight to stdout,
// through pkg/analysis/cache's Recon domain. See reconCachedText.
func runFileReconCached(path string) error {
	text, err := reconCachedText(path)
	fmt.Print(text) // print what was captured either way, success or not, same as if this call had not been cached
	return err
}

// reconCachedText is runFileRecon's printed report, captured as text rather
// than written straight to stdout: the same report for the same file reads
// from the cache instead of being recomputed, until either the file's own
// content changes or go-unbrick's recognizers do (cache.Versions). Returning
// the text instead of printing it lets a caller that post-processes it
// (runDirRecon's brief summary) share the same cache runFileReconCached uses,
// rather than needing its own copy of this logic.
//
// Bypassed (always recomputed, never read from or written to the cache)
// whenever this recon has a side effect beyond the printed report: --carve
// writes files, --learn writes to the knowledge store, and neither should be
// skipped just because an earlier, textually identical report is on file.
func reconCachedText(path string) (string, error) {
	if reconCarveDir != "" || reconLearn {
		return captureStdout(func() error { return runFileRecon(path) })
	}
	if key := reconCacheKey(path); key != "" {
		if text, ok := cache.Get(cache.Recon, key); ok {
			return text, nil
		}
	}
	text, err := captureStdout(func() error { return runFileRecon(path) })
	if err == nil {
		// Recomputed, not reused from above: running the recon may itself have
		// read the file in full and so recorded its content digest
		// (infile.ReadFile) only just now, letting this result be found by a
		// later recon of a byte-identical path even if this path's own
		// identity never matches it again.
		if key := reconCacheKey(path); key != "" {
			cache.Put(cache.Recon, key, text)
		}
	}
	return text, err
}

// reconCacheKey names everything a cached recon report depends on besides the
// recognizers themselves (cache.Recon's Version already covers those): the
// file's own content, which secrets are loaded to decrypt it (a report with
// and without them differs), and the request-shaping flags that change what
// is printed. "" when the file's identity can't be determined, so the caller
// knows not to cache this one at all rather than under a key that might
// collide with an unrelated input.
func reconCacheKey(path string) string {
	id := contentOrPathIdentity(path)
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

// contentOrPathIdentity prefers path's content digest, qualified by its own
// bare name, over its path+size+mtime Identity, when a digest is already
// known for it: two different paths of the same name sharing byte-identical
// content then converge onto the same recon cache row instead of each paying
// for its own recon -- the same member name recurring across two firmware
// packages, say. The name stays in the key even though the digest is
// content-based: recon's output can genuinely depend on it (a vendor
// recognizer matching by filename, the bare-extension fallback in typeLabel),
// not only on bytes, so two files sharing content under *different* names
// must not share a cache row even once both digests are known. Two ways a
// digest can already be known:
//
//   - infile.ReadFile has already recorded one for this exact path (someone
//     fully read it before: recon's own earlier pass, a diff, --creds-audit).
//   - hashcache.GetBySize has a digest for some OTHER path of the same size --
//     a cheap, stat-only signal (no bytes read to produce it) that this might
//     be that same content. On that signal alone this does force a read:
//     infile.ReadFile, to actually hash and confirm, rather than doing a full
//     recon on the strength of a size guess. Worth it even when the guess is
//     wrong (coincidence, not identity): most of recon's own per-format
//     handlers (reconELF, reconGPT, the entropy fallback, ...) already read
//     the file in full themselves, so this mostly just moves that read
//     earlier rather than adding one, and the digest is cached either way for
//     next time -- and worth it even when the name turns out to differ from
//     whatever first cached that content, since the digest is still useful on
//     its own (GetBySize, a future same-named match).
//
// Falls back to plain Identity when no digest is known either way.
func contentOrPathIdentity(path string) string {
	id := infile.Identity(path)
	if id == "" {
		return ""
	}
	fi, err := infile.Stat(path)
	if err != nil {
		return id
	}
	name := infile.Base(path)
	if sum, ok := hashcache.Get(id+"\x00sha256", fi.Size(), false); ok {
		return "sha256:" + sum + "\x00name=" + name
	}
	if _, ok := hashcache.GetBySize(fi.Size()); ok {
		if b, err := infile.ReadFile(path); err == nil {
			if sum, ok := hashcache.Get(id+"\x00sha256", int64(len(b)), false); ok {
				return "sha256:" + sum + "\x00name=" + name
			}
		}
	}
	return id
}
