package harvest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Sources are where a harvest looks, as catalog/harvest.yaml declares them;
// each list is the default for its flag.
type Sources struct {
	Repos                []string      `yaml:"repos,omitempty"`
	Orgs                 []string      `yaml:"orgs,omitempty"`
	Archives             []string      `yaml:"archives,omitempty"`
	Pages                []string      `yaml:"pages,omitempty"`
	Sites                []Site        `yaml:"sites,omitempty"`
	DiscoverFingerprints []Fingerprint `yaml:"discover_fingerprints,omitempty"`
	DiscoverDenylist     []string      `yaml:"discover_denylist,omitempty"`
}

// Merge appends another file's lists.
func (s *Sources) Merge(o Sources) {
	s.Repos = append(s.Repos, o.Repos...)
	s.Orgs = append(s.Orgs, o.Orgs...)
	s.Archives = append(s.Archives, o.Archives...)
	s.Pages = append(s.Pages, o.Pages...)
	s.Sites = append(s.Sites, o.Sites...)
	s.DiscoverFingerprints = append(s.DiscoverFingerprints, o.DiscoverFingerprints...)
	s.DiscoverDenylist = append(s.DiscoverDenylist, o.DiscoverDenylist...)
}

// Fingerprint is a code-search term for --discover: a file name, or else a
// path fragment.
type Fingerprint struct {
	Term     string `yaml:"term"`
	Filename bool   `yaml:"filename,omitempty"`
}

// Code search allows ~10 queries/min.
const codeSearchDelay = 8 * time.Second

// expandOrg lists an org's repos: a bare name is a GitHub org, "host/group" a
// GitLab group.
func (h *harvester) expandOrg(org string) []string {
	if r := parseRepo(org); !r.isGitHub() {
		if r.isGitLab() {
			return h.expandGitLabGroup(r)
		}
		h.warnf("cannot enumerate %s: only GitHub orgs and GitLab groups are supported", org)
		return nil
	}
	out, err := exec.Command("gh", "api", "orgs/"+org+"/repos?per_page=100", "--paginate",
		"--jq", ".[] | select(.size > 0) | .full_name").Output()
	if err != nil {
		// A missing token should cost this org's repos, not the whole run.
		h.warnf("could not enumerate org %s: %v", org, err)
		return nil
	}
	return nonEmptyLines(string(out))
}

func (h *harvester) codeSearchRepos(term string, isFilename bool) map[string]bool {
	args := []string{"search", "code", "--limit", "50", "--json", "repository"}
	if isFilename {
		args = append(args, "--filename", term)
	} else {
		args = append(args, term, "--match", "path")
	}
	out, err := exec.Command("gh", args...).Output()
	if err != nil {
		h.warnf("code search %q failed (rate limit?): %v", term, err)
		return nil
	}
	var rows []struct {
		Repository struct {
			NameWithOwner string `json:"nameWithOwner"`
			IsFork        bool   `json:"isFork"`
		} `json:"repository"`
	}
	if json.Unmarshal(out, &rows) != nil {
		return nil
	}
	set := map[string]bool{}
	for _, r := range rows {
		if !r.Repository.IsFork {
			set[r.Repository.NameWithOwner] = true
		}
	}
	return set
}

// repoLoaderCount is how many loader-named binaries a repo's tree holds, via
// the git/trees API (which lists binaries code search cannot).
func repoLoaderCount(repo string) int {
	out, err := exec.Command("gh", "api", "repos/"+repo+"/git/trees/HEAD?recursive=1",
		"--jq", `.tree[] | select(.type=="blob") | .path`).Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, p := range nonEmptyLines(string(out)) {
		if loaderExts[strings.ToLower(filepath.Ext(p))] && loaderName.MatchString(filepath.Base(p)) {
			n++
		}
	}
	return n
}

// discoverRepos sweeps text fingerprints for candidate repos, then keeps those
// whose tree holds loader binaries. Cached for scrapeTTL: the rate-limited
// code-search sweep is the slow part.
func (h *harvester) discoverRepos(known map[string]bool) []string {
	cachefile := filepath.Join(h.o.CacheDir, "discover_cache.json")
	var cached struct {
		FetchedAt float64  `json:"fetched_at"`
		Repos     []string `json:"repos"`
	}
	if age, ok := fresh(cachefile); ok && !h.o.Rescrape {
		if b, err := os.ReadFile(cachefile); err == nil && json.Unmarshal(b, &cached) == nil {
			h.logf("  [cache] discovery: %d repo(s), swept %dh ago", len(cached.Repos), int(age.Hours()))
			return cached.Repos
		}
	}
	if h.o.DryRun {
		return nil
	}
	candidates := map[string]bool{}
	for _, fp := range h.o.Sources.DiscoverFingerprints {
		hits := h.codeSearchRepos(fp.Term, fp.Filename)
		h.logf("  [discover] %s: %d repo(s)", fp.Term, len(hits))
		for r := range hits {
			candidates[r] = true
		}
		time.Sleep(codeSearchDelay)
	}
	deny := map[string]bool{}
	for _, r := range h.o.Sources.DiscoverDenylist {
		deny[r] = true
	}
	var sorted []string
	for r := range candidates {
		if !known[r] && !deny[r] {
			sorted = append(sorted, r)
		}
	}
	sort.Strings(sorted)
	h.logf("  [discover] %d new candidate repo(s); checking trees for loaders...", len(sorted))
	var found []string
	for _, r := range sorted {
		if n := repoLoaderCount(r); n > 0 {
			found = append(found, r)
			h.logf("  [discover] + %s (%d loader file(s))", r, n)
		}
	}
	cached.FetchedAt, cached.Repos = float64(time.Now().Unix()), found
	writeJSONFile(cachefile, cached)
	return found
}

// cloneRepo shallow-clones repo into the cache (gh for GitHub, falling back to
// git; git for other hosts), or reuses the cached clone; with Refresh it
// fetches and resets instead.
func (h *harvester) cloneRepo(repo repoRef) string {
	target := filepath.Join(h.o.CacheDir, repo.cacheName())
	if _, err := os.Stat(filepath.Join(target, ".git")); err == nil {
		if !h.o.Refresh {
			h.logf("  [cache] %s -> %s", repo, target)
			return target
		}
		h.logf("  [refresh] %s", repo)
		if !h.o.DryRun {
			_ = h.run("git", "-C", target, "fetch", "--depth", "1", "origin")
			_ = h.run("git", "-C", target, "reset", "--hard", "FETCH_HEAD")
		}
		return target
	}
	h.logf("  [clone] %s", repo)
	if h.o.DryRun {
		return target
	}
	_ = os.MkdirAll(h.o.CacheDir, 0o755)
	var err error
	if repo.isGitHub() {
		if err = h.run("gh", "repo", "clone", repo.path, target, "--", "--depth", "1"); err != nil {
			h.warnf("gh repo clone failed, falling back to git clone")
		}
	}
	if !repo.isGitHub() || err != nil {
		if err := h.run("git", "clone", "--depth", "1", repo.cloneURL(), target); err != nil {
			h.errorf("failed to clone %s", repo)
			return ""
		}
	}
	return target
}

func (h *harvester) run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = h.o.Log, h.o.Log
	return cmd.Run()
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func writeJSONFile(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, b, 0o644)
}

// fresh reports a cache file's age and whether it is within scrapeTTL.
func fresh(path string) (time.Duration, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	age := time.Since(fi.ModTime())
	return age, age < scrapeTTL
}
