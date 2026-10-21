package srcdiff

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/gitsrc"
	"github.com/W-Floyd/go-unbrick/internal/matchcache"
	core "github.com/W-Floyd/go-unbrick/internal/srcdiff"
	"github.com/W-Floyd/go-unbrick/internal/srcident"
	"github.com/W-Floyd/go-unbrick/internal/upstreamsrc"
)

// A release often does not say which version of a project it holds. FindTag looks for the
// upstream tag whose tree has the most of a sample of the project's files, byte for byte. It is
// `srcdiff --auto`'s tag search: the same method, and the same answers cache.
const (
	// tagSampleFiles is how many of the tree's files are hashed to score a tag with.
	tagSampleFiles = 300
	// tagSampleMax skips files too big to be worth hashing for a sample.
	tagSampleMax = 256 << 10
	// tagCoarse is how many items one round of the search scores, spread across the range it
	// is narrowing.
	tagCoarse = 30
	// tagConfident is the share of the sample a tag must hold to be named.
	tagConfident = 0.3
	// tagAnswerTTL is how long an answer is kept: a tree's closest release does not change
	// when later releases are made, only if it was a tie.
	tagAnswerTTL = 30 * 24 * time.Hour
)

// matchParams names the search's own settings, so a change to how it searches does not serve
// answers it would no longer give. It is what `srcdiff` names them, so the answers are shared.
func matchParams() string {
	return fmt.Sprint("v1/", tagSampleFiles, "/", tagSampleMax, "/", tagCoarse, "/", 0.01)
}

type matchAnswer struct {
	Ref  string
	Note string
}

type versionedTag struct {
	upstreamsrc.Tag
	Version string
}

// sampleBlobs hashes an evenly spread sample of the tree's files into a set of git blob ids,
// which a commit holds when it has that file's content.
func sampleBlobs(files []core.File) (map[string]bool, int, error) {
	var cand []core.File
	for _, f := range files {
		if f.Size > 0 && f.Size <= tagSampleMax {
			cand = append(cand, f)
		}
	}
	sort.Slice(cand, func(i, j int) bool { return cand[i].Path < cand[j].Path })
	step := max(1, len(cand)/tagSampleFiles)
	var picked []core.File
	for i := 0; i < len(cand) && len(picked) < tagSampleFiles; i += step {
		picked = append(picked, cand[i])
	}
	set := map[string]bool{}
	for _, f := range picked {
		rc, err := f.Open()
		if err != nil {
			return nil, 0, err
		}
		sha, err := core.BlobSHA(rc, f.Size)
		rc.Close()
		if err != nil {
			return nil, 0, err
		}
		set[sha] = true
	}
	return set, len(picked), nil
}

var (
	anyVersion = regexp.MustCompile(`\d+(?:[._]\d+)*[a-z]?`)
	preRelease = regexp.MustCompile(`(?i)(rc|beta|alpha|pre|dev|snapshot)[-_.]?\d*`)
)

// versionedTags keeps the tags that name a release, sorted by version. A tag template says
// which; without a rule, any tag with a version in its name that is not a pre-release.
func versionedTags(rule *srcident.Rule, tags []upstreamsrc.Tag) []versionedTag {
	var out []versionedTag
	for _, t := range tags {
		var v string
		var ok bool
		if rule != nil {
			v, ok = rule.TagVersion(t.Name)
		} else if m := anyVersion.FindString(t.Name); m != "" && !preRelease.MatchString(t.Name) {
			v, ok = strings.ReplaceAll(m, "_", "."), true
		}
		if ok {
			out = append(out, versionedTag{t, v})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return srcident.CompareVersions(out[i].Version, out[j].Version) < 0 })
	return out
}

// scorer makes the function a search scores items with: it brings in the trees of the items it
// is asked about, together, and counts how many of the sample's files each holds byte for byte.
func scorer(repo *upstreamsrc.Repo, local map[string]bool, label string, item func(int) upstreamsrc.Tag, scores map[int]int) func([]int) error {
	return func(idx []int) error {
		var todo []int
		var fetch []upstreamsrc.Tag
		for _, i := range idx {
			if _, done := scores[i]; !done {
				todo = append(todo, i)
				fetch = append(fetch, item(i))
			}
		}
		if len(todo) == 0 {
			return nil
		}
		if err := repo.Fetch("searching "+label, fetch); err != nil {
			return err
		}
		for _, i := range todo {
			set, err := repo.Blobs(item(i).Commit)
			if err != nil {
				return err
			}
			m := 0
			for sha := range local {
				if set[sha] {
					m++
				}
			}
			scores[i] = m
		}
		return nil
	}
}

// bestIndex is the item with the most matches, the latest among equals.
func bestIndex(scores map[int]int) int {
	b := -1
	for i, m := range scores {
		if b < 0 || m > scores[b] || (m == scores[b] && i > b) {
			b = i
		}
	}
	return b
}

// searchBest finds the best of n ordered items without scoring them all: it scores a spread
// across the range, then spreads across the best one's neighbours, and so on until it is scoring
// every item between them. The match is not monotonic but it is peaked, so this finds the peak
// in a few dozen items out of thousands.
func searchBest(n int, score func([]int) error, scores map[int]int) (int, error) {
	lo, hi := 0, n-1
	for {
		step := max(1, (hi-lo+1)/tagCoarse)
		var idx []int
		for i := lo; i <= hi; i += step {
			idx = append(idx, i)
		}
		if idx[len(idx)-1] != hi {
			idx = append(idx, hi)
		}
		if err := score(idx); err != nil {
			return -1, err
		}
		b := bestIndex(scores)
		if step == 1 {
			return b, nil
		}
		lo, hi = max(lo, b-step), min(hi, b+step)
	}
}

// FindTag finds the upstream tag the project at root in the archive is closest to: the tag whose
// tree holds the most of a sample of the project's files. ref is "" when none is close enough,
// and note says what was found either way. It fetches from the upstream's git host (the tags'
// trees, partially) and can take a while.
func FindTag(input, root, catalogDir string, o Options) (ref, note string, err error) {
	found, _, err := identify(input, catalogDir)
	if err != nil {
		return "", "", err
	}
	var c *srcident.Candidate
	for i := range found {
		if found[i].Root == root {
			c = &found[i]
		}
	}
	if c == nil {
		return "", "", fmt.Errorf("%q is not a project the catalog knows an upstream for", root)
	}
	if _, err := allowed(c.Rule.Repo); err != nil {
		return "", "", err
	}
	files, _, closeIn, err := treeFiles(input, root)
	if err != nil {
		return "", "", err
	}
	defer closeIn()
	local, n, err := sampleBlobs(files)
	if err != nil {
		return "", "", err
	}
	if n == 0 {
		return "", "no files to match tags with", nil
	}
	mc := matchcache.Default()
	key := matchcache.Key("besttag", matchParams(), c.Rule.Repo, c.Rule.Tag, matchcache.SetKey(local))
	var hit matchAnswer
	if mc.Get(key, &hit) {
		return hit.Ref, hit.Note + " [cached]", nil
	}
	tags, err := upstreamsrc.ListTags(c.Rule.Repo)
	if err != nil {
		return "", "", err
	}
	vt := versionedTags(c.Rule, tags)
	if len(vt) == 0 {
		return "", "", fmt.Errorf("%s has no tags of the shape %q", c.Rule.Repo, c.Rule.Tag)
	}
	cache := o.CacheDir
	if cache == "" {
		if cache, err = gitsrc.DefaultCache(); err != nil {
			return "", "", err
		}
	}
	repo, err := upstreamsrc.OpenRepo(c.Rule.Repo, cache)
	if err != nil {
		return "", "", err
	}
	scores := map[int]int{}
	b, err := searchBest(len(vt), scorer(repo, local, c.Rule.ID+" tags", func(i int) upstreamsrc.Tag { return vt[i].Tag }, scores), scores)
	if err != nil {
		return "", "", err
	}
	ties := 0
	for i, m := range scores {
		if i != b && m == scores[b] {
			ties++
		}
	}
	share := float64(scores[b]) / float64(len(local))
	if share < tagConfident {
		note = fmt.Sprintf("no confident match: closest is %s with %d%% of %d sampled files", vt[b].Name, int(share*100), len(local))
		mc.Put(key, tagAnswerTTL, matchAnswer{Note: note})
		return "", note, nil
	}
	note = fmt.Sprintf("best-matching tag %s: %d%% of %d sampled files identical", vt[b].Name, int(share*100), len(local))
	if ties > 0 {
		note += fmt.Sprintf(" (%d other tag(s) match as well; the latest is taken)", ties)
	}
	mc.Put(key, tagAnswerTTL, matchAnswer{Ref: vt[b].Name, Note: note})
	return vt[b].Name, note, nil
}
