package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/gitsrc"
	work "github.com/W-Floyd/go-unbrick/internal/progress"
	"github.com/W-Floyd/go-unbrick/internal/srcdiff"
	"github.com/W-Floyd/go-unbrick/internal/srcident"
	"github.com/W-Floyd/go-unbrick/internal/upstreamsrc"
)

const (
	// tagSampleFiles is how many of the tree's files are hashed to score a tag with.
	tagSampleFiles = 300
	// tagSampleMax skips files too big to be worth hashing for a sample.
	tagSampleMax = 256 << 10
	// tagCoarse is how many items one round of the search scores, spread across the
	// range it is narrowing.
	tagCoarse = 30
	// tagConfident is the share of the sample a tag must hold to be named.
	tagConfident = 0.3
	// sweepGain is how much better (of the sample) a commit between tags must
	// match than the tag to be taken over it.
	sweepGain = 0.01
)

// versionedTag is a tag with the version its name states.
type versionedTag struct {
	upstreamsrc.Tag
	Version string
}

// sampleBlobs hashes an evenly spread sample of the tree's files into a set of git
// blob ids, which a commit holds when it has that file's content.
func sampleBlobs(files []srcdiff.File, label string) (map[string]bool, int, error) {
	var cand []srcdiff.File
	for _, f := range files {
		if f.Size > 0 && f.Size <= tagSampleMax {
			cand = append(cand, f)
		}
	}
	sort.Slice(cand, func(i, j int) bool { return cand[i].Path < cand[j].Path })
	step := max(1, len(cand)/tagSampleFiles)
	var picked []srcdiff.File
	for i := 0; i < len(cand) && len(picked) < tagSampleFiles; i += step {
		picked = append(picked, cand[i])
	}
	task := work.Begin("sampling "+label, int64(len(picked)))
	defer task.End()
	set := map[string]bool{}
	for _, f := range picked {
		rc, err := f.Open()
		if err != nil {
			return nil, 0, err
		}
		sha, err := srcdiff.BlobSHA(rc, f.Size)
		rc.Close()
		if err != nil {
			return nil, 0, err
		}
		set[sha] = true
		task.Add(1)
	}
	return set, len(picked), nil
}

// anyVersion reads a version out of a tag name of any shape (release-1.2, v1.2.3,
// libfoo_1_2): for a project the catalog has no tag template for.
var anyVersion = regexp.MustCompile(`\d+(?:[._]\d+)*[a-z]?`)

// versionedTags keeps the tags that name a release, sorted by version. A tag
// template says which; without a rule, any tag with a version in its name that is
// not marked as a pre-release.
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

var preRelease = regexp.MustCompile(`(?i)(rc|beta|alpha|pre|dev|snapshot)[-_.]?\d*`)

// scorer makes the function a search scores items with: it brings in the trees of
// the items it is asked about, together, and counts how many of the sample's files
// each holds byte for byte.
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
		task := work.Begin("scoring "+label, int64(len(todo)))
		defer task.End()
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
			task.Add(1)
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

// searchBest finds the best of n ordered items without scoring them all: it scores
// a spread across the range, then spreads across the best one's neighbours, and so
// on until it is scoring every item between them. The match is not monotonic but
// it is peaked, so this finds the peak in a few dozen items out of thousands.
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

// bestTag finds the upstream tag a tree with no stated version is closest to: the
// tag whose tree holds the most of a sample of the tree's files, byte for byte.
func bestTag(input string, c srcident.Candidate) (ref, note string, err error) {
	files, _, closeIn, err := treeFiles(input, c.Root)
	if err != nil {
		return "", "", err
	}
	defer closeIn()
	local, n, err := sampleBlobs(files, c.Root)
	if err != nil {
		return "", "", err
	}
	if n == 0 {
		return "", "no files to match tags with", nil
	}
	tags, err := upstreamsrc.ListTags(c.Rule.Repo)
	if err != nil {
		return "", "", err
	}
	vt := versionedTags(c.Rule, tags)
	if len(vt) == 0 {
		return "", "", fmt.Errorf("%s has no tags of the shape %q", c.Rule.Repo, c.Rule.Tag)
	}
	cache, err := gitsrc.DefaultCache()
	if err != nil {
		return "", "", err
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
		return "", fmt.Sprintf("no confident match: closest is %s with %d%% of %d sampled files", vt[b].Name, int(share*100), len(local)), nil
	}
	note = fmt.Sprintf("best-matching tag %s: %d%% of %d sampled files identical", vt[b].Name, int(share*100), len(local))
	if ties > 0 {
		note += fmt.Sprintf(" (%d other tag(s) match as well; the latest is taken)", ties)
	}
	return vt[b].Name, note, nil
}

// sweepCommits looks between releases for what a tag only approximates. A vendor
// usually takes a snapshot of upstream at some commit, not at a tag, so a file the
// tag disagrees with may be upstream's own change since. It lists the commits
// between the tags either side of tag and finds the one whose tree holds the most
// of the sample. commit is "" when none beats the tag.
func sweepCommits(input, root, repoURL string, rule *srcident.Rule, tag string) (commit, note string, err error) {
	files, _, closeIn, err := treeFiles(input, root)
	if err != nil {
		return "", "", err
	}
	defer closeIn()
	local, n, err := sampleBlobs(files, root)
	if err != nil {
		return "", "", err
	}
	if n == 0 {
		return "", "no files to sweep with", nil
	}
	tags, err := upstreamsrc.ListTags(repoURL)
	if err != nil {
		return "", "", err
	}
	vt := versionedTags(rule, tags)
	at := -1
	for i, t := range vt {
		if t.Name == tag {
			at = i
		}
	}
	if at < 0 {
		return "", "", fmt.Errorf("%q is not one of the repository's release tags", tag)
	}
	if at == 0 {
		return "", "no earlier release to bound a sweep from", nil
	}
	from, to := vt[at-1].Name, vt[min(at+1, len(vt)-1)].Name
	cache, err := gitsrc.DefaultCache()
	if err != nil {
		return "", "", err
	}
	repo, err := upstreamsrc.OpenRepo(repoURL, cache)
	if err != nil {
		return "", "", err
	}
	stop := showProgress(root)
	history, err := repo.History("listing commits "+from+".."+to, from, to)
	stop()
	if err != nil {
		return "", "", fmt.Errorf("listing commits between %s and %s: %w", from, to, err)
	}
	if len(history) == 0 {
		return "", "no commits between " + from + " and " + to, nil
	}
	// The tag's own commit is scored too, as the figure to beat; it sits after the
	// commits so the search's ordering of the history is not disturbed.
	items := append(append([]string(nil), history...), vt[at].Commit)
	scores := map[int]int{}
	score := scorer(repo, local, "commits of "+tag, func(i int) upstreamsrc.Tag { return upstreamsrc.Tag{Commit: items[i]} }, scores)
	stop = showProgress(root)
	defer stop()
	b, err := searchBest(len(history), score, scores)
	if err != nil {
		return "", "", err
	}
	if err := score([]int{len(history)}); err != nil {
		return "", "", err
	}
	tagShare := float64(scores[len(history)]) / float64(len(local))
	share := float64(scores[b]) / float64(len(local))
	if share < tagShare+sweepGain {
		return "", fmt.Sprintf("no commit between %s and %s matches better than %s (%d%% of %d sampled files)", from, to, tag, int(tagShare*100), len(local)), nil
	}
	// Commits that match equally are indistinguishable by this sample; the earliest
	// is taken and the span said.
	first, last := b, b
	for i, m := range scores {
		if i < len(history) && m == scores[b] {
			first, last = min(first, i), max(last, i)
		}
	}
	date, subject := repo.Describe(history[first])
	note = fmt.Sprintf("closest upstream commit %s (%s %q): %d%% of %d sampled files identical, against %d%% at %s; %d commits between %s and %s",
		history[first][:12], date, subject, int(share*100), len(local), int(tagShare*100), tag, len(history), from, to)
	if last != first {
		note += fmt.Sprintf(" (commits %s to %s match equally)", history[first][:12], history[last][:12])
	}
	return history[first], note, nil
}

// srcdiffSweep is set by --sweep.
var srcdiffSweep bool
