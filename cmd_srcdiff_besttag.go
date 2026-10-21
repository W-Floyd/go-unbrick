package main

import (
	"fmt"
	"sort"

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
	// tagCoarse is how many tags the first pass scores, spread across all of them.
	tagCoarse = 30
	// tagConfident is the share of the sample a tag must hold to be named.
	tagConfident = 0.3
)

// versionedTag is a tag with the version its name states.
type versionedTag struct {
	upstreamsrc.Tag
	Version string
}

// sampleBlobs hashes an evenly spread sample of the tree's files into a set of git
// blob ids, which a tag holds when it has that file's content.
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

// bestTag finds the upstream tag a tree with no stated version is closest to: the
// tag whose tree holds the most of a sample of the tree's files, byte for byte. It
// scores a spread of tags first and then every tag between the best one's
// neighbours, so a project with hundreds of tags costs about a hundred trees, which
// share most of their objects.
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
	var vt []versionedTag
	for _, t := range tags {
		if v, ok := c.Rule.TagVersion(t.Name); ok {
			vt = append(vt, versionedTag{t, v})
		}
	}
	if len(vt) == 0 {
		return "", "", fmt.Errorf("%s has no tags of the shape %q", c.Rule.Repo, c.Rule.Tag)
	}
	sort.Slice(vt, func(i, j int) bool { return srcident.CompareVersions(vt[i].Version, vt[j].Version) < 0 })

	cache, err := gitsrc.DefaultCache()
	if err != nil {
		return "", "", err
	}
	repo, err := upstreamsrc.OpenRepo(c.Rule.Repo, cache)
	if err != nil {
		return "", "", err
	}
	scores := map[int]int{} // index into vt to files matched
	score := func(idx []int) error {
		var todo []int
		var fetchTags []upstreamsrc.Tag
		for _, i := range idx {
			if _, done := scores[i]; !done {
				todo = append(todo, i)
				fetchTags = append(fetchTags, vt[i].Tag)
			}
		}
		if err := repo.Fetch("searching "+c.Rule.ID+" tags", fetchTags); err != nil {
			return err
		}
		task := work.Begin("scoring "+c.Rule.ID+" tags", int64(len(todo)))
		defer task.End()
		for _, i := range todo {
			set, err := repo.Blobs(vt[i].Commit)
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

	step := max(1, len(vt)/tagCoarse)
	var coarse []int
	for i := 0; i < len(vt); i += step {
		coarse = append(coarse, i)
	}
	if coarse[len(coarse)-1] != len(vt)-1 {
		coarse = append(coarse, len(vt)-1)
	}
	if err := score(coarse); err != nil {
		return "", "", err
	}
	best := func() int {
		b := -1
		for i, m := range scores {
			if b < 0 || m > scores[b] || (m == scores[b] && i > b) {
				b = i
			}
		}
		return b
	}
	if b := best(); b >= 0 && step > 1 {
		lo, hi := max(0, b-step), min(len(vt)-1, b+step)
		var fine []int
		for i := lo; i <= hi; i++ {
			fine = append(fine, i)
		}
		if err := score(fine); err != nil {
			return "", "", err
		}
	}
	b := best()
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
