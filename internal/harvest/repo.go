package harvest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const github = "github.com"

// repoRef is a git repo on some forge. Specs name one as "owner/name" (GitHub,
// the historical form), "host/path/to/project" (gitlab.com, a self-hosted
// GitLab, any git host), or a full https URL.
type repoRef struct {
	host, path string
}

func parseRepo(spec string) repoRef {
	s := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(spec), "https://"), "http://")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	if first, rest, ok := strings.Cut(s, "/"); ok && strings.Contains(first, ".") {
		return repoRef{host: strings.ToLower(first), path: rest}
	}
	return repoRef{host: github, path: s}
}

// String keeps GitHub repos as "owner/name", so manifests and cache paths from
// before other hosts were supported stay valid.
func (r repoRef) String() string {
	if r.host == github {
		return r.path
	}
	return r.host + "/" + r.path
}

func (r repoRef) isGitHub() bool { return r.host == github }

// isGitLab: gitlab.com or a self-hosted instance named for it.
func (r repoRef) isGitLab() bool { return strings.Contains(r.host, "gitlab") }

func (r repoRef) cloneURL() string { return "https://" + r.host + "/" + r.path + ".git" }

func (r repoRef) cacheName() string { return strings.ReplaceAll(r.String(), "/", "__") }

// blobURL links a file at HEAD in the forge's web UI.
func (r repoRef) blobURL(rel string) string {
	base := "https://" + r.host + "/" + r.path
	switch {
	case r.isGitHub():
		return base + "/blob/HEAD/" + rel
	case r.isGitLab():
		return base + "/-/blob/HEAD/" + rel
	}
	return base
}

// expandGitLabGroup lists a GitLab group's non-empty projects, subgroups
// included, through the public API (no token needed for public groups).
func (h *harvester) expandGitLabGroup(r repoRef) []string {
	var out []string
	for page := 1; ; page++ {
		u := fmt.Sprintf("https://%s/api/v4/groups/%s/projects?include_subgroups=true&per_page=100&page=%d",
			r.host, url.PathEscape(r.path), page)
		var projects []struct {
			Path      string `json:"path_with_namespace"`
			EmptyRepo bool   `json:"empty_repo"`
		}
		if err := json.Unmarshal([]byte(getText(u)), &projects); err != nil {
			if page == 1 {
				h.warnf("could not enumerate GitLab group %s", r)
			}
			break
		}
		if len(projects) == 0 {
			break
		}
		for _, p := range projects {
			if !p.EmptyRepo {
				out = append(out, r.host+"/"+p.Path)
			}
		}
		if len(projects) < 100 {
			break
		}
	}
	return out
}
