package catalog

import (
	"os"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/srcident"
	"github.com/W-Floyd/go-unbrick/internal/upstreamsrc"
)

func TestShippedUpstreams(t *testing.T) {
	c, err := Load("../../catalog")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, u := range c.Upstreams() {
		if seen[u.ID] {
			t.Errorf("duplicate upstream %s", u.ID)
		}
		seen[u.ID] = true
		if u.Repo == "" {
			t.Errorf("%s: no repo", u.ID)
		}
	}
	for _, want := range []string{"u-boot", "openssl", "glib", "kenlm"} {
		if !seen[want] {
			t.Errorf("missing %s", want)
		}
	}
}

// TestUpstreamTagShapes checks each rule's tag template against its real remote:
// at least one tag must read as a release under it. It needs the network, so it
// runs only when UNBRICK_NETWORK_TESTS is set.
func TestUpstreamTagShapes(t *testing.T) {
	if os.Getenv("UNBRICK_NETWORK_TESTS") == "" {
		t.Skip("set UNBRICK_NETWORK_TESTS=1 to check tag templates against the remotes")
	}
	c, err := Load("../../catalog")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range c.Upstreams() {
		u := u
		if u.ID == "kenlm" {
			continue // pinned to a commit by its notice; the repository has no release tags
		}
		t.Run(u.ID, func(t *testing.T) {
			tags, err := upstreamsrc.ListTags(u.Repo)
			if err != nil {
				t.Skipf("remote not reachable: %v", err)
			}
			n, last := 0, ""
			for _, tag := range tags {
				if v, ok := u.TagVersion(tag.Name); ok {
					n++
					if last == "" || srcident.CompareVersions(v, last) > 0 {
						last = v
					}
				}
			}
			if n == 0 {
				t.Errorf("no tag of %s reads as a release under %q (%d tags)", u.Repo, u.Tag, len(tags))
			} else {
				t.Logf("%d release tags, newest %s", n, last)
			}
		})
	}
}
