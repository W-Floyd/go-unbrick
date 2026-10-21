package catalog

import "testing"

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
