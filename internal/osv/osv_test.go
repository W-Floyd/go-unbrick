package osv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestGitPagesAndCaches(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		var q query
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/v1/query" || q.Package.Ecosystem != "GIT" || q.Package.Name != "https://github.com/x/y" || q.Version != "v1.0" {
			t.Errorf("request %s %+v", r.URL.Path, q)
		}
		switch q.PageToken {
		case "":
			json.NewEncoder(w).Encode(response{Vulns: []Vuln{{ID: "OSV-2", Aliases: []string{"CVE-2020-0002"}}}, NextPageToken: "p2"})
		case "p2":
			json.NewEncoder(w).Encode(response{Vulns: []Vuln{{ID: "CVE-2020-0001"}, {ID: "GHSA-x", Aliases: []string{"CVE-2020-0002"}}}})
		default:
			t.Errorf("token %q", q.PageToken)
		}
	}))
	defer srv.Close()

	c := New(t.TempDir())
	c.Base = srv.URL
	vulns, err := c.Git("https://github.com/x/y", "v1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 3 || hits != 2 {
		t.Fatalf("vulns %d hits %d", len(vulns), hits)
	}
	if got := CVEIDs(vulns); !reflect.DeepEqual(got, []string{"CVE-2020-0001", "CVE-2020-0002"}) {
		t.Errorf("cves %v", got)
	}
	// Served from the cache.
	if _, err := c.Git("https://github.com/x/y", "v1.0"); err != nil || hits != 2 {
		t.Errorf("second call: hits %d err %v", hits, err)
	}
	// An old answer is asked for again.
	c.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if _, err := c.Git("https://github.com/x/y", "v1.0"); err != nil || hits != 4 {
		t.Errorf("stale call: hits %d err %v", hits, err)
	}
}

func TestGitErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer srv.Close()
	c := New("")
	c.Base = srv.URL
	if _, err := c.Git("r", "t"); err == nil {
		t.Error("a 400 was accepted")
	}
}
