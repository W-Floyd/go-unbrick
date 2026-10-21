// Package osv asks the OSV database (api.osv.dev) which known vulnerabilities
// affect a project at a git tag. OSV records a vulnerability's affected versions
// as commit ranges in a repository, so a repository URL and a tag is enough to
// ask: no package-manager coordinates, which a C project does not have.
//
// What it returns is what OSV has derived ranges for, and for older versions that
// is often fewer than exist. Nothing found is not evidence of nothing affecting a
// version.
package osv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultBase is the public OSV API.
const DefaultBase = "https://api.osv.dev"

// cacheTTL is how long an answer is reused: OSV changes daily, and an
// investigation asks the same question many times.
const cacheTTL = 24 * time.Hour

// Vuln is the part of an OSV record this tool uses.
type Vuln struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Published string   `json:"published,omitempty"`
	Modified  string   `json:"modified,omitempty"`
}

// CVEs are the CVE ids the record is known by.
func (v Vuln) CVEs() []string {
	var out []string
	if strings.HasPrefix(v.ID, "CVE-") {
		out = append(out, v.ID)
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}

// Client queries OSV.
type Client struct {
	Base  string
	HTTP  *http.Client
	Cache string // directory for answers; "" for none
	now   func() time.Time
}

// New is a client of the public API caching under cache.
func New(cache string) *Client {
	return &Client{Base: DefaultBase, HTTP: &http.Client{Timeout: 30 * time.Second}, Cache: cache, now: time.Now}
}

type query struct {
	Version   string `json:"version"`
	Package   pkg    `json:"package"`
	PageToken string `json:"page_token,omitempty"`
}

type pkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type response struct {
	Vulns         []Vuln `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

type cached struct {
	Fetched time.Time `json:"fetched"`
	Vulns   []Vuln    `json:"vulns"`
}

func (c *Client) cachePath(repo, tag string) string {
	sum := sha256.Sum256([]byte(repo + "\x00" + tag))
	return filepath.Join(c.Cache, hex.EncodeToString(sum[:10])+".json")
}

// Git is the vulnerabilities OSV lists for repo at tag. repo must be spelled as
// OSV recorded it (a GitHub URL, usually), and tag as the repository names it.
func (c *Client) Git(repo, tag string) ([]Vuln, error) {
	if c.Cache != "" {
		if b, err := os.ReadFile(c.cachePath(repo, tag)); err == nil {
			var e cached
			if json.Unmarshal(b, &e) == nil && c.now().Sub(e.Fetched) < cacheTTL {
				return e.Vulns, nil
			}
		}
	}
	var all []Vuln
	token := ""
	for page := 0; page < 20; page++ { // a bound, not an expectation
		body, err := json.Marshal(query{Version: tag, Package: pkg{Name: repo, Ecosystem: "GIT"}, PageToken: token})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(c.Base, "/")+"/v1/query", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "go-unbrick")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("osv: %w", err)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("osv: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("osv: %s: %s", resp.Status, strings.TrimSpace(string(b[:min(len(b), 200)])))
		}
		var r response
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("osv: %w", err)
		}
		all = append(all, r.Vulns...)
		if token = r.NextPageToken; token == "" {
			break
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	if c.Cache != "" {
		if err := os.MkdirAll(c.Cache, 0o755); err == nil {
			if b, err := json.Marshal(cached{Fetched: c.now(), Vulns: all}); err == nil {
				os.WriteFile(c.cachePath(repo, tag), b, 0o644) //nolint:errcheck // a cache that cannot be written is not an error
			}
		}
	}
	return all, nil
}

// CVEIDs is the distinct CVE ids across the records, sorted.
func CVEIDs(vulns []Vuln) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vulns {
		for _, id := range v.CVEs() {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}
