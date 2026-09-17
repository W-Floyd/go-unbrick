// Package upstream fetches signed Firehose loaders from the community
// bkerler/Loaders database (a submodule of bkerler/edl). Files there are bare
// fhprg.bin programmers named <HWID>_<PKHASH>_fhprg[_variant].bin, where HWID
// decomposes to the same JTAG_ID | OEM_ID | MODEL_ID that our secboot cert parse
// yields — so an entry can be filtered by OEM_ID and keyed by JTAG_ID before a
// single byte is downloaded. This is the only network path in the tool; it exists
// so `library sync` can pull loaders instead of us maintaining a parallel DB.
package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go-unbrick/internal/catalog"
)

// VendorDir maps a catalog vendor id to its directory in bkerler/Loaders (default fallback).
var VendorDir = map[string]string{
	"motorola": "lenovo_motorola",
	"qualcomm": "qualcomm",
	"xiaomi":   "xiaomi",
}

// ResolveVendorDir resolves the directory in bkerler/Loaders for vendorID,
// preferring catalog/vendors.yaml over the default fallback map.
func ResolveVendorDir(vendorID string) string {
	if cat, err := catalog.Default(); err == nil && cat != nil {
		if d := cat.VendorDir(vendorID); d != "" && d != vendorID {
			return d
		}
	}
	return VendorDir[vendorID]
}

const (
	apiBase   = "https://api.github.com/repos/bkerler/Loaders/contents/"
	userAgent = "go-unbrick/library-sync"
)

// Entry is one loader file in the database, with its name decoded.
type Entry struct {
	Name        string // filename, e.g. "0016f0e102e80000_a51a1c2e4a5ec0f8_fhprg.bin"
	HWID        string // 16-hex, JTAG|OEM|MODEL
	JTAGID      string // uppercase 8-hex MSM id
	OEMID       string // uppercase 4-hex
	ModelID     string // uppercase 4-hex
	PKHASH      string // root cert hash prefix (16-hex)
	Variant     string // "", "peek", "edlauth", or a device tag
	Size        int
	DownloadURL string
}

// Stock reports whether this is an untouched signed loader (not a peek/edlauth
// research build) — the only kind that authenticates on a secure-boot target.
func (e Entry) Stock() bool { return e.Variant != "peek" && e.Variant != "edlauth" }

type ghContent struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Size        int    `json:"size"`
	DownloadURL string `json:"download_url"`
}

// parseName decodes a bkerler loader filename. Returns ok=false for names that
// don't match the <16hex>_<16hex>_fhprg... shape (e.g. .gitignore, __init__.py).
func parseName(name string) (Entry, bool) {
	base := strings.TrimSuffix(name, ".bin")
	parts := strings.SplitN(base, "_", 3) // hwid, pkhash, "fhprg[_variant]"
	if len(parts) < 3 || len(parts[0]) != 16 || len(parts[1]) != 16 {
		return Entry{}, false
	}
	if !isHex(parts[0]) || !isHex(parts[1]) {
		return Entry{}, false
	}
	rest := parts[2] // "fhprg" or "fhprg_peek" or "fhprg_moto_g52" ...
	variant := ""
	if v, ok := strings.CutPrefix(rest, "fhprg"); ok {
		variant = strings.TrimPrefix(v, "_")
	} else {
		return Entry{}, false
	}
	hw := strings.ToUpper(parts[0])
	return Entry{
		Name:    name,
		HWID:    hw,
		JTAGID:  hw[:8],
		OEMID:   hw[8:12],
		ModelID: hw[12:16],
		PKHASH:  strings.ToLower(parts[1]),
		Variant: variant,
	}, true
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// List returns the decoded loader entries in a vendor's directory. oemIDs, when
// non-empty, keeps only entries signed with one of those OEM_IDs (uppercase hex).
func List(ctx context.Context, vendorDir string, oemIDs []string) ([]Entry, error) {
	return listFrom(ctx, apiBase, vendorDir, oemIDs)
}

func listFrom(ctx context.Context, base, vendorDir string, oemIDs []string) ([]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+vendorDir, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	body, err := do(req)
	if err != nil {
		return nil, err
	}
	var contents []ghContent
	if err := json.Unmarshal(body, &contents); err != nil {
		return nil, fmt.Errorf("decode GitHub listing: %w", err)
	}
	want := map[string]bool{}
	for _, o := range oemIDs {
		want[strings.ToUpper(o)] = true
	}
	var out []Entry
	for _, c := range contents {
		if c.Type != "file" {
			continue
		}
		e, ok := parseName(c.Name)
		if !ok {
			continue
		}
		if len(want) > 0 && !want[e.OEMID] {
			continue
		}
		e.Size, e.DownloadURL = c.Size, c.DownloadURL
		out = append(out, e)
	}
	return out, nil
}

// Download fetches a loader's raw bytes.
func Download(ctx context.Context, e Entry) ([]byte, error) {
	if e.DownloadURL == "" {
		return nil, fmt.Errorf("entry %s has no download URL", e.Name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.DownloadURL, nil)
	if err != nil {
		return nil, err
	}
	return do(req)
}

// do runs a request with a shared UA and optional GITHUB_TOKEN auth (raises the
// unauthenticated 60/hr API rate limit), returning the body on 2xx.
func do(req *http.Request) ([]byte, error) {
	req.Header.Set("User-Agent", userAgent)
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("%s: HTTP %d: %s", req.URL, resp.StatusCode, msg)
	}
	return body, nil
}
