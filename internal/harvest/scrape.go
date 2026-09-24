package harvest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Site is a scraper whose pages link off-site archives: exactly one of Index
// (an index page whose PagePattern links are device pages), WP (a WordPress
// category or search) or AFH (an AndroidFileHost search) is set.
type Site struct {
	Index       string `yaml:"index,omitempty"`
	PagePattern string `yaml:"page_pattern,omitempty"`
	WP          string `yaml:"wp,omitempty"`
	Category    string `yaml:"category,omitempty"`
	Search      string `yaml:"search,omitempty"`
	AFH         string `yaml:"afh,omitempty"`
}

// SitePagePattern is what a bare --site URL follows: same-page links that look
// like device or loader pages.
const SitePagePattern = `(blankflash|firehose|loader|programmer)`

// Bounds and pacing: be polite, and never wander into an unbounded tree.
const (
	maxIndexDirs = 64
	indexDelay   = 300 * time.Millisecond
	scrapeTTL    = 24 * time.Hour
	scrapeDelay  = time.Second
	afhMaxPages  = 40 // ~15 results/page
)

var (
	reHref     = regexp.MustCompile(`href="([^"]+)"`)
	reHostLink = regexp.MustCompile(`https://drive\.google\.com/file/d/[A-Za-z0-9_-]+` +
		`|https://mega\.nz/[^\s"'<>]+|https://www\.mediafire\.com/[^\s"'<>]+`)
	// A firehose search on a firmware site also returns multi-GB stock-ROM posts.
	reNonLoaderPost = regexp.MustCompile(`(?i)stock rom|flash file|firmware|full rom`)
	reAFHFid        = regexp.MustCompile(`fid=([0-9]{15,})`)
)

// fetchPage downloads every loader-looking file linked from an HTML index,
// recursing into subdirectory links under the root. Walking beats a file list:
// it found Oplus/ and Oplus_Exploit/, which Temblast's own crawl missed.
func (h *harvester) fetchPage(root string) string {
	dir := filepath.Join(h.o.CacheDir, "pages", reStemJunk.ReplaceAllString(root, "_"))
	if _, err := os.Stat(dir); err == nil && !h.o.Refresh {
		h.logf("  [cache] %s", root)
		return dir
	}
	if h.o.DryRun {
		return dir
	}
	_ = os.MkdirAll(dir, 0o755)
	seen := map[string]bool{}
	queue := []string{root}
	found := 0
	for len(queue) > 0 && len(seen) < maxIndexDirs {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		body := getText(cur)
		if body == "" {
			h.warnf("failed index %s", cur)
			continue
		}
		base, _ := url.Parse(cur)
		for _, m := range reHref.FindAllStringSubmatch(body, -1) {
			href := m[1]
			if href == ".." || href == "." || strings.HasPrefix(href, "//") {
				continue
			}
			ref, err := url.Parse(href)
			if err != nil {
				continue
			}
			full := base.ResolveReference(ref).String()
			if !strings.HasPrefix(full, root) {
				continue
			}
			if strings.HasSuffix(full, "/") {
				if !seen[full] {
					queue = append(queue, full)
				}
				continue
			}
			pu, _ := url.Parse(full)
			if pu == nil || !loaderExts[strings.ToLower(path.Ext(pu.Path))] {
				continue
			}
			// Mirror the remote layout so same-named files in sibling dirs don't collide.
			rel, _ := url.PathUnescape(strings.TrimPrefix(full[len(root):], "/"))
			target := filepath.Join(dir, filepath.FromSlash(rel))
			if !strings.HasPrefix(target, dir+string(filepath.Separator)) {
				continue
			}
			if _, err := os.Stat(target); err == nil {
				continue
			}
			if err := download(full, target); err != nil {
				h.warnf("failed %s", full)
			} else {
				found++
			}
		}
		time.Sleep(indexDelay)
	}
	h.logf("  [page] %s: walked %d dir(s), fetched %d loader(s)", root, len(seen), found)
	return dir
}

func (s Site) key() string {
	switch {
	case s.AFH != "":
		return "androidfilehost#" + s.AFH
	case s.Search != "":
		return s.WP + "#search=" + s.Search
	case s.WP != "":
		return s.WP + "#cat=" + s.Category
	}
	return s.Index
}

// scrapeSite collects a site's off-site archive URLs. The link list is cached
// per site for scrapeTTL: the per-post fan-out is the slow, rude part, not the
// separately cached downloads.
func (h *harvester) scrapeSite(s Site) []string {
	key := s.key()
	cachefile := filepath.Join(h.o.CacheDir, "scrape_cache", reStemJunk.ReplaceAllString(key, "_")+".json")
	var cached struct {
		FetchedAt float64  `json:"fetched_at"`
		Key       string   `json:"key"`
		Links     []string `json:"links"`
	}
	if age, ok := fresh(cachefile); ok && !h.o.Rescrape {
		if b, err := os.ReadFile(cachefile); err == nil && json.Unmarshal(b, &cached) == nil {
			h.logf("  [cache] %s: %d link(s), scraped %dh ago", key, len(cached.Links), int(age.Hours()))
			return cached.Links
		}
	}
	if h.o.DryRun {
		return nil
	}
	var links []string
	switch {
	case s.AFH != "":
		links = h.scrapeAFH(s.AFH)
	case s.Search != "":
		links = h.scrapeWPSearch(strings.TrimRight(s.WP, "/"), s.Search)
	case s.WP != "":
		links = h.scrapeWPCategory(strings.TrimRight(s.WP, "/"), s.Category)
	default:
		links = h.scrapeHTMLIndex(s.Index, s.PagePattern)
	}
	links = uniqSorted(links)
	cached.FetchedAt, cached.Key, cached.Links = float64(time.Now().Unix()), key, links
	writeJSONFile(cachefile, cached)
	return links
}

// scrapeHTMLIndex: index page → per-device pages (by pattern) → archive links.
func (h *harvester) scrapeHTMLIndex(index, pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		h.warnf("bad page pattern %q: %v", pattern, err)
		return nil
	}
	body := getText(index)
	if body == "" {
		h.warnf("failed to fetch index %s", index)
		return nil
	}
	base, _ := url.Parse(index)
	pages := map[string]bool{}
	for _, m := range reHref.FindAllStringSubmatch(body, -1) {
		if re.MatchString(m[1]) {
			if ref, err := url.Parse(m[1]); err == nil {
				pages[base.ResolveReference(ref).String()] = true
			}
		}
	}
	var links []string
	for _, p := range uniqSorted(keys(pages)) {
		if t := getText(p); t != "" {
			links = append(links, reHostLink.FindAllString(t, -1)...)
		}
		time.Sleep(scrapeDelay)
	}
	h.logf("  [scrape] %s: %d page(s) -> %d link(s)", index, len(pages), len(uniqSorted(links)))
	return links
}

type wpPost struct {
	ID    int `json:"id"`
	Title struct {
		Rendered string `json:"rendered"`
	} `json:"title"`
	Content struct {
		Rendered string `json:"rendered"`
	} `json:"content"`
}

// scrapeWPCategory enumerates a WordPress category through the REST API and
// pulls each post's archive link.
func (h *harvester) scrapeWPCategory(base, slug string) []string {
	var cats []struct {
		ID int `json:"id"`
	}
	if json.Unmarshal([]byte(getText(base+"/wp-json/wp/v2/categories?slug="+url.QueryEscape(slug))), &cats) != nil || len(cats) == 0 {
		h.warnf("no WP category %q at %s", slug, base)
		return nil
	}
	var links []string
	for page := 1; ; page++ {
		var posts []wpPost
		u := fmt.Sprintf("%s/wp-json/wp/v2/posts?categories=%d&per_page=100&page=%d&_fields=content", base, cats[0].ID, page)
		if json.Unmarshal([]byte(getText(u)), &posts) != nil || len(posts) == 0 {
			break
		}
		for _, p := range posts {
			links = append(links, reHostLink.FindAllString(p.Content.Rendered, -1)...)
		}
		if len(posts) < 100 {
			break
		}
		time.Sleep(scrapeDelay)
	}
	h.logf("  [scrape] %s [%s]: %d link(s)", base, slug, len(uniqSorted(links)))
	return links
}

// scrapeWPSearch is the WordPress REST search: matching post ids, then their
// content in batches, skipping stock-firmware posts.
func (h *harvester) scrapeWPSearch(base, query string) []string {
	var ids []string
	for page := 1; ; page++ {
		var rows []struct {
			ID int `json:"id"`
		}
		u := fmt.Sprintf("%s/wp-json/wp/v2/search?search=%s&per_page=100&page=%d&_fields=id", base, url.QueryEscape(query), page)
		if json.Unmarshal([]byte(getText(u)), &rows) != nil || len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if r.ID != 0 {
				ids = append(ids, fmt.Sprint(r.ID))
			}
		}
		if len(rows) < 100 {
			break
		}
		time.Sleep(scrapeDelay)
	}
	var links []string
	skipped := 0
	for i := 0; i < len(ids); i += 100 {
		batch := strings.Join(ids[i:min(i+100, len(ids))], ",")
		var posts []wpPost
		u := fmt.Sprintf("%s/wp-json/wp/v2/posts?include=%s&per_page=100&_fields=title,content", base, batch)
		if json.Unmarshal([]byte(getText(u)), &posts) != nil {
			continue
		}
		for _, p := range posts {
			if reNonLoaderPost.MatchString(p.Title.Rendered) {
				skipped++
				continue
			}
			links = append(links, reHostLink.FindAllString(p.Content.Rendered, -1)...)
		}
		time.Sleep(scrapeDelay)
	}
	h.logf("  [scrape] %s [?%s]: %d post(s), %d firmware skipped -> %d link(s)",
		base, query, len(ids), skipped, len(uniqSorted(links)))
	return links
}

// scrapeAFH paginates an AndroidFileHost search into ?fid= URLs, resolved to a
// mirror at download time.
func (h *harvester) scrapeAFH(query string) []string {
	fids := map[string]bool{}
	for page := 1; page <= afhMaxPages; page++ {
		body := getText(fmt.Sprintf("https://androidfilehost.com/?w=search&s=%s&type=files&page=%d", url.QueryEscape(query), page))
		found := reAFHFid.FindAllStringSubmatch(body, -1)
		if len(found) == 0 {
			break
		}
		for _, m := range found {
			fids["https://androidfilehost.com/?fid="+m[1]] = true
		}
		time.Sleep(scrapeDelay)
	}
	h.logf("  [scrape] androidfilehost [?%s]: %d file(s)", query, len(fids))
	return keys(fids)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func uniqSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	out := keys(set)
	sort.Strings(out)
	return out
}
