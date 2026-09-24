package harvest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/text/encoding/charmap"
)

// TemblastURL is a curated loader catalog with per-file signer and hash
// metadata. It is used as an overlay, not a download list: it names upstream
// repos, a signer per known file, and the loaders it flags as bad.
const TemblastURL = "https://www.temblast.com/ref/loaders.htm"

// TemblastEntry is one catalog row, as the JSON catalog file stores it.
type TemblastEntry struct {
	Row      int    `json:"row"`
	Signer   string `json:"signer"`
	SHA256   string `json:"sha256"`
	SHA384   string `json:"sha384"`
	FileMD5  string `json:"file_md5"`
	Type     string `json:"type"`
	Ver      string `json:"ver"`
	Site     string `json:"site"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	IsBad    bool   `json:"is_bad"`
	Repo     string `json:"repo"`
	RepoPath string `json:"repo_path"`
}

type temblastMeta struct {
	Signer string
	Type   string
	IsBad  bool
}

type cell struct {
	text             string
	rowspan, colspan int
	class            string
	links            []string
}

// parseTemblast reads the catalog table, resolving rowspan/colspan so each
// data row gets its eight columns: signer, sha256, sha384, md5, type, ver,
// site, path.
func parseTemblast(r io.Reader) []TemblastEntry {
	z := html.NewTokenizer(r)
	var rows [][]*cell
	var row []*cell
	var cur *cell
	var text strings.Builder
	inTable, inRow := false, false
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		tok := z.Token()
		switch tt {
		case html.StartTagToken:
			switch tok.Data {
			case "table":
				inTable = true
			case "tr":
				if inTable {
					inRow, row = true, nil
				}
			case "td", "th":
				if inRow {
					cur = &cell{rowspan: 1, colspan: 1}
					text.Reset()
					for _, a := range tok.Attr {
						switch a.Key {
						case "rowspan":
							cur.rowspan = atoiOr(a.Val, 1)
						case "colspan":
							cur.colspan = atoiOr(a.Val, 1)
						case "class":
							cur.class = a.Val
						}
					}
				}
			case "a":
				if cur != nil {
					for _, a := range tok.Attr {
						if a.Key == "href" {
							cur.links = append(cur.links, a.Val)
						}
					}
				}
			}
		case html.TextToken:
			if cur != nil {
				text.WriteString(tok.Data)
			}
		case html.EndTagToken:
			switch tok.Data {
			case "td", "th":
				if cur != nil {
					cur.text = strings.TrimSpace(text.String())
					row = append(row, cur)
					cur = nil
				}
			case "tr":
				if inRow && len(row) > 0 {
					rows = append(rows, row)
				}
				inRow = false
			case "table":
				inTable = false
			}
		}
	}
	if len(rows) < 2 {
		return nil
	}
	type pos struct{ r, c int }
	occupied := map[pos]*cell{}
	for r, cells := range rows[1:] { // skip the header row
		c := 0
		for _, cl := range cells {
			for occupied[pos{r, c}] != nil {
				c++
			}
			for dr := 0; dr < cl.rowspan; dr++ {
				for dc := 0; dc < cl.colspan; dc++ {
					occupied[pos{r + dr, c + dc}] = cl
				}
			}
			c += cl.colspan
		}
	}
	var out []TemblastEntry
	for r := 0; r < len(rows)-1; r++ {
		get := func(c int) *cell { return occupied[pos{r, c}] }
		txt := func(c int) string {
			if cl := get(c); cl != nil {
				return cl.text
			}
			return ""
		}
		e := TemblastEntry{Row: r + 1, Signer: txt(0), SHA256: txt(1), SHA384: txt(2), FileMD5: txt(3),
			Type: txt(4), Ver: txt(5), Site: txt(6), Path: txt(7)}
		if cl := get(7); cl != nil && len(cl.links) > 0 {
			e.URL = cl.links[0]
		}
		for c := 0; c < 8; c++ {
			if cl := get(c); cl != nil && strings.Contains(cl.class, "bad") {
				e.IsBad = true
			}
		}
		if i := strings.Index(e.URL, "github.com/"); i >= 0 {
			parts := strings.Split(e.URL[i+len("github.com/"):], "/")
			if len(parts) >= 5 && parts[2] == "blob" {
				e.Repo = parts[0] + "/" + parts[1]
				e.RepoPath, _ = url.PathUnescape(strings.Join(parts[4:], "/"))
			}
		}
		out = append(out, e)
	}
	return out
}

func atoiOr(s string, d int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return d
}

// refreshTemblast re-scrapes the catalog into path. The page is ISO-8859-1.
func (h *harvester) refreshTemblast(path string) error {
	h.logf("Fetching %s ...", TemblastURL)
	body := getText(TemblastURL)
	if body == "" {
		return fmt.Errorf("could not fetch the Temblast page")
	}
	decoded, err := charmap.ISO8859_1.NewDecoder().String(body)
	if err != nil {
		decoded = body
	}
	entries := parseTemblast(strings.NewReader(decoded))
	if len(entries) < 1000 {
		// The live table has thousands of rows; a short parse means the markup moved.
		return fmt.Errorf("parsed only %d rows, refusing to overwrite the catalog", len(entries))
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	h.logf("  wrote %d entries to %s", len(entries), path)
	return nil
}

// loadTemblast is the overlay: a 16-hex MD5 prefix (all Temblast publishes) to
// the row's signer/type/bad flag, and the GitHub repos its rows point at. The
// signer matters: without it import-loaders falls back to OEM_ID, which has no
// mapping for e.g. 0073 and files every Vivo loader under "qualcomm".
func loadTemblast(path string) (map[string]temblastMeta, map[string]bool) {
	meta, repos := map[string]temblastMeta{}, map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return meta, repos
	}
	var entries []TemblastEntry
	if json.Unmarshal(b, &entries) != nil {
		return meta, repos
	}
	for _, e := range entries {
		if md5 := strings.ToLower(e.FileMD5); md5 != "" {
			if _, ok := meta[md5]; !ok { // first row wins
				meta[md5] = temblastMeta{Signer: e.Signer, Type: e.Type, IsBad: e.IsBad}
			}
		}
		if i := strings.Index(e.URL, "github.com/"); i >= 0 {
			if parts := strings.Split(e.URL[i+len("github.com/"):], "/"); len(parts) >= 2 {
				repos[parts[0]+"/"+parts[1]] = true
			}
		}
	}
	return meta, repos
}
