// Package harvest gathers Firehose loaders from bulk community sources into a
// flat directory plus manifest, which `library import-loaders` then files.
//
// Sources come in five flavours: git repos (cloned shallow; orgs expanded, and
// more found with --discover), archives outside git (Drive, MediaFire, Mega,
// AndroidFileHost, plain URLs or local files, nested archives unpacked), HTML
// indexes that link loaders directly, scraped sites whose pages link archives,
// and anything dropped into found/. Temblast is folded in as a metadata
// overlay: its catalog supplies upstream repos, a signer per known file, and
// the loaders it flags as bad.
package harvest

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Options configure a harvest. A nil list means "the default from Sources"; an
// empty, non-nil list means none. Naming repos (Repos non-nil) turns off the
// default pages, sites, orgs, Temblast repos and discovery, as the explicit
// list is then the whole run.
type Options struct {
	Sources                                Sources // catalog/harvest.yaml
	Repos, Orgs, Pages, SiteURLs, Archives []string
	NoDefaultArchives                      bool
	ArchivePassword                        string

	Out, CacheDir, FoundDir string
	TemblastCatalog         string
	RefreshCatalog          bool
	DeltaOnly               bool // emit only loaders Temblast does not list
	IncludeBad              bool // keep loaders Temblast flags as broken
	NoTemblastRepos         bool
	SkipOpaque              bool
	Structure               string // flat, by-repo, by-type
	MinSize, MaxSize        int64
	Refresh, Rescrape       bool
	Discover                bool
	Limit                   int
	DryRun                  bool

	Log io.Writer
}

// Record is one harvested loader, as manifest.json stores it.
type Record struct {
	Signer    string `json:"signer"`
	SHA256    string `json:"sha256"`
	SHA384    string `json:"sha384"`
	FileMD5   string `json:"file_md5"`
	Type      string `json:"type"`
	Ver       string `json:"ver"`
	Site      string `json:"site"`
	Path      string `json:"path"`
	URL       string `json:"url"`
	IsBad     bool   `json:"is_bad"`
	Known     bool   `json:"known"`
	Repaired  bool   `json:"repaired"`
	Repo      string `json:"repo"`
	RepoPath  string `json:"repo_path"`
	SavedFile string `json:"saved_file"`
}

// Result summarises a run.
type Result struct {
	Records                                 []Record
	Sources, Scanned                        int
	SkippedKnown, SkippedDup, SkippedOpaque int
	SkippedBad, SkippedBootImage, Annotated int
	Repaired                                int
}

type source struct {
	label, root, site string
	urlFor            func(rel string) string
}

type harvester struct {
	o        Options
	temblast map[string]temblastMeta
}

func (h *harvester) logf(format string, a ...any) { fmt.Fprintf(h.o.Log, format+"\n", a...) }
func (h *harvester) warnf(format string, a ...any) {
	fmt.Fprintf(h.o.Log, "  [warning] "+format+"\n", a...)
}
func (h *harvester) errorf(format string, a ...any) {
	fmt.Fprintf(h.o.Log, "  [error] "+format+"\n", a...)
}

// Run harvests every configured source into o.Out.
func Run(o Options) (*Result, error) {
	if o.Log == nil {
		o.Log = io.Discard
	}
	h := &harvester{o: o}
	explicitRepos := o.Repos != nil

	def := o.Sources
	repos := o.Repos
	if repos == nil {
		repos = append([]string(nil), def.Repos...)
	}
	archives := o.Archives
	if archives == nil && !o.NoDefaultArchives {
		archives = append([]string(nil), def.Archives...)
	}
	pages := o.Pages
	if pages == nil && !explicitRepos {
		pages = def.Pages
	}
	var sites []Site
	switch {
	case o.SiteURLs != nil:
		for _, u := range o.SiteURLs {
			sites = append(sites, Site{Index: u, PagePattern: SitePagePattern})
		}
	case !explicitRepos:
		sites = def.Sites
	}
	orgs := o.Orgs
	if orgs == nil && !explicitRepos {
		orgs = def.Orgs
	}

	// Anything dropped in found/ is harvested with no flag: archives at any
	// depth are extracted, loose loaders are scanned in place.
	foundLoose := false
	if fi, err := os.Stat(o.FoundDir); err == nil && fi.IsDir() && o.Archives == nil {
		var dropped []string
		loose := 0
		_ = filepath.WalkDir(o.FoundDir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if archiveExts[strings.ToLower(filepath.Ext(p))] {
				dropped = append(dropped, p)
			} else if info, err := d.Info(); err == nil && looksLikeLoader(p, info.Size(), o.MinSize, o.MaxSize) {
				loose++
			}
			return nil
		})
		sort.Strings(dropped)
		if len(dropped) > 0 {
			h.logf("%s/: %d archive(s)", o.FoundDir, len(dropped))
			archives = append(archives, dropped...)
		}
		if loose > 0 {
			h.logf("%s/: %d loose loader file(s)", o.FoundDir, loose)
			foundLoose = true
		}
	}

	for _, org := range orgs {
		orgRepos := h.expandOrg(org)
		h.logf("Org %s: %d repo(s)", org, len(orgRepos))
		repos = appendNew(repos, orgRepos...)
	}

	_, ghErr := exec.LookPath("gh")
	_, gitErr := exec.LookPath("git")
	if ghErr != nil && gitErr != nil && len(repos) > 0 {
		return nil, fmt.Errorf("neither 'gh' nor 'git' is in PATH")
	}

	if o.RefreshCatalog {
		if err := h.refreshTemblast(o.TemblastCatalog); err != nil {
			h.errorf("%v", err)
		}
	}
	var temblastRepos map[string]bool
	h.temblast, temblastRepos = loadTemblast(o.TemblastCatalog)
	if len(h.temblast) > 0 {
		named := 0
		for _, m := range h.temblast {
			if m.Signer != "" {
				named++
			}
		}
		h.logf("Temblast: %d known loaders (%d with a signer), %d upstream repo(s).", len(h.temblast), named, len(temblastRepos))
	}
	if !o.NoTemblastRepos && !explicitRepos {
		repos = appendNew(repos, uniqSorted(keys(temblastRepos))...)
	}

	if o.Discover && !explicitRepos {
		h.logf("\nDiscovering loader repos on GitHub...")
		known := map[string]bool{}
		for _, r := range repos {
			known[r] = true
		}
		repos = appendNew(repos, h.discoverRepos(known)...)
	}

	if len(sites) > 0 {
		h.logf("\nScraping %d site(s)...", len(sites))
		for _, s := range sites {
			archives = appendNew(archives, h.scrapeSite(s)...)
		}
	}

	var sources []source
	h.logf("\nCloning %d repo(s)...", len(repos))
	cloned := map[string]bool{}
	for _, spec := range repos {
		r := parseRepo(spec)
		if cloned[r.String()] {
			continue
		}
		cloned[r.String()] = true
		if root := h.cloneRepo(r); root != "" {
			sources = append(sources, source{r.String(), root, "G", r.blobURL})
		}
	}
	if len(archives) > 0 {
		h.logf("\nFetching %d archive(s)...", len(archives))
		for _, spec := range archives {
			if root := h.fetchArchive(spec); root != "" {
				s := spec
				sources = append(sources, source{spec, root, "Z", func(string) string { return s }})
			}
		}
	}
	if len(pages) > 0 {
		h.logf("\nScraping %d index page(s)...", len(pages))
		for _, u := range pages {
			if root := h.fetchPage(u); root != "" {
				base := u
				sources = append(sources, source{u, root, "W", func(rel string) string {
					return strings.TrimRight(base, "/") + "/" + rel
				}})
			}
		}
	}
	if foundLoose {
		fd := o.FoundDir
		sources = append(sources, source{fd, fd, "F", func(rel string) string { return fd + "/" + rel }})
	}

	res := h.scan(sources)
	if len(res.Records) > 0 && !o.DryRun {
		if err := writeManifest(o.Out, res.Records); err != nil {
			return res, err
		}
		h.logf("\nWrote %s and %s", filepath.Join(o.Out, "manifest.json"), filepath.Join(o.Out, "manifest.csv"))
	}
	return res, nil
}

var reUnsafeName = regexp.MustCompile(`[\\/:*?"<>|]`)

func sanitize(name string) string {
	s := strings.TrimSpace(reUnsafeName.ReplaceAllString(name, "_"))
	if s == "" {
		return "unknown"
	}
	return s
}

func (h *harvester) scan(sources []source) *Result {
	o := h.o
	res := &Result{Sources: len(sources)}
	seen := map[string]bool{}
	for _, src := range sources {
		if _, err := os.Stat(src.root); err != nil {
			continue
		}
		// Blankflash donors hide the programmer inside a SINGLE_N_LONELY
		// container the flat scan skips; carve it out first.
		if n := expandSingleimages(src.root); n > 0 {
			h.logf("  [singleimage] %s: carved %d programmer(s)", src.label, n)
		}
		var paths []string
		_ = filepath.WalkDir(src.root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if info, err := d.Info(); err == nil && looksLikeLoader(p, info.Size(), o.MinSize, o.MaxSize) {
				paths = append(paths, p)
			}
			return nil
		})
		sort.Strings(paths)
		for _, p := range paths {
			if o.Limit > 0 && len(res.Records) >= o.Limit {
				return res
			}
			res.Scanned++
			md5hex, shahex, err := hashFile(p)
			if err != nil {
				continue
			}
			row, known := h.temblast[md5hex[:16]]
			if known && row.IsBad && !o.IncludeBad {
				res.SkippedBad++
				continue
			}
			if known && o.DeltaOnly {
				res.SkippedKnown++
				continue
			}
			if seen[md5hex] {
				res.SkippedDup++
				continue
			}
			ltype := classifyImage(p)
			if o.SkipOpaque && ltype == "OPAQUE" {
				res.SkippedOpaque++
				continue
			}
			// A signed image is only a loader if it is a programmer: per-device
			// firmware dumps ship the whole boot chain (Alephgsm/SAM alone had
			// 1638 boot images against 95 real loaders).
			if (ltype == "ELF32" || ltype == "ELF64" || ltype == "MBN") && !isFirehoseLoader(p) {
				res.SkippedBootImage++
				continue
			}
			seen[md5hex] = true

			rel, _ := filepath.Rel(src.root, p)
			rel = filepath.ToSlash(rel)
			destName := shahex[:16] + "_" + md5hex[:16] + "_" + sanitize(filepath.Base(p))
			dest := filepath.Join(o.Out, destName)
			switch o.Structure {
			case "by-repo":
				dest = filepath.Join(o.Out, sanitize(strings.ReplaceAll(src.label, "/", "__")), destName)
			case "by-type":
				dest = filepath.Join(o.Out, sanitize(ltype), destName)
			}
			head, _ := readHead(p, 8)
			off, fixed, repaired := repairMagic(head)
			if repaired {
				res.Repaired++
			}
			if known && row.Signer != "" {
				res.Annotated++
			}
			note := ""
			if repaired {
				note = "  [magic repaired]"
			}
			h.logf("  [%d] %s:%s -> %s%s", len(res.Records)+1, src.label, rel, filepath.Base(dest), note)
			if !o.DryRun {
				if err := copyFile(p, dest); err != nil {
					h.errorf("copying %s: %v", p, err)
					continue
				}
				if repaired {
					if f, err := os.OpenFile(dest, os.O_WRONLY, 0); err == nil {
						_, _ = f.WriteAt([]byte{fixed}, int64(off))
						f.Close()
					}
				}
			}
			saved, _ := filepath.Rel(o.Out, dest)
			res.Records = append(res.Records, Record{
				// Sources Temblast does not cover carry no signer; import-loaders
				// then falls back to the image's own OEM_ID.
				Signer: row.Signer, SHA256: shahex[:16], FileMD5: md5hex[:16], Type: ltype,
				Site: src.site, Path: rel, URL: src.urlFor(rel), IsBad: known && row.IsBad,
				Known: known, Repaired: repaired, Repo: src.label, RepoPath: rel,
				SavedFile: filepath.ToSlash(saved),
			})
		}
	}
	return res
}

func hashFile(p string) (string, string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	m, s := md5.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, s), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if fi, err := in.Stat(); err == nil {
		_ = os.Chtimes(dst, fi.ModTime(), fi.ModTime())
	}
	return nil
}

func writeManifest(out string, recs []Record) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), b, 0o644); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(out, "manifest.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.UseCRLF = true // as Python's csv module writes it
	_ = w.Write([]string{"signer", "sha256", "sha384", "file_md5", "type", "ver", "site", "path", "url",
		"is_bad", "known", "repaired", "repo", "repo_path", "saved_file"})
	for _, r := range recs {
		_ = w.Write([]string{r.Signer, r.SHA256, r.SHA384, r.FileMD5, r.Type, r.Ver, r.Site, r.Path, r.URL,
			pyBool(r.IsBad), pyBool(r.Known), pyBool(r.Repaired), r.Repo, r.RepoPath, r.SavedFile})
	}
	w.Flush()
	return w.Error()
}

// pyBool keeps manifest.csv byte-compatible with the Python harvester's.
func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func appendNew(list []string, add ...string) []string {
	have := map[string]bool{}
	for _, s := range list {
		have[s] = true
	}
	for _, s := range add {
		if !have[s] {
			have[s] = true
			list = append(list, s)
		}
	}
	return list
}
