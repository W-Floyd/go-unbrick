// Package pmaports reads postmarketOS's package repository for the kernel trees
// it builds its mainline-based device kernels from, and turns them into the
// catalog's soc_trees entries: a repository, the branches of it that matter, and
// the SoCs each carries. pmaports is where that knowledge is already kept up to
// date (every kernel package names its source repository, a pinned tag or commit
// and what it is for), so the catalog is generated from it rather than typed in.
package pmaports

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
)

// Package is what an APKBUILD says that matters here.
type Package struct {
	Name     string // linux-postmarketos-mediatek-mt6768
	Category string // main, community, testing, archived, downstream
	Desc     string
	URL      string            // url=
	Vars     map[string]string // top-level literal assignments
	Source   []string          // source= entries
}

var assign = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// ParseAPKBUILD reads the top-level variable assignments of an APKBUILD: enough
// to find its source repository. Shell it does not model (command substitution,
// substring expansions) is left unexpanded, and a value that depends on it is
// treated as unknown.
func ParseAPKBUILD(name, category, text string) Package {
	p := Package{Name: name, Category: category, Vars: map[string]string{}}
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		m := assign.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		if q := val[:min(1, len(val))]; q == `"` || q == `'` {
			// A quoted value may run over several lines (source=" ... ").
			for !closed(val, q) && i+1 < len(lines) {
				i++
				val += "\n" + lines[i]
			}
			val = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(val), q), q))
		}
		p.Vars[key] = val
	}
	p.Desc, p.URL = p.Vars["pkgdesc"], p.Vars["url"]
	for _, l := range strings.Fields(p.Vars["source"]) {
		p.Source = append(p.Source, l)
	}
	return p
}

// closed says a quoted value has its closing quote.
func closed(v, q string) bool {
	v = strings.TrimSpace(v)
	return len(v) >= 2 && strings.HasSuffix(v, q)
}

var ref = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expand substitutes the package's own variables into s; what it cannot resolve
// stays as it was, with its "$".
func (p Package) expand(s string) string {
	for i := 0; i < 6; i++ {
		out := ref.ReplaceAllStringFunc(s, func(m string) string {
			sub := ref.FindStringSubmatch(m)
			name := sub[1] + sub[2]
			if name == "pkgname" {
				return p.Name
			}
			if v, ok := p.Vars[name]; ok {
				return v
			}
			return m
		})
		if out == s {
			break
		}
		s = out
	}
	return s
}

func (p Package) known(s string) string {
	if v := p.expand(s); !strings.Contains(v, "$") {
		return v
	}
	return ""
}

// archive recognises a forge's tarball URL and gives the repository it is of.
var archives = []*regexp.Regexp{
	regexp.MustCompile(`^(https://[^/]+/.+?)/-/archive/`),                               // GitLab
	regexp.MustCompile(`^(https://(?:github\.com|codeberg\.org)/[^/]+/[^/]+)/archive/`), // GitHub, Codeberg
}

var treeURL = regexp.MustCompile(`^(https://[^/]+/.+?)/(?:-/)?tree/(.+)$`)

// Source is where a package's kernel comes from.
type Source struct {
	URL    string // the repository
	Ref    string // a branch the url= names, if it does
	Pinned string // the tag or commit the package builds
}

// Repository finds the package's kernel repository. ok is false for a package
// that builds a kernel.org tarball (that is mainline itself, not a fork) or whose
// source could not be worked out.
func (p Package) Repository() (Source, bool) {
	var s Source
	for _, line := range p.Source {
		u := line
		if i := strings.Index(u, "::"); i >= 0 {
			u = u[i+2:]
		}
		u = p.known(u)
		if u == "" || strings.Contains(u, "kernel.org") {
			continue
		}
		for _, re := range archives {
			if m := re.FindStringSubmatch(u); m != nil {
				s.URL = m[1]
			}
		}
		if s.URL != "" {
			break
		}
	}
	if u := p.known(p.URL); s.URL == "" && u != "" {
		if strings.Contains(u, "kernel.org") {
			return Source{}, false
		}
		s.URL = strings.TrimSuffix(u, "/")
	}
	if s.URL == "" {
		return Source{}, false
	}
	// A url= may point at a branch: https://github.com/o/r/tree/branch.
	if m := treeURL.FindStringSubmatch(s.URL); m != nil {
		s.URL, s.Ref = m[1], m[2]
	} else if m := treeURL.FindStringSubmatch(p.known(p.URL)); m != nil && strings.HasPrefix(m[1], s.URL) {
		s.Ref = m[2]
	}
	s.Pinned = p.known(p.Vars["_commit"])
	if s.Pinned == "" {
		s.Pinned = p.known(p.Vars["_tag"])
	}
	return s, true
}

// SoCs are the compatibles a kernel package is for, from its name and
// description, by the vendor naming rules (the catalog's soc_naming):
// "linux-postmarketos-qcom-msm8916" described as "MSM8909/MSM8916/MSM8939
// devices" is three. A package for a vendor with no rule gives none.
func (p Package) SoCs(naming map[string]catalog.SoCNaming) []string {
	rest := strings.TrimPrefix(p.Name, "linux-postmarketos-")
	word, soc, _ := strings.Cut(rest, "-")
	word = strings.TrimRight(word, "0123456789") // exynos850: the vendor word is exynos
	var n *catalog.SoCNaming
	for _, cand := range naming {
		for _, w := range cand.PackageWords {
			if strings.EqualFold(w, word) {
				c := cand
				n = &c
			}
		}
	}
	if n == nil {
		return nil
	}
	re := n.PartRegexp()
	if re == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	// The name's tail, the name whole (exynos850 has its number in the vendor
	// word), and the description.
	for _, text := range []string{soc, strings.TrimPrefix(p.Name, "linux-postmarketos-"), p.Desc} {
		for _, t := range re.FindAllString(text, -1) {
			c := n.Prefix + "," + strings.ToLower(strings.ReplaceAll(t, " ", ""))
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Repos reads every postmarketos kernel package under a pmaports checkout's
// device/ directory into catalog entries, grouped by repository. skipped names
// the packages that build mainline itself or whose source could not be read.
func Repos(root, date string, naming map[string]catalog.SoCNaming) (repos []*catalog.SoCRepo, skipped []string, err error) {
	dirs, err := filepath.Glob(filepath.Join(root, "device", "*", "linux-postmarketos-*", "APKBUILD"))
	if err != nil {
		return nil, nil, err
	}
	if len(dirs) == 0 {
		return nil, nil, fmt.Errorf("no linux-postmarketos-* APKBUILDs under %s/device: not a pmaports checkout, or its device/ directories were not checked out", root)
	}
	sort.Strings(dirs)
	byURL := map[string]*catalog.SoCRepo{}
	for _, f := range dirs {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		pkgDir := filepath.Dir(f)
		p := ParseAPKBUILD(filepath.Base(pkgDir), filepath.Base(filepath.Dir(pkgDir)), string(b))
		src, ok := p.Repository()
		socs := p.SoCs(naming)
		if !ok || len(socs) == 0 {
			skipped = append(skipped, p.Name)
			continue
		}
		r := byURL[src.URL]
		if r == nil {
			r = &catalog.SoCRepo{URL: src.URL, Kind: "fork"}
			byURL[src.URL] = r
		}
		notes := p.Desc
		if p.Category == "archived" {
			notes += " (archived in pmaports: probably upstreamed or abandoned)"
		}
		var br *catalog.SoCBranch
		for i := range r.Branches {
			if r.Branches[i].Ref == src.Ref {
				br = &r.Branches[i]
			}
		}
		if br == nil {
			r.Branches = append(r.Branches, catalog.SoCBranch{Ref: src.Ref, Checked: date})
			br = &r.Branches[len(r.Branches)-1]
		}
		br.SoCs = unionSorted(br.SoCs, socs)
		br.Notes = joinUnique(br.Notes, notes, "; ")
		br.Pinned = joinUnique(br.Pinned, src.Pinned, ", ")
		br.Source = joinUnique(br.Source, "pmaports "+p.Category+"/"+p.Name, ", ")
	}
	for _, r := range byURL {
		repos = append(repos, r)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].URL < repos[j].URL })
	return repos, skipped, nil
}

func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func joinUnique(a, b, sep string) string {
	if b == "" || a == b || strings.Contains(sep+a+sep, sep+b+sep) {
		return a
	}
	if a == "" {
		return b
	}
	return a + sep + b
}
