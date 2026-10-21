// Package srcident finds which upstream projects a vendor's source release is made
// of, from what the release itself says: directory names that carry a project and
// version (gstreamer-1.16.3_r0), version files inside the tree (Makefile,
// openssl.version, configure.in), and notices that pin a commit (via
// kenlm_5bf7b46.patch). Which projects exist, where their upstreams are and how a
// version becomes a tag is data (catalog/upstreams.yaml), not code.
package srcident

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// VersionSource says how to read a project's version from a file in its tree.
type VersionSource struct {
	File    string `yaml:"file"`    // relative to the project's root
	Pattern string `yaml:"pattern"` // a regular expression; (?s) lets it span lines
	Format  string `yaml:"format"`  // how the capture groups make the version: "{1}.{2}"; default "{1}"
}

// Rule is one upstream project.
type Rule struct {
	ID    string   `yaml:"id"`
	Names []string `yaml:"names"` // directory or recipe names that mean this project; the id counts too
	// AOSP is the project's path in the Android tree ("external/e2fsprogs"): a
	// release names such a project by dotting it ("platform.external.e2fsprogs").
	AOSP    string          `yaml:"aosp,omitempty"`
	Repo    string          `yaml:"repo"`
	Tag     string          `yaml:"tag,omitempty"` // {version} or {version_} (dots as underscores); default {version}
	Version []VersionSource `yaml:"version,omitempty"`
	// Heavy marks an upstream too big to fetch for a routine comparison.
	Heavy bool `yaml:"heavy,omitempty"`
	// Strict reports a match only when a version is found: for a name common
	// enough (linux) that a directory of it is usually part of something else.
	Strict bool   `yaml:"strict,omitempty"`
	Notes  string `yaml:"notes,omitempty"`
}

// Candidate is a directory of the release identified with an upstream project.
type Candidate struct {
	Root     string // the project's directory in the release
	Rule     *Rule
	Version  string // "" when the release does not say
	Ref      string // what to fetch upstream: a tag from Version, or a pinned commit; "" if neither is known
	Evidence string // how it was identified
}

var (
	nameVersion = regexp.MustCompile(`^(.+?)[-_ ]v?(\d+(?:\.\d+)+[a-z]?)(?:[-_]r\d+)?$`)
	pinned      = regexp.MustCompile(`\bvia\s+([A-Za-z0-9_.+-]+?)_([0-9a-f]{7,40})\.patch`)
)

// norm is a name with case and punctuation removed, for comparing spellings
// (gst-plugins-bad, gst_plugins_bad).
func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// splitName reads a directory name that carries a version.
func splitName(base string) (stem, version string) {
	if m := nameVersion.FindStringSubmatch(base); m != nil {
		return m[1], m[2]
	}
	return base, ""
}

// matches says whether a directory name is the rule's project.
func (r *Rule) matches(base string) bool {
	stem, _ := splitName(base)
	want := map[string]bool{norm(r.ID): true}
	for _, n := range r.Names {
		want[norm(n)] = true
	}
	for _, cand := range []string{stem, strings.TrimSuffix(strings.TrimSuffix(stem, "-src"), ".src")} {
		if want[norm(cand)] {
			return true
		}
	}
	if r.AOSP != "" {
		dotted := strings.ReplaceAll(base, ".", "/")
		return dotted == r.AOSP || strings.HasSuffix(dotted, "/"+r.AOSP)
	}
	return false
}

// readVersion applies a rule's version sources to the files of root.
func (r *Rule) readVersion(root string, read func(string) []byte) (string, string) {
	for _, vs := range r.Version {
		data := read(root + "/" + vs.File)
		if data == nil {
			continue
		}
		re, err := regexp.Compile(vs.Pattern)
		if err != nil {
			continue
		}
		m := re.FindSubmatch(data)
		if m == nil {
			continue
		}
		format := vs.Format
		if format == "" {
			format = "{1}"
		}
		v := format
		for i := len(m) - 1; i >= 1; i-- {
			v = strings.ReplaceAll(v, fmt.Sprintf("{%d}", i), string(m[i]))
		}
		return strings.TrimSpace(v), vs.File
	}
	return "", ""
}

// TagFor is the upstream ref a version has under the rule's tag template.
func (r *Rule) TagFor(version string) string {
	if version == "" {
		return ""
	}
	t := r.Tag
	if t == "" {
		t = "{version}"
	}
	t = strings.ReplaceAll(t, "{version_}", strings.ReplaceAll(version, ".", "_"))
	return strings.ReplaceAll(t, "{version}", version)
}

// Find identifies the projects in a release. names are the member paths; read gives
// a member's content (nil if it has none).
func Find(names []string, read func(string) []byte, rules []Rule) []Candidate {
	files := map[string]int{}                // directory to the files under it
	children := map[string]map[string]bool{} // directory to its directory children
	direct := map[string]int{}               // directory to the files directly in it
	all := map[string]bool{}
	for _, n := range names {
		all[n] = true
		parts := strings.Split(n, "/")
		for i := 1; i < len(parts); i++ {
			dir := strings.Join(parts[:i], "/")
			files[dir]++
			if i < len(parts)-1 {
				if children[dir] == nil {
					children[dir] = map[string]bool{}
				}
				children[dir][strings.Join(parts[:i+1], "/")] = true
			}
		}
		if i := strings.LastIndexByte(n, '/'); i >= 0 {
			direct[n[:i]]++
		}
	}
	dirs := make([]string, 0, len(files))
	for d := range files {
		if strings.Count(d, "/") <= 5 && files[d] >= 3 {
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)

	// descend steps into a lone subdirectory a snapshot wraps its tree in ("2",
	// "gstreamer-1.16.3").
	descend := func(d string) string {
		for i := 0; i < 3 && direct[d] == 0 && len(children[d]) == 1; i++ {
			for c := range children[d] {
				d = c
			}
		}
		return d
	}

	var out []Candidate
	for ri := range rules {
		r := &rules[ri]
		var roots []string
		for _, d := range dirs {
			base := d[strings.LastIndexByte(d, '/')+1:]
			if !r.matches(base) {
				continue
			}
			outer := false
			for _, o := range roots {
				if strings.HasPrefix(d, o+"/") {
					outer = true
				}
			}
			if !outer {
				roots = append(roots, d)
			}
		}
		for _, d := range roots {
			base := d[strings.LastIndexByte(d, '/')+1:]
			root := descend(d)
			c := Candidate{Root: root, Rule: r}
			if _, v := splitName(base); v != "" {
				c.Version, c.Evidence = v, "directory name "+base
			} else if v, file := r.readVersion(root, read); v != "" {
				c.Version, c.Evidence = v, file
			} else {
				c.Evidence = "directory name " + base
			}
			c.Ref = r.TagFor(c.Version)
			if r.Strict && c.Version == "" {
				continue
			}
			out = append(out, c)
		}
	}
	out = outermost(out)
	pinCommits(out, names, read)
	sort.Slice(out, func(i, j int) bool { return out[i].Root < out[j].Root })
	return out
}

// outermost drops a candidate that lies inside another project's root: a
// directory called "linux" under u-boot's include/ is U-Boot's, not the kernel.
func outermost(cands []Candidate) []Candidate {
	var out []Candidate
	for i, c := range cands {
		inside := false
		for j, o := range cands {
			if i != j && o.Rule != c.Rule && strings.HasPrefix(c.Root, o.Root+"/") {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, c)
		}
	}
	return out
}

// pinCommits lets a notice that names the commit a project was taken from ("via
// kenlm_5bf7b46.patch") say which one it is, overriding a tag.
func pinCommits(cands []Candidate, names []string, read func(string) []byte) {
	for _, n := range names {
		if strings.Contains(n, "/") || !strings.HasSuffix(n, ".txt") {
			continue
		}
		data := read(n)
		if len(data) == 0 || len(data) > 1<<20 {
			continue
		}
		for _, m := range pinned.FindAllSubmatch(data, -1) {
			project := norm(string(m[1]))
			for i := range cands {
				c := &cands[i]
				if project == norm(c.Rule.ID) || containsNorm(c.Rule.Names, project) {
					c.Ref, c.Evidence = string(m[2]), "pinned by notice "+strings.TrimSuffix(n, ".txt")
				}
			}
		}
	}
}

func containsNorm(names []string, n string) bool {
	for _, s := range names {
		if norm(s) == n {
			return true
		}
	}
	return false
}

// TagVersion is the version a tag names under the rule's tag template ("v1.42.9" is
// 1.42.9 for "v{version}"); ok is false for a tag of some other shape (a
// release candidate, a branch-point marker).
func (r *Rule) TagVersion(tag string) (string, bool) {
	t := r.Tag
	if t == "" {
		t = "{version}"
	}
	const ver = `(\d+(?:\.\d+)*[a-z]?)`
	pat := regexp.QuoteMeta(t)
	pat = strings.ReplaceAll(pat, regexp.QuoteMeta("{version_}"), `(\d+(?:_\d+)*[a-z]?)`)
	pat = strings.ReplaceAll(pat, regexp.QuoteMeta("{version}"), ver)
	re, err := regexp.Compile("^" + pat + "$")
	if err != nil {
		return "", false
	}
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return "", false
	}
	return strings.ReplaceAll(m[1], "_", "."), true
}

// CompareVersions orders two dotted versions, numerically by part (1.9 < 1.10),
// with a trailing letter (1.0.1e) after the number it follows.
func CompareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y [2]int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		for k := range x {
			if x[k] != y[k] {
				if x[k] < y[k] {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

var versionPart = regexp.MustCompile(`(\d+)([a-z]?)`)

// versionParts reads each dotted part as its number and its trailing letter.
func versionParts(v string) [][2]int {
	var out [][2]int
	for _, m := range versionPart.FindAllStringSubmatch(v, -1) {
		n := 0
		fmt.Sscanf(m[1], "%d", &n)
		letter := 0
		if m[2] != "" {
			letter = int(m[2][0]-'a') + 1
		}
		out = append(out, [2]int{n, letter})
	}
	return out
}
