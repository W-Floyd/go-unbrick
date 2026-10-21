package vendor

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// SourceComponents and SourceNotices are the facts of a Mobis open-source
// release (a GPL source drop beside a head unit's firmware): its top-level
// component trees, and the *_notice.txt each ships naming the files Mobis
// modified and the licence they carry.
var (
	SourceComponents = facts.Key[string]("source_components")
	SourceNotices    = facts.Key[string]("source_notices")
)

var (
	noticePath    = regexp.MustCompile(`(?im)^[\s*/]*File path\s*\d*\s*:`)
	noticeLicense = regexp.MustCompile(`(?im)^[\s*/]*License Name[ \t]*:[ \t]*(.+?)[ \t]*$`)
)

// NoticeSummary is what one *_notice.txt says: how many modified files it lists
// and under which licences. Files is 0 for a notice that only lists packages.
type NoticeSummary struct {
	Files    int
	Licenses []string
}

// ParseNotice reads a Mobis modification notice.
func ParseNotice(data []byte) NoticeSummary {
	var s NoticeSummary
	s.Files = len(noticePath.FindAll(data, -1))
	seen := map[string]bool{}
	for _, m := range noticeLicense.FindAllSubmatch(data, -1) {
		l := strings.TrimSpace(string(m[1]))
		if l != "" && !seen[l] {
			seen[l] = true
			s.Licenses = append(s.Licenses, l)
		}
	}
	sort.Strings(s.Licenses)
	return s
}

// sourceRelease reads a source release's shape from member names alone: the
// top-level directories with their file counts, largest first, and the
// top-level *_notice.txt members.
func sourceRelease(names map[string]bool) (comps []string, notices []string) {
	count := map[string]int{}
	for n := range names {
		top, rest, ok := strings.Cut(n, "/")
		switch {
		case ok && rest != "":
			count[top]++
		case !ok && strings.HasSuffix(n, "_notice.txt"):
			notices = append(notices, n)
		}
	}
	dirs := make([]string, 0, len(count))
	for d := range count {
		dirs = append(dirs, d)
	}
	sort.Slice(dirs, func(i, j int) bool {
		if count[dirs[i]] != count[dirs[j]] {
			return count[dirs[i]] > count[dirs[j]]
		}
		return dirs[i] < dirs[j]
	})
	for _, d := range dirs {
		comps = append(comps, fmt.Sprintf("%s (%d files)", d, count[d]))
	}
	sort.Strings(notices)
	return comps, notices
}

// learnSourceRelease folds a source release's layout and any notices into the
// bag. A firmware package is not a source tree and adds nothing.
func learnSourceRelease(pkg PackageAccess, bag *facts.Bag) {
	names := make([]string, 0, len(pkg.Names))
	for n := range pkg.Names {
		names = append(names, n)
	}
	if !srcfile.IsSourceTree(names) {
		return
	}
	comps, notices := sourceRelease(pkg.Names)
	if len(comps) == 0 {
		return
	}
	facts.Set(bag, SourceComponents, strings.Join(comps, "; "), facts.Provenance{Source: "top-level directories", Authority: facts.Attested})
	if len(notices) == 0 {
		return
	}
	var lines []string
	for _, n := range notices {
		s := ParseNotice(pkg.Read(n))
		name := strings.TrimSuffix(n, "_notice.txt")
		line := name
		if s.Files > 0 {
			line += fmt.Sprintf(": %d modified file(s)", s.Files)
		} else {
			line += ": package list"
		}
		if len(s.Licenses) > 0 {
			line += ", " + strings.Join(s.Licenses, " / ")
		}
		lines = append(lines, line)
	}
	facts.Set(bag, SourceNotices, strings.Join(lines, "; "), facts.Provenance{Source: "*_notice.txt", Authority: facts.Attested})
}

// isSourceRelease says path is an archive of source files. No driver's package
// format is one, and each CanIngest would otherwise probe every member, matching
// stray source text as a loader or scatter.
func isSourceRelease(path string) bool {
	names, _ := srcfile.Names(path)
	return srcfile.IsSourceTree(names)
}
