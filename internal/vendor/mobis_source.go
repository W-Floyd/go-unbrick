package vendor

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// Facts of a Mobis open-source release (a GPL source drop beside a head unit's
// firmware): its component trees, the product it is for, when it was last
// touched, and what its notices say Mobis changed.
var (
	SourceComponents = facts.Key[string]("source_components")
	SourceNotices    = facts.Key[string]("source_notices")
	// SourceProduct is the product and platform the tree names encode
	// ("0109_AVNT5W_DaudioKK_kernel.lk": product AVNT5W, platform DaudioKK).
	SourceProduct = facts.Key[string]("source_product")
	// SourceDates is the span of dated modifications the notices record.
	SourceDates = facts.Key[string]("source_dates")
	// SourceSecurity is the modifications whose title or files concern signing,
	// verification, keys, locks or update paths: what changed in the trust chain.
	SourceSecurity = facts.Key[string]("source_security")
)

var (
	noticePath    = regexp.MustCompile(`(?im)^[\s*/]*File path\s*\d*\s*:`)
	noticeLicense = regexp.MustCompile(`(?im)^[\s*/]*License Name[ \t]*:[ \t]*(.+?)[ \t]*$`)
	noticeModInfo = regexp.MustCompile(`(?im)^[\s*/]*Modification Information[^:\n]*:[ \t]*(.+?)[ \t]*$`)
	noticeDateRe  = regexp.MustCompile(`(?i)^\s*Date:\s*(.+?)\s*$`)
	dateYMD       = regexp.MustCompile(`(\d{4})\s*[-./]\s*(\d{1,2})\s*[-./]\s*(\d{1,2})`)
	dateDMY       = regexp.MustCompile(`(\d{1,2})/(\d{1,2})/(\d{4})`)
	dateYM        = regexp.MustCompile(`^\s*(\d{4})-(\d{2})\s*$`)
	dateGit       = regexp.MustCompile(`[A-Z][a-z]{2} ([A-Z][a-z]{2}) +(\d{1,2}) \d{2}:\d{2}:\d{2} (\d{4})( [+-]\d{4})?`)
	// security picks out changes to the trust chain by what they are named for.
	// Bounded by non-alphanumerics, not \b: "_" joins words in identifiers
	// (check_rsa_image).
	security = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(rsa|verif[a-z]*|signature|signed|signing|secure ?boot|encrypt[a-z]*|decrypt[a-z]*|keys?|unlock[a-z]*|locked?|fastboot|rollback|anti-?rollback|tsbm|hash|certificate)(?:[^a-z0-9]|$)`)
	dirName  = regexp.MustCompile(`^(\d{4})_([A-Za-z0-9]+)_([A-Za-z0-9]+)_.+$`)
	noticeTx = regexp.MustCompile(`^\d{4}_.+\.txt$`)
)

// NoticeMod is one modification a notice records.
type NoticeMod struct {
	Date  string // yyyy-mm-dd (or yyyy-mm), "" if the notice gives none
	Title string
	Files []string
}

// NoticeSummary is what one notice says: the files and modifications it lists,
// their dates, and the licences they carry. Files is 0 for a notice that only
// lists packages.
type NoticeSummary struct {
	Files    int
	Licenses []string
	Mods     []NoticeMod
}

// normDate reads the date formats the notices use (2022.05.23, 2023. 07. 20,
// 2020-12-28, 28/11/2024, 2017-10) as yyyy-mm-dd; "" if there is none.
func normDate(s string) string {
	if m := dateYMD.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("%s-%02s-%02s", m[1], m[2], m[3])
	}
	if m := dateDMY.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("%s-%02s-%02s", m[3], m[2], m[1])
	}
	if m := dateYM.FindStringSubmatch(s); m != nil {
		return m[1] + "-" + m[2]
	}
	if m := dateGit.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("%s-%02d-%02s", m[3], strings.Index("JanFebMarAprMayJunJulAugSepOctNovDec", m[1])/3+1, m[2])
	}
	return ""
}

// cleanTitle is a modification's subject alone: the commit date git appended and
// the issue-detail text some titles carry after " - " are cut.
func cleanTitle(s string) string {
	s = dateGit.ReplaceAllString(s, "")
	s = strings.TrimSpace(dateYMD.ReplaceAllString(s, ""))
	if i := strings.Index(s, " - "); i > 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimRight(s, " +0123456789"), ","))
	return strings.TrimSpace(s)
}

// duplicate says a title is a merge or pull-request record of a commit listed on
// its own.
func duplicate(title string) bool {
	return strings.HasPrefix(title, "Pull request #") || strings.HasPrefix(title, "Merge ")
}

// ParseNotice reads a Mobis modification notice, in either of its two layouts: a
// header of "File path"/"License Name"/"Modification Information & date" lines,
// or blocks of "Modification:" and "Date:" followed by the files changed.
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

	for _, m := range noticeModInfo.FindAllSubmatch(data, -1) {
		text := string(m[1])
		s.Mods = append(s.Mods, NoticeMod{Date: normDate(text), Title: cleanTitle(text)})
	}
	var cur *NoticeMod
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Modification:"):
			text := strings.TrimSpace(strings.TrimPrefix(line, "Modification:"))
			s.Mods = append(s.Mods, NoticeMod{Date: normDate(text), Title: cleanTitle(text)})
			cur = &s.Mods[len(s.Mods)-1]
		case cur != nil && noticeDateRe.MatchString(line):
			if d := normDate(noticeDateRe.FindStringSubmatch(line)[1]); d != "" {
				cur.Date = d
			}
		case strings.HasPrefix(line, "===="):
			cur = nil
		case cur != nil && line != "" && !strings.ContainsAny(line, " \t") && strings.Contains(line, "/"):
			cur.Files = append(cur.Files, strings.TrimPrefix(line, "./"))
		}
	}
	return s
}

// Span is the earliest and latest dated modification, "" if none is dated.
func (s NoticeSummary) Span() (first, last string) {
	for _, m := range s.Mods {
		if m.Date == "" {
			continue
		}
		if first == "" || m.Date < first {
			first = m.Date
		}
		if m.Date > last {
			last = m.Date
		}
	}
	return first, last
}

// sourceRelease reads a source release's shape from member names alone: the
// top-level directories with their file counts, largest first, and the
// top-level notices (*_notice.txt, or numbered NNNN_*.txt).
func sourceRelease(names map[string]bool) (comps []string, notices []string, dirs []string) {
	count := map[string]int{}
	for n := range names {
		top, rest, ok := strings.Cut(n, "/")
		switch {
		case ok && rest != "":
			count[top]++
		case !ok && (strings.HasSuffix(n, "_notice.txt") || noticeTx.MatchString(n)):
			notices = append(notices, n)
		}
	}
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
	return comps, notices, dirs
}

// sourceProduct reads the product and platforms the tree directories name.
func sourceProduct(dirs []string) string {
	var product string
	platforms := map[string]bool{}
	for _, d := range dirs {
		if m := dirName.FindStringSubmatch(d); m != nil {
			if product == "" {
				product = m[2]
			}
			platforms[m[3]] = true
		}
	}
	if product == "" {
		return ""
	}
	var ps []string
	for p := range platforms {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return product + " (" + strings.Join(ps, ", ") + ")"
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
	comps, notices, dirs := sourceRelease(pkg.Names)
	if len(comps) == 0 {
		return
	}
	prov := facts.Provenance{Source: "top-level directories", Authority: facts.Attested}
	facts.Set(bag, SourceComponents, strings.Join(comps, "; "), prov)
	if p := sourceProduct(dirs); p != "" {
		facts.Set(bag, SourceProduct, p, prov)
	}
	if len(notices) == 0 {
		return
	}
	var lines []string
	var sec []secMod
	first, last := "", ""
	for _, n := range notices {
		s := ParseNotice(pkg.Read(n))
		line := strings.TrimSuffix(strings.TrimSuffix(n, ".txt"), "_notice")
		switch {
		case s.Files > 0:
			line += fmt.Sprintf(": %d modified file(s)", s.Files)
		case len(s.Mods) > 0:
			line += fmt.Sprintf(": %d modification(s)", len(s.Mods))
		default:
			line += ": package list"
		}
		if f, l := s.Span(); f != "" {
			if f == l {
				line += ", " + f
			} else {
				line += ", " + f + " to " + l
			}
			if first == "" || f < first {
				first = f
			}
			if l > last {
				last = l
			}
		}
		if len(s.Licenses) > 0 {
			line += ", " + strings.Join(s.Licenses, " / ")
		}
		lines = append(lines, line)
		for _, m := range s.Mods {
			if !duplicate(m.Title) && security.MatchString(m.Title+" "+strings.Join(m.Files, " ")) {
				sec = append(sec, secMod{m.Date, securityLine(n, m)})
			}
		}
	}
	nprov := facts.Provenance{Source: "notices", Authority: facts.Attested}
	facts.Set(bag, SourceNotices, strings.Join(lines, "; "), nprov)
	switch {
	case first != "" && first == last:
		facts.Set(bag, SourceDates, first, nprov)
	case first != "":
		facts.Set(bag, SourceDates, first+" to "+last, nprov)
	}
	if len(sec) > 0 {
		facts.Set(bag, SourceSecurity, strings.Join(recent(sec, securityMax), "; "), nprov)
	}
}

// securityMax bounds the trust-chain changes listed: the most recent, which say
// what the shipped build does.
const securityMax = 12

// secMod is a trust-chain modification's line with its date, for ordering.
type secMod struct{ date, line string }

// recent is the newest max lines, newest first, noting how many were left out.
func recent(mods []secMod, max int) []string {
	sort.SliceStable(mods, func(i, j int) bool { return mods[i].date > mods[j].date })
	var out []string
	for i, m := range mods {
		if i == max {
			out = append(out, fmt.Sprintf("(%d older not shown)", len(mods)-max))
			break
		}
		out = append(out, m.line)
	}
	return out
}

// securityLine is one trust-chain modification as "date title (notice)".
func securityLine(notice string, m NoticeMod) string {
	title := m.Title
	if len(title) > 110 {
		title = title[:110] + "…"
	}
	out := title
	if m.Date != "" {
		out = m.Date + " " + out
	}
	return out + " [" + strings.TrimSuffix(strings.TrimSuffix(notice, ".txt"), "_notice") + "]"
}
