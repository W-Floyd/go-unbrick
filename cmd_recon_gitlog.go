package main

import (
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/gitlog"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// gitLogDump is a vendor's `git log` left in a source release, with where it sits.
type gitLogDump struct {
	Name string
	Log  *gitlog.Log
}

const (
	// gitLogMin and gitLogMax bound the size of a member worth looking at: a log
	// of any length is more than a couple of KiB, and less than a gigabyte.
	gitLogMin = 2 << 10
	gitLogMax = 1 << 30
	// gitLogDepth is how many directories deep a dump is looked for: they are left
	// at the top of a tree, not in its source.
	gitLogDepth = 6
)

// notLogs are the plain-text files every project has, which are never a log.
var notLogs = map[string]bool{
	"makefile": true, "maintainers": true, "changelog": true, "changes": true, "news": true, "authors": true,
	"install": true, "kconfig": true, "kbuild": true, "configure": true, "version": true, "todo": true,
	"contributing": true, "credits": true, "hacking": true, "thanks": true, "bugs": true, "history": true,
}

// gitLogCandidate says a member could be a log by its name and size alone, so the
// release's thousands of source files are not opened to find out.
func gitLogCandidate(name string, size uint64) bool {
	if size < gitLogMin || size > gitLogMax || strings.Count(name, "/") > gitLogDepth {
		return false
	}
	base := strings.ToLower(path.Base(name))
	if strings.HasPrefix(base, ".") || notLogs[base] {
		return false
	}
	for _, p := range []string{"readme", "license", "copying", "notice"} {
		if strings.HasPrefix(base, p) {
			return false
		}
	}
	switch path.Ext(base) {
	case "", ".log", ".txt", ".out":
		return true
	}
	return false
}

// findGitLogs reads each member under prefix ("" for all) that is a log of two or
// more commits.
func findGitLogs(entries []srcfile.Entry, prefix string) []gitLogDump {
	var out []gitLogDump
	for _, e := range entries {
		if !strings.HasPrefix(e.Name, prefix) || !gitLogCandidate(e.Name, e.Size) {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		head := make([]byte, 4096)
		n, _ := io.ReadFull(rc, head)
		rc.Close()
		if !gitlog.LooksLike(head[:n]) {
			continue
		}
		rc, err = e.Open()
		if err != nil {
			continue
		}
		l, err := gitlog.Parse(rc)
		rc.Close()
		if err == nil && len(l.Commits) >= 2 {
			out = append(out, gitLogDump{Name: e.Name, Log: l})
		}
	}
	return out
}

// printGitLogs reports the vendor history a source release left behind: how much
// there is, which release of upstream it begins from, and what the vendor
// committed on top of that.
func printGitLogs(input string) {
	entries, closer, err := srcfile.Entries(input)
	if err != nil || closer == nil {
		return
	}
	defer closer.Close()
	dumps := findGitLogs(entries, "")
	if len(dumps) == 0 {
		return
	}
	fmt.Println("  Git history left in the release:")
	for _, d := range dumps {
		l := d.Log
		// The range is the first and last commit as listed, not the extremes of the
		// dates: one commit in a long history may carry a nonsense author date.
		head, tail := l.Commits[0], l.Commits[len(l.Commits)-1]
		fmt.Printf("    %s: %d commits, %s to %s; newest by %s (%s)\n", d.Name, len(l.Commits),
			tail.Date.Format("2006-01-02"), head.Date.Format("2006-01-02"), domainOrUnknown(gitlog.Domain(head.Email)), head.Author)
		i, ok := l.Base()
		if !ok {
			fmt.Println("      no upstream release marker found, so the vendor's own commits cannot be told apart")
			continue
		}
		base, above := l.Commits[i], l.Commits[:i]
		lo, hi := gitlog.Span(above)
		fmt.Printf("      base: %s %q (%s); %d commit(s) above it by %d author(s)",
			base.Hash[:12], base.Subject, base.Date.Format("2006-01-02"), len(above), gitlog.Authors(above))
		if len(above) > 0 {
			fmt.Printf(", %s to %s", lo.Format("2006-01-02"), hi.Format("2006-01-02"))
		}
		fmt.Println()
		for j, c := range above {
			if j == 6 {
				fmt.Printf("        ... %d more\n", len(above)-6)
				break
			}
			fmt.Printf("        %s %s %s\n", c.Hash[:10], c.Date.Format("2006-01-02"), c.Subject)
		}
	}
}

func domainOrUnknown(s string) string {
	if s == "" {
		return "an unknown address"
	}
	return s
}

// pinFromGitLog gives a project the exact upstream commit its own history says it
// began from, when a log inside its tree names one.
func pinFromGitLog(entries []srcfile.Entry, root string) (commit, evidence string, ok bool) {
	for _, d := range findGitLogs(entries, root+"/") {
		if i, found := d.Log.Base(); found {
			c := d.Log.Commits[i]
			return c.Hash, fmt.Sprintf("pinned by the git history %s: base %s %q", infile.Base(d.Name), c.Hash[:12], c.Subject), true
		}
	}
	return "", "", false
}
