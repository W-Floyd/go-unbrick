// Package gitlog reads the text `git log` prints, for the dumps of it that vendors
// leave in source releases. Such a file is a vendor's own history: who changed
// what, when, and on top of which upstream release.
package gitlog

import (
	"bufio"
	"io"
	"regexp"
	"strings"
	"time"
)

// Commit is one entry of a log.
type Commit struct {
	Hash    string
	Author  string
	Email   string
	Date    time.Time // zero if its date was not in a form read here
	Subject string
	Merge   bool
}

// Log is a log, newest commit first as git prints it.
type Log struct {
	Commits []Commit
}

var (
	ansi       = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	commitLine = regexp.MustCompile(`^commit ([0-9a-f]{40})\b`)
	authorLine = regexp.MustCompile(`^Author:\s+(.*?)\s*(?:<([^>]*)>)?\s*$`)
	headProbe  = regexp.MustCompile(`(?m)^commit [0-9a-f]{40}\b[^\n]*\n(?:Merge:[^\n]*\n)?Author:[^\n]*\nDate:`)
)

// dateLayouts are the forms git prints a date in (the default, and --date=iso).
var dateLayouts = []string{
	"Mon Jan 2 15:04:05 2006 -0700",
	"2006-01-02 15:04:05 -0700",
	time.RFC3339,
}

// LooksLike says the start of a file is a log: a commit, its author and its date,
// as git prints them, with or without colour.
func LooksLike(head []byte) bool {
	return headProbe.Match(ansi.ReplaceAll(head, nil))
}

// Parse reads a log. A line is at most 1 MiB, past which it is cut: the dumps
// carry the occasional minified file in a message.
func Parse(r io.Reader) (*Log, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var l Log
	var cur *Commit
	inBody := false
	for sc.Scan() {
		line := ansi.ReplaceAllString(sc.Text(), "")
		if m := commitLine.FindStringSubmatch(line); m != nil {
			l.Commits = append(l.Commits, Commit{Hash: m[1]})
			cur = &l.Commits[len(l.Commits)-1]
			inBody = false
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case !inBody && strings.HasPrefix(line, "Merge:"):
			cur.Merge = true
		case !inBody && strings.HasPrefix(line, "Author:"):
			if m := authorLine.FindStringSubmatch(line); m != nil {
				cur.Author, cur.Email = m[1], m[2]
			}
		case !inBody && strings.HasPrefix(line, "Date:"):
			cur.Date = parseDate(strings.TrimSpace(strings.TrimPrefix(line, "Date:")))
		case strings.HasPrefix(line, "    "):
			inBody = true
			if cur.Subject == "" {
				cur.Subject = strings.TrimSpace(line)
			}
		}
	}
	return &l, sc.Err()
}

func parseDate(s string) time.Time {
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Domain is the part of an email address after the @, lower case.
func Domain(email string) string {
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		return strings.ToLower(email[i+1:])
	}
	return ""
}

// release is a subject that marks an upstream release (U-Boot's "Prepare
// v2016.01", "Release 1.2.3", "Version 4.5").
var release = regexp.MustCompile(`(?i)^(prepare|release[d]?|version|bump version to)\s+v?\d+(\.\d+)+`)

// Base finds the newest commit that marks an upstream release: where the vendor's
// own commits, which are those above it, begin. ok is false when none does.
func (l *Log) Base() (i int, ok bool) {
	for i, c := range l.Commits {
		if release.MatchString(c.Subject) {
			return i, true
		}
	}
	return 0, false
}

// Span is the dates of the oldest and newest dated commits in cs.
func Span(cs []Commit) (oldest, newest time.Time) {
	for _, c := range cs {
		if c.Date.IsZero() {
			continue
		}
		if oldest.IsZero() || c.Date.Before(oldest) {
			oldest = c.Date
		}
		if c.Date.After(newest) {
			newest = c.Date
		}
	}
	return oldest, newest
}

// Authors counts the distinct authors of cs.
func Authors(cs []Commit) int {
	seen := map[string]bool{}
	for _, c := range cs {
		seen[c.Author+"\x00"+c.Email] = true
	}
	return len(seen)
}
