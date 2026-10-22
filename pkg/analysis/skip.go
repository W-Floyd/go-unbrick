package analysis

import (
	"regexp"
	"strings"
	"sync"
)

// Skipping: a list of regular expressions, tried against an entry's full path from
// the input's root, through nested containers, with forward slashes. An entry that
// matches is left out, and a container that matches is not opened.

var skipRegexps sync.Map // pattern -> *regexp.Regexp, nil for one that does not compile

func skipRegexp(pattern string) *regexp.Regexp {
	if v, ok := skipRegexps.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	skipRegexps.Store(pattern, re)
	return re
}

// SkipPath reports whether path matches any of the skip patterns. An empty pattern
// matches nothing, and one that does not compile is ignored: hosts check theirs with
// regexp.Compile first.
func SkipPath(skip []string, path string) bool {
	for _, s := range skip {
		if s == "" {
			continue
		}
		if re := skipRegexp(s); re != nil && re.MatchString(strings.TrimPrefix(path, "/")) {
			return true
		}
	}
	return false
}
