package main

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
)

// defaultSkip is what --skip is when it is not given: the navigation map backups,
// gigabytes of map data that no command here has anything to find in. "--skip=" (an
// empty pattern) skips nothing.
const defaultSkip = `(^|/)navi_backup\.tar\d*$`

// addSkipFlag registers --skip on c: regular expressions tried against an entry's
// full path from the input's root, through nested containers; a match is left out,
// and a container that matches is not opened. what says what is left out where.
func addSkipFlag(c *cobra.Command, dst *[]string, what string) {
	c.Flags().StringArrayVar(dst, "skip", []string{defaultSkip},
		what+": leave out entries whose full path matches this regular expression (repeatable; default "+
			"matches the navigation map backups, navi_backup.tar*; --skip= skips nothing)")
}

// checkSkips drops empty patterns and reports one that is not a regular expression.
func checkSkips(skip []string) ([]string, error) {
	var out []string
	for _, s := range skip {
		if s == "" {
			continue
		}
		if _, err := regexp.Compile(s); err != nil {
			return nil, fmt.Errorf("--skip %q: %w", s, err)
		}
		out = append(out, s)
	}
	return out, nil
}
