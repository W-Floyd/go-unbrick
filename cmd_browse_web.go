package main

import (
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/web"
)

// runBrowseWeb serves browse as a web page: the same levels, previews and recon
// reports as the terminal browser.
func runBrowseWeb(input string, skip []string, addr string) error {
	b, err := analysis.NewBrowser(input, skip)
	if err != nil {
		return err
	}
	return serveWeb(addr, web.BrowseHandler(b, web.BrowseOptions{
		Title: infile.Base(input),
		Recon: func(e analysis.BrowseEntry) (string, error) {
			// One at a time (the handler's worker): runReconJob captures stdout, which is
			// process-wide.
			return stripANSI(runReconJob(reconJob{key: e.Key(), name: e.Name, osPath: e.OSPath, node: e.Node})), nil
		},
	}))
}
