package main

import (
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/web"
)

// runBrowseWeb serves browse as a web page: the same levels, previews and recon
// reports as the terminal browser.
func runBrowseWeb(input string, skip []string, addr string) error {
	stop := showProgress("opening " + infile.Base(input))
	b, err := analysis.NewBrowser(input, skip)
	stop()
	if err != nil {
		return err
	}
	opts := web.BrowseOptions{
		Title: infile.Base(input),
		Recon: func(e analysis.BrowseEntry) (string, error) {
			// One at a time (the handler's worker): runReconJob captures stdout, which is
			// process-wide.
			return stripANSI(runReconJob(reconJob{key: e.Key(), name: e.Name, osPath: e.OSPath, node: e.Node})), nil
		},
	}
	if infile.IsRemote(input) {
		// Run by the same worker as Recon, one at a time, so the flag is this job's alone.
		opts.ReconFull = func(e analysis.BrowseEntry) (string, error) {
			prev := infile.FullDownload
			infile.FullDownload = true
			defer func() { infile.FullDownload = prev }()
			return opts.Recon(e)
		}
	}
	return serveWeb(addr, web.BrowseHandler(b, opts))
}
