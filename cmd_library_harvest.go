package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/harvest"
)

func newLibraryHarvestCmd() *cobra.Command {
	o := harvest.Options{Log: os.Stdout}
	var repos, orgs, pages, sites, archives []string
	var importAfter bool
	c := &cobra.Command{
		Use:   "harvest",
		Short: "gather Firehose loaders from community repos, archives, indexes and sites",
		Long: `Harvests loaders into --out with a manifest.json that import-loaders reads
(--import runs it straight after). Default sources are catalog/harvest.yaml;
each flag replaces its list for the run.

  git repos      GitHub (owner/name), GitLab or any git host (host/path),
                 cloned shallow into --cache-dir; --org expands a GitHub org or
                 GitLab group, --discover searches GitHub for more
  archives       URLs (Drive, MediaFire, Mega via mega-get, AndroidFileHost) or
                 local paths; nested archives are unpacked, RAR/7z via unar
  index pages    HTML autoindexes, walked recursively
  sites          pages whose posts link archives (therxtx, WordPress
                 categories and searches, AndroidFileHost searches)
  found/         archives and loose loaders dropped there, with no flag

The Temblast catalog is an overlay: it supplies upstream repos, a signer per
known file, and the loaders it flags as bad. Naming --repo limits the run to
those repos (plus any --archive/--page/--site given). Scraped link lists and
discovery results are cached for 24h; clones and downloads until --refresh.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			set := func(name string, v []string) []string {
				if cmd.Flags().Changed(name) {
					return v
				}
				return nil
			}
			o.Repos, o.Orgs, o.Pages = set("repo", repos), set("org", orgs), set("page", pages)
			o.SiteURLs, o.Archives = set("site", sites), set("archive", archives)
			o.Sources = activeCatalog().Harvest()
			res, err := harvest.Run(o)
			if err != nil {
				return err
			}
			byType := map[string]int{}
			for _, r := range res.Records {
				byType[r.Type]++
			}
			var types []string
			for t, n := range byType {
				if t == "" {
					t = "unknown"
				}
				types = append(types, fmt.Sprintf("%s=%d", t, n))
			}
			sort.Strings(types)
			fmt.Printf("\nScanned %d candidate file(s) across %d source(s).\n", res.Scanned, res.Sources)
			fmt.Printf("  %d carry a Temblast signer, %d dropped as known-bad, %d boot-chain images (not loaders) skipped.\n",
				res.Annotated, res.SkippedBad, res.SkippedBootImage)
			fmt.Printf("  %d skipped as already catalogued, %d duplicates", res.SkippedKnown, res.SkippedDup)
			if o.SkipOpaque {
				fmt.Printf(", %d opaque blobs", res.SkippedOpaque)
			}
			fmt.Println(".")
			if res.Repaired > 0 {
				fmt.Printf("  %d had a neutered magic byte, repaired on copy.\n", res.Repaired)
			}
			fmt.Printf("  %d new loader(s): %s\n", len(res.Records), strings.Join(types, ", "))
			if len(res.Records) == 0 || o.DryRun {
				return nil
			}
			if !importAfter {
				fmt.Printf("\nNext: unbrick library import-loaders %s\n", o.Out)
				return nil
			}
			fmt.Println()
			return importLoaders(o.Out, "", false, 0)
		},
	}
	f := c.Flags()
	f.StringArrayVar(&repos, "repo", nil, "repo to harvest: owner/name (GitHub) or host/path (GitLab, any git host); repeatable (default: catalog)")
	f.StringArrayVar(&orgs, "org", nil, "harvest every repo in a GitHub org, or host/group for a GitLab group; repeatable (default: catalog)")
	f.StringArrayVar(&pages, "page", nil, "HTML index linking loader files; repeatable (default: catalog)")
	f.StringArrayVar(&sites, "site", nil, "index URL whose per-device pages each link an off-site archive; repeatable (default: catalog)")
	f.StringArrayVar(&archives, "archive", nil, "archive of loaders (URL or local path); repeatable (default: catalog)")
	f.BoolVar(&o.NoDefaultArchives, "no-default-archives", false, "skip the catalog's archive list")
	f.StringVar(&o.ArchivePassword, "archive-password", "", "password for encrypted archives (also applied to found/)")
	f.BoolVar(&o.Rescrape, "rescrape", false, "re-scrape sites and re-run discovery even if their cache is fresh")
	f.BoolVar(&o.Discover, "discover", false, "find new loader repos on GitHub by code-searching loader fingerprints")
	f.StringVar(&o.Out, "out", "harvested_loaders", "output directory")
	f.StringVar(&o.CacheDir, "cache-dir", ".gh_loader_repos", "clone, download and scrape cache")
	f.StringVar(&o.FoundDir, "found-dir", "found", "drop directory harvested with no flag")
	f.StringVar(&o.TemblastCatalog, "temblast-catalog", "catalog/temblast_loaders.json", "Temblast catalog JSON")
	f.BoolVar(&o.RefreshCatalog, "refresh-catalog", false, "re-scrape "+harvest.TemblastURL+" into the catalog first")
	f.BoolVar(&o.DeltaOnly, "delta-only", false, "emit only loaders Temblast does not already list")
	f.BoolVar(&o.IncludeBad, "include-bad", false, "keep the loaders Temblast flags as broken")
	f.BoolVar(&o.NoTemblastRepos, "no-temblast-repos", false, "do not harvest the upstream repos named by the catalog")
	f.BoolVar(&o.SkipOpaque, "skip-opaque", false, "drop encrypted/compressed blobs instead of copying them")
	f.StringVar(&o.Structure, "structure", "flat", "output layout: flat, by-repo, by-type")
	f.Int64Var(&o.MinSize, "min-size", 16<<10, "skip files smaller than this")
	f.Int64Var(&o.MaxSize, "max-size", 8<<20, "skip files larger than this")
	f.BoolVar(&o.Refresh, "refresh", false, "re-fetch cached clones, downloads and index pages")
	f.IntVar(&o.Limit, "limit", 0, "max files to copy (0 = all)")
	f.BoolVar(&o.DryRun, "dry-run", false, "report what would be harvested")
	f.BoolVar(&importAfter, "import", false, "run import-loaders on the output afterwards")
	return c
}
