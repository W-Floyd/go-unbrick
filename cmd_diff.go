package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/imgdiff"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

func init() {
	analysis.OpenRoot = carveRoot
	analysis.TypeLabel = typeLabel
}

// ---- diff ----

// newDiffCmd compares two signed images in terms that survive re-signing. The
// raw byte count is reported too, because seeing it next to the verdict is the
// point: it is routinely an order of magnitude larger than the real change.
func newDiffCmd() *cobra.Command {
	var verbose, verify, profile, interactive bool
	var member, view string
	var context int
	var fetchAheadMiB int64
	var depth int
	c := &cobra.Command{
		Use:   "diff <a> <b>",
		Short: "compare two signed images, separating re-signing from real change; or two packages or directories (local or ssh://), member by member, with renames and moves matched by content",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := analysis.Config{A: args[0], B: args[1], Depth: depth, Verbose: verbose, Member: member, Verify: verify, FetchAhead: fetchAheadMiB << 20}
			if fetchAheadMiB == 0 {
				cfg.FetchAhead = -1
			}
			if profile {
				analysis.StartProfile()
			}
			if _, err := viewMode(view); err != nil {
				return err
			}
			diffContext = context
			if interactive {
				return runDiffInteractive(cfg)
			}
			if member != "" { // one file out of each input
				return runFileDiff(args[0], args[1], member, view)
			}
			if ok, err := analysis.Print(cfg); ok || err != nil {
				return err
			}
			a, err := infile.ReadFile(args[0])
			if err != nil {
				return err
			}
			b, err := infile.ReadFile(args[1])
			if err != nil {
				return err
			}
			r, err := imgdiff.Compare(a, b)
			if err != nil {
				// Not a signed image: two files of any kind, shown as what differs.
				return runFileDiff(args[0], args[1], "", view)
			}
			rawPct := 0.0
			if r.SizeA > 0 {
				rawPct = 100 * float64(r.RawDiffering) / float64(r.SizeA)
			}
			fmt.Printf("%s vs %s\n", infile.Base(args[0]), infile.Base(args[1]))
			fmt.Printf("  verdict: %s\n", r.Verdict)
			if r.Note != "" {
				fmt.Printf("  %s\n", r.Note)
			}
			fmt.Printf("  raw byte diff: %d of %d (%.1f%%) -- not a measure of change\n",
				r.RawDiffering, r.SizeA, rawPct)
			for _, s := range r.Segments {
				kind := "payload"
				if s.Hash {
					kind = "hash/sig"
				}
				switch {
				case s.OnlyA():
					fmt.Printf("  seg %-7s %-8s paddr=0x%-9x %7d bytes  only in first\n",
						segLabel(s), kind, s.Paddr, s.SizeA)
					continue
				case s.OnlyB():
					fmt.Printf("  seg %-7s %-8s paddr=0x%-9x %7d bytes  only in second\n",
						segLabel(s), kind, s.Paddr, s.SizeB)
					continue
				case s.Differing == 0 && !s.Resized():
					fmt.Printf("  seg %-7s %-8s paddr=0x%-9x %7d bytes  identical\n",
						segLabel(s), kind, s.Paddr, s.SizeA)
					continue
				}
				note := ""
				switch {
				case s.Hash:
					note = "  (re-signed; expected)"
				case len(s.Reports) > 0:
					note = "  (" + s.Reports[0].Summary() + ")"
				case s.Opaque():
					note = "  (opaque: compressed or key material)"
				case s.NamesEqual && !s.NamesOrdered:
					note = fmt.Sprintf("  (same %d names, reordered)", len(s.NamesA))
				}
				size := fmt.Sprintf("%7d", s.SizeA)
				if s.Resized() {
					size = fmt.Sprintf("%d->%d", s.SizeA, s.SizeB)
				}
				fmt.Printf("  seg %-7s %-8s paddr=0x%-9x %7s bytes  %d differing%s\n",
					segLabel(s), kind, s.Paddr, size, s.Differing, note)
				if !verbose {
					continue
				}
				for i, run := range s.Runs {
					if i >= 6 {
						fmt.Printf("      ... %d more runs\n", len(s.Runs)-6)
						break
					}
					tag := "structured"
					if run.Opaque {
						tag = "opaque"
					}
					fmt.Printf("      +%-8d %7d bytes  entropy %.2f  %s\n", run.Start, run.Len, run.Entropy, tag)
				}
				if s.NamesEqual {
					order := "same order"
					if !s.NamesOrdered {
						order = "reordered"
					}
					fmt.Printf("      name table: %d names, identical set, %s\n", len(s.NamesA), order)
				}
				for _, rep := range s.Reports {
					printReport("      ", rep)
				}
			}
			for _, rep := range r.Reports {
				fmt.Printf("  %s, compared independently of layout: %s\n", rep.Kind, rep.Summary())
				for _, line := range rep.Detail {
					fmt.Printf("      %s\n", line)
				}
			}
			if r.OutsideDiffering > 0 {
				fmt.Printf("  outside segments: %d differing\n", r.OutsideDiffering)
				if r.StampA != "" || r.StampB != "" {
					fmt.Printf("      %s\n      %s\n", r.StampA, r.StampB)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&member, "path", "", "compare just the file at this path inside each input (a directory, an archive or an image, as ls and extract take a path)")
	c.Flags().StringVar(&view, "view", modeNames[modeAuto], "for one file: diff (a line diff for text; for a binary, overlap and strings), strings, or overlap")
	c.Flags().IntVarP(&context, "context", "U", contextLines, "for one file: unchanged lines shown around each change")
	c.Flags().BoolVarP(&interactive, "interactive", "i", false, "browse the differences: a line diff for text; for binaries, shared vs unique bytes and a diff of the strings in them")
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "show each differing run with its entropy (images); list unchanged members too (packages)")
	c.Flags().Int64Var(&fetchAheadMiB, "fetch-ahead", analysis.DefaultFetchAhead>>20, "ssh:// inputs: MiB of upcoming files to fetch while the current one is processed (0 = off)")
	c.Flags().BoolVar(&profile, "profile", false, "packages: report on stderr where the time went")
	_ = c.Flags().MarkHidden("profile")
	c.Flags().BoolVar(&verify, "verify", false, "packages: read every file instead of trusting vendor manifests (.ver, update.info, TarList) for their hashes")
	c.Flags().IntVar(&depth, "depth", 3, "packages: how many container levels to compare into")
	addSecrets(c)
	return c
}

// segLabel names a segment by its program-header index on each side. They
// diverge when a rebuild inserts or drops one, which is why segments are
// aligned on load address rather than index.
func segLabel(s imgdiff.SegmentDiff) string {
	switch {
	case s.OnlyA():
		return fmt.Sprintf("%d/-", s.IndexA)
	case s.OnlyB():
		return fmt.Sprintf("-/%d", s.IndexB)
	case s.IndexA != s.IndexB:
		return fmt.Sprintf("%d/%d", s.IndexA, s.IndexB)
	}
	return fmt.Sprintf("%d", s.IndexA)
}

// printReport renders an analyzer's finding. The command prints what an
// analyzer produced without knowing which formats exist; teaching the tool a
// new one means registering an analyzer, not editing this.
func printReport(indent string, r imgdiff.Report) {
	fmt.Printf("%s%s: %s\n", indent, r.Kind, r.Summary())
	for _, line := range r.Detail {
		fmt.Printf("%s  %s\n", indent, line)
	}
}
