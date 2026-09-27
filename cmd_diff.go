package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/imgdiff"
)

// ---- diff ----

// newDiffCmd compares two signed images in terms that survive re-signing. The
// raw byte count is reported too, because seeing it next to the verdict is the
// point: it is routinely an order of magnitude larger than the real change.
func newDiffCmd() *cobra.Command {
	var verbose bool
	c := &cobra.Command{
		Use:   "diff <a> <b>",
		Short: "compare two signed images, separating re-signing from real change",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			b, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			r, err := imgdiff.Compare(a, b)
			if err != nil {
				return err
			}
			rawPct := 0.0
			if r.SizeA > 0 {
				rawPct = 100 * float64(r.RawDiffering) / float64(r.SizeA)
			}
			fmt.Printf("%s vs %s\n", filepath.Base(args[0]), filepath.Base(args[1]))
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
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "show each differing run with its entropy")
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
