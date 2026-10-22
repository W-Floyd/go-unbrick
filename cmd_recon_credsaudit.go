package main

import (
	"context"
	"fmt"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// runCredsAudit drives analysis.SweepCreds for --creds-audit: it opens the input
// just as runKeySweep does (so the registered vendor expanders and any loaded
// secrets are in effect), runs the sweep, and prints the redacted report.
func runCredsAudit(input string, depth int) error {
	if _, err := carveRoot(input); err != nil {
		return err
	}
	res, err := analysis.SweepCreds(context.Background(), input, analysis.CredSweepOptions{
		Depth: depth,
		Skip:  reconSkip,
	})
	if err != nil {
		return err
	}
	fmt.Print(res.Summary())
	if n := len(res.Unreadable); n > 0 {
		fmt.Printf("%d could not be read as listed:\n", n)
		for _, u := range res.Unreadable[:min(n, 10)] {
			fmt.Printf("  %s\n", u)
		}
		if n > 10 {
			fmt.Printf("  … and %d more\n", n-10)
		}
	}
	return nil
}
