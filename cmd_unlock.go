package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/unlock"
	"go-unbrick/internal/vendor"
)

// newUnlockCmd groups offline bootloader-unlock-code tooling. It only *verifies*
// a vendor-issued code against a device's signed unlock record; it cannot derive
// one (see docs/motorola/README.md §3.5). The scheme is resolved through the
// vendor seam (vendor.UnlockVerifier), so any OEM that implements it is covered.
func newUnlockCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "unlock",
		Short: "verify a bootloader-unlock code against a device's signed unlock record",
	}
	c.AddCommand(newUnlockVerifyCmd(), newUnlockShowCmd())
	return c
}

// resolveRecord parses an unlock record from either a --file path (a raw record
// blob, e.g. a `cid`-partition dump) or a positional source: a '#'-separated
// get_unlock_data wire string, or a raw record as hex. Exactly one of file/src
// is expected to be set.
func resolveRecord(file, src string) (*unlock.Record, error) {
	var us vendor.UnlockSource
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		us.Blob = b
	case strings.Contains(src, "#"):
		us.Text = src
	default:
		b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(src), " ", ""))
		if err != nil {
			return nil, fmt.Errorf("source is not a get_unlock_data wire string (with '#') or a hex record; for a binary record use --file: %w", err)
		}
		us.Blob = b
	}
	return vendor.ParseUnlock(us)
}

// unlockPositional pulls the record source (if any) and the trailing operands
// from args, given whether --file was set. Without --file the first positional
// is the source; want is how many operands follow it (1 for a code, 0 for none).
func unlockPositional(file string, args []string, want int) (src string, rest []string, err error) {
	if file != "" {
		if len(args) != want {
			return "", nil, fmt.Errorf("with --file, pass %d argument(s), got %d", want, len(args))
		}
		return "", args, nil
	}
	if len(args) != want+1 {
		return "", nil, fmt.Errorf("pass a <source> plus %d argument(s), or use --file", want)
	}
	return args[0], args[1:], nil
}

func newUnlockVerifyCmd() *cobra.Command {
	var file string
	c := &cobra.Command{
		Use:   "verify [source] <code>",
		Short: "check whether a code is valid for a get_unlock_data challenge or record",
		Long: "Verify a bootloader-unlock code offline. Give the record as a positional\n" +
			"source — an OEM get_unlock_data wire string (contains '#') or a raw record as\n" +
			"hex — or read a binary record with --file (e.g. a cid-partition dump). Exits\n" +
			"non-zero on REJECT.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, rest, err := unlockPositional(file, args, 1)
			if err != nil {
				return err
			}
			rec, err := resolveRecord(file, src)
			if err != nil {
				return err
			}
			if rec.Verify(rest[0]) {
				fmt.Fprintln(cmd.OutOrStdout(), "ACCEPT")
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "REJECT")
			return fmt.Errorf("code rejected")
		},
	}
	c.Flags().StringVarP(&file, "file", "f", "", "read the raw unlock record from a binary file (e.g. a cid-partition dump)")
	return c
}

func newUnlockShowCmd() *cobra.Command {
	var file string
	c := &cobra.Command{
		Use:   "show [source]",
		Short: "print the parsed unlock-record fields (version, serial, salt, target)",
		Args:  cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, _, err := unlockPositional(file, args, 0)
			if err != nil {
				return err
			}
			rec, err := resolveRecord(file, src)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "scheme:  %s\n", rec.Scheme)
			for _, f := range rec.Fields {
				fmt.Fprintf(out, "%-8s %s\n", f.Key+":", f.Value)
			}
			return nil
		},
	}
	c.Flags().StringVarP(&file, "file", "f", "", "read the raw unlock record from a binary file (e.g. a cid-partition dump)")
	return c
}
