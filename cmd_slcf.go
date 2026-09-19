package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"go-unbrick/internal/srcfile"
	"go-unbrick/internal/vendor"
)

// newSLCFCmd parses Motorola's subsidy-lock config (slcf_*.nvm).
func newSLCFCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "slcf",
		Short: "parse a Motorola subsidy-lock config (slcf_*.nvm)",
	}
	c.AddCommand(newSLCFParseCmd())
	return c
}

func newSLCFParseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "parse <stock.zip | slcf_*.nvm>",
		Short: "show the subsidy lock state, control-key length, and locked networks",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// From a stock zip, pick the slcf member; else read the file directly.
			member, data, err := srcfile.Open(args[0], slcfMembers(args[0])...)
			if err != nil {
				return err
			}
			cfg, err := vendor.ParseSLCF(data)
			if err != nil {
				return err
			}
			fmt.Printf("Source:      %s (%d bytes)\n", member, len(data))
			if !cfg.Locked {
				fmt.Println("Subsidy lock: none (retail / subsidy-DEFAULT)")
				return nil
			}
			fmt.Println("Subsidy lock: ENABLED")
			if cfg.ControlKeyDigits > 0 {
				fmt.Printf("Control key:  %d-digit unlock code\n", cfg.ControlKeyDigits)
			}
			fmt.Printf("NV items:    ")
			for i, id := range cfg.NVItems {
				sep := ""
				if i > 0 {
					sep = ", "
				}
				name := vendor.SLCFNVItemName(id)
				if name != "" {
					fmt.Printf("%s0x%04x (%s)", sep, id, name)
				} else {
					fmt.Printf("%s0x%04x", sep, id)
				}
			}
			fmt.Println()
			fmt.Printf("Locked to %d network(s):\n", len(cfg.PLMNs))
			for _, p := range cfg.PLMNs {
				fmt.Printf("  %s\n", p.String())
			}
			return nil
		},
	}
}

// slcfMembers returns candidate member names for a zip (any slcf_*.nvm), or the
// path itself when not a zip (Open ignores names then).
func slcfMembers(path string) []string {
	if names, err := srcfile.Glob(path, "slcf_*.nvm"); err == nil && len(names) > 0 {
		return names
	}
	return []string{"subsidy_lock_config.nvm"}
}
