package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"go-unbrick/internal/vendor"
)

// ---- stock package ----

func newStockCmd() *cobra.Command {
	c := &cobra.Command{Use: "stock", Short: "work with an OEM stock firmware package"}
	c.AddCommand(newStockExtractCmd())
	return c
}

func newStockExtractCmd() *cobra.Command {
	var out string
	var super bool
	c := &cobra.Command{
		Use:   "extract <stock.zip>",
		Short: "write every partition image in a stock package to a directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			drv, _, ok := vendor.DetectStock(path)
			if !ok {
				return fmt.Errorf("unrecognized stock package (no vendor driver matched): %s", path)
			}
			ex, ok := drv.(vendor.StockExploder)
			if !ok {
				return fmt.Errorf("%s packages cannot be exploded yet: %w", drv.ID(), vendor.ErrUnsupported)
			}
			names, err := ex.ExplodeStock(path, out, vendor.ExplodeOptions{Super: super})
			if err != nil {
				// Partial output is still useful; only a total failure is fatal.
				if len(names) == 0 {
					return err
				}
				fmt.Fprintf(os.Stderr, "  ! %v\n", err)
			}
			for _, n := range names {
				if fi, err := os.Stat(filepath.Join(out, n)); err == nil {
					fmt.Printf("  %12d  %s\n", fi.Size(), n)
				}
			}
			fmt.Printf("%d images (%s) -> %s\n", len(names), drv.ID(), out)
			if !super {
				fmt.Println("  (super image skipped; --super to join it)")
			}
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.Flags().BoolVar(&super, "super", false, "also join and write the multi-gigabyte super image")
	c.MarkFlagRequired("out")
	return c
}
