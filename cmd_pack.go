package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
)

// ---- container: unpack / pack ----

type manifestEntry struct {
	Name string `json:"name"`
	Size int    `json:"size"`
}

func newUnpackCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "unpack <container>",
		Short: "explode a SINGLE_N_LONELY container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			blob, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			recs, err := blankflash.Parse(blob)
			if err != nil {
				return err
			}
			var manifest []manifestEntry
			for _, r := range recs {
				if r.Name == blankflash.Trailer {
					continue
				}
				if err := write(filepath.Join(out, r.Name), r.Data); err != nil {
					return err
				}
				manifest = append(manifest, manifestEntry{Name: r.Name, Size: len(r.Data)})
			}
			mj, _ := json.MarshalIndent(manifest, "", "  ")
			if err := write(filepath.Join(out, "manifest.json"), mj); err != nil {
				return err
			}
			for _, m := range manifest {
				fmt.Printf("  %10d  %s\n", m.Size, m.Name)
			}
			fmt.Printf("%d records -> %s\n", len(manifest), out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.MarkFlagRequired("out")
	return c
}

func newPackCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "pack <dir>",
		Short: "rebuild a container from an unpacked dir",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			mj, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if err != nil {
				return err
			}
			var manifest []manifestEntry
			if err := json.Unmarshal(mj, &manifest); err != nil {
				return err
			}
			var recs []blankflash.Record
			for _, m := range manifest {
				b, err := os.ReadFile(filepath.Join(dir, m.Name))
				if err != nil {
					return err
				}
				recs = append(recs, blankflash.Record{Name: m.Name, Data: b})
			}
			blob, err := blankflash.Build(blankflash.WithTrailer(recs))
			if err != nil {
				return err
			}
			if err := write(out, blob); err != nil {
				return err
			}
			fmt.Printf("packed %d records -> %s (%d bytes)\n", len(recs), out, len(blob))
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output container")
	c.MarkFlagRequired("out")
	return c
}
