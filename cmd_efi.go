package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/efi"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// ---- efi ----

// efiInputs resolves any supported input to named images to scan: a stock
// package explodes to its partitions, a SINGLE_N_LONELY container to its
// records, and anything else (a bare abl.elf/xbl.elf, a raw dump) is itself.
func efiInputs(path string) (map[string][]byte, error) {
	if _, sp, ok := vendor.DetectStock(path); ok {
		t, err := sp.HarvestStockPackage(path)
		if err != nil {
			return nil, err
		}
		return t.Parts, nil
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		out := map[string][]byte{}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(path, e.Name())); err == nil {
				out[e.Name()] = b
			}
		}
		return out, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if blankflash.IsContainer(b) {
		recs, err := blankflash.Parse(b)
		if err != nil {
			return nil, err
		}
		out := map[string][]byte{}
		for _, r := range recs {
			if r.Name != blankflash.Trailer {
				out[r.Name] = r.Data
			}
		}
		return out, nil
	}
	return map[string][]byte{filepath.Base(path): b}, nil
}

func newEFICmd() *cobra.Command {
	var out, guids string
	c := &cobra.Command{
		Use:   "efi <stock.zip | abl.elf | container | dir>",
		Short: "list or extract the UEFI modules in a boot chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imgs, err := efiInputs(args[0])
			if err != nil {
				return err
			}
			var names map[string]string
			if guids != "" {
				f, err := os.Open(guids)
				if err != nil {
					return err
				}
				defer f.Close()
				if names, err = efi.LoadGUIDNames(f); err != nil {
					return err
				}
			}
			total := 0
			for _, img := range sortedKeys(imgs) {
				vols := efi.Volumes(imgs[img])
				if len(vols) == 0 {
					continue
				}
				mods, err := efi.Extract(imgs[img])
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ! %s: %v\n", img, err)
					continue
				}
				efi.ApplyNames(mods, names)
				fmt.Printf("%s: %d volume(s), %d modules\n", img, len(vols), len(mods))
				for _, m := range mods {
					if out == "" {
						fmt.Printf("  %s  type=0x%02x %-32s %d bytes\n", m.GUID, m.Type, m.Name, len(m.Data))
						continue
					}
					dst := filepath.Join(out, strings.TrimSuffix(img, filepath.Ext(img)), m.Filename())
					if err := write(dst, m.Data); err != nil {
						return err
					}
				}
				total += len(mods)
			}
			if total == 0 {
				fmt.Println("no UEFI firmware volumes found")
				return nil
			}
			if out != "" {
				fmt.Printf("%d modules -> %s\n", total, out)
			}
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "extract modules to this directory (default: list only)")
	c.Flags().StringVar(&guids, "guids", "", "CSV of guid,name to name modules that carry no UI section")
	return c
}
