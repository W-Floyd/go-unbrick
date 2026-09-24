package main

import (
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go-unbrick/internal/modem"
	"go-unbrick/internal/srcfile"
)

// modemImage reads the modem image from a stock zip (finds radio.img) or a
// radio.img / NON-HLOS.bin passed directly.
func modemImage(path string) ([]byte, error) {
	_, data, err := srcfile.Open(path, "radio.img", "NON-HLOS.bin")
	return data, err
}

// newModemCmd groups offline inspection of a Motorola modem image (radio.img /
// NON-HLOS.bin). It peels the SINGLE_N_LONELY → sparse → ext4 chain in pure Go.
func newModemCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "modem",
		Short: "inspect a Motorola modem image (radio.img / NON-HLOS.bin)",
	}
	c.AddCommand(newModemLsCmd(), newModemExtractCmd(), newModemRawCmd())
	return c
}

func newModemLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls <stock.zip | radio.img | NON-HLOS.bin>",
		Short: "list the files in a modem image",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			img, err := modemImage(args[0])
			if err != nil {
				return err
			}
			entries, err := modem.List(img)
			if err != nil {
				return err
			}
			for _, e := range entries {
				fmt.Printf("%10d  %s\n", e.Size, e.Path)
			}
			fmt.Printf("\n%d file(s)\n", len(entries))
			return nil
		},
	}
}

func newModemExtractCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "extract <stock.zip | radio.img | NON-HLOS.bin> <file>",
		Short: "extract one file (e.g. image/mcfg_hw.mbn, or just mcfg_hw.mbn)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			img, err := modemImage(args[0])
			if err != nil {
				return err
			}
			data, err := modem.Extract(img, args[1])
			if err != nil {
				return err
			}
			if out == "" {
				fmt.Printf("%s  %d bytes  sha256=%x\n", args[1], len(data), sha256.Sum256(data))
				return nil
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}
			fmt.Printf("wrote %s (%d bytes, sha256=%x)\n", out, len(data), sha256.Sum256(data))
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write to this path instead of printing size+hash")
	return c
}

func newModemRawCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "raw <stock.zip | radio.img | NON-HLOS.bin>",
		Short: "write the resolved raw ext4 image (for external tools)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			img, err := modemImage(args[0])
			if err != nil {
				return err
			}
			raw, err := modem.Resolve(img)
			if err != nil {
				return err
			}
			if out == "" {
				out = "modem_ext4.img"
			}
			if err := os.WriteFile(out, raw, 0o644); err != nil {
				return err
			}
			fmt.Printf("wrote %s (%d bytes)\n", out, len(raw))
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output path (default modem_ext4.img)")
	return c
}
