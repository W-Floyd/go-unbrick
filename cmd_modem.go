package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/modem"
	"github.com/W-Floyd/go-unbrick/internal/payload"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// modemImage reads the modem image from a stock zip (finds radio.img), an OTA
// zip or payload.bin (its modem partition), or a radio.img / NON-HLOS.bin /
// modem partition image passed directly.
func modemImage(path string) ([]byte, error) {
	if srcfile.IsZip(path) {
		_, data, err := srcfile.Open(path, "radio.img", "NON-HLOS.bin")
		if err == nil {
			return data, nil
		}
		p, closer, perr := payload.OpenZip(path)
		if perr != nil {
			return nil, err // no payload either: the stock-zip error says more
		}
		defer closer.Close()
		return payloadModem(p, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	magic := make([]byte, len(payload.HeaderMagic))
	if _, err := io.ReadFull(f, magic); err == nil && string(magic) == payload.HeaderMagic {
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		p, err := payload.NewFromReaderAt(f, fi.Size())
		if err != nil {
			return nil, err
		}
		return payloadModem(p, path)
	}
	return os.ReadFile(path)
}

// payloadModem materializes an OTA payload's modem partition.
func payloadModem(p *payload.Payload, path string) ([]byte, error) {
	for _, name := range []string{"modem", "modem_a"} {
		if p.Partition(name) == nil {
			continue
		}
		ra, size, err := p.PartitionReaderAt(name)
		if err != nil {
			return nil, err
		}
		img := make([]byte, size)
		if _, err := ra.ReadAt(img, 0); err != nil {
			return nil, err
		}
		return img, nil
	}
	return nil, fmt.Errorf("%s: OTA payload has no modem partition", path)
}

// newModemCmd groups offline inspection of a Motorola modem image (radio.img /
// NON-HLOS.bin). It peels the SINGLE_N_LONELY → sparse → ext4 chain in pure Go.
func newModemCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "modem",
		Short: "inspect a modem image (radio.img / NON-HLOS.bin / OTA modem partition)",
	}
	c.AddCommand(newModemLsCmd(), newModemExtractCmd(), newModemRawCmd())
	return c
}

func newModemLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls <stock.zip | ota.zip | payload.bin | radio.img | NON-HLOS.bin>",
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
		Use:   "extract <stock.zip | ota.zip | payload.bin | radio.img | NON-HLOS.bin> <file>",
		Short: "extract one file (e.g. image/mcfg_hw.mbn, or just mcfg_hw.mbn); a missing X.mbn is joined from X.mdt + X.bNN",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			img, err := modemImage(args[0])
			if err != nil {
				return err
			}
			data, err := modem.Extract(img, args[1])
			if errors.Is(err, modem.ErrNotFound) && strings.EqualFold(path.Ext(args[1]), ".mbn") {
				// No such .mbn: build it from the PIL split the loader actually reads.
				mdt := strings.TrimSuffix(args[1], path.Ext(args[1])) + ".mdt"
				var missing []int
				if data, missing, err = modem.JoinSplit(img, mdt); err != nil {
					return fmt.Errorf("%s not in image, and joining %s failed: %w", args[1], mdt, err)
				}
				if len(missing) > 0 {
					return fmt.Errorf("joining %s: segment file(s) %v missing", mdt, missing)
				}
				fmt.Printf("joined %s from %s and its .bNN segments\n", args[1], mdt)
			}
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
		Use:   "raw <stock.zip | ota.zip | payload.bin | radio.img | NON-HLOS.bin>",
		Short: "write the resolved raw ext4 or FAT image (for external tools)",
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
