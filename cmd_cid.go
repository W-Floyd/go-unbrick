package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// newCIDCmd groups offline CID (carrier/customer ID) inspection of firmware.
func newCIDCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "cid",
		Short: "inspect the Motorola CID a firmware image declares",
	}
	c.AddCommand(newCIDVBMetaCmd())
	return c
}

// newCIDVBMetaCmd reads the codename and CID from a vbmeta.img HAB_META property.
// NOTE: this HAB_META CID is a signing/base value, constant across a device's
// carrier variants — it is NOT the carrier CID the bootloader matches. For that,
// read flashfile.xml's cid_value (see `recon` on a stock zip). This command is
// still useful to confirm the codename and base signing CID of a lone vbmeta.img.
func newCIDVBMetaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vbmeta <stock.zip | vbmeta.img>",
		Short: "read the codename and base (signing) CID from a vbmeta image (HAB_META)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, data, err := srcfile.Open(args[0], "vbmeta.img")
			if err != nil {
				return err
			}
			m, ok := vendor.ParseHABMeta(data)
			if !ok {
				return fmt.Errorf("no HAB_META property found in %s (not a Motorola vbmeta image?)", args[0])
			}
			fmt.Printf("Codename:  %s\n", m.Codename)
			fmt.Printf("HAB CID:   %s (%d) — signing/base value, not the carrier CID\n", m.CIDHex(), m.CID)
			fmt.Printf("           (carrier CID is flashfile.xml cid_value; see `recon`)\n")
			return nil
		},
	}
}
