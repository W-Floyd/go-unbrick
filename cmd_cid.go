package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go-unbrick/internal/cid"
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

// newCIDVBMetaCmd reads the CID a firmware's vbmeta.img is built for, from its
// HAB_META AVB property — so you can compare a package's target CID against a
// device's live `fastboot getvar cid` before flashing.
func newCIDVBMetaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vbmeta <vbmeta.img>",
		Short: "extract the target codename and CID from a vbmeta image (HAB_META)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			m, ok := cid.ParseHABMeta(data)
			if !ok {
				return fmt.Errorf("no HAB_META property found in %s (not a Motorola vbmeta image?)", args[0])
			}
			fmt.Printf("Codename: %s\n", m.Codename)
			fmt.Printf("CID:      %s (%d)\n", m.CIDHex(), m.CID)

			cat := activeCatalog()
			if name := cat.CarrierIDName(m.CIDHex()); name != "" {
				fmt.Printf("Carrier:  %s\n", name)
			} else if ref := cat.CarrierIDReference(m.CIDHex()); ref != "" {
				fmt.Printf("Carrier:  %s (unverified)\n", ref)
			}
			return nil
		},
	}
}
