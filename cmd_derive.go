package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/library"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// ---- derive ----

func newDeriveCmd() *cobra.Command {
	var storage, provisionFrom, out, loaderBuild, stockBuild, format string
	var stripModel bool
	c := &cobra.Command{
		Use:   "derive <codename>",
		Short: "extrapolate a blankflash from a stored family loader + stock",
		Args:  cobra.ExactArgs(1),
	}
	tf := addTargetFlags(c)
	c.Flags().StringVar(&loaderBuild, "loader", "", "loader build id to use (default: newest)")
	c.Flags().StringVar(&stockBuild, "stock", "", "stock build id to use (default: newest)")
	c.Flags().BoolVar(&stripModel, "strip-model", false, "strip the QCDT model field so a sibling-model boot chain matches (cross-model donation)")
	c.Flags().StringVar(&storage, "storage", "", "override target storage type (emmc/ufs)")
	c.Flags().StringVar(&format, "format", "", "output format: native vendor format (default) or 'qfil'/'edl' for a bkerler/edl rawprogram bundle")
	c.Flags().StringVar(&provisionFrom, "provision-from", "", "XML file with a target-specific provisioning block")
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.MarkFlagRequired("out")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		c2, err := catalog.Load(catalogDir())
		if err != nil {
			return err
		}
		dev, ok := c2.Device(args[0])
		if !ok {
			return fmt.Errorf("unknown codename %q; extrapolation is limited to catalog devices", args[0])
		}
		drv, ok := vendor.For(dev.Vendor)
		if !ok {
			return fmt.Errorf("no vendor driver for %q", dev.Vendor)
		}
		lib, err := stockLibrary()
		if err != nil {
			return err
		}
		// Resolve candidate loaders (lowest SW_ID first). A recorded jtag_id is
		// the fact the PBL enforces, so it keys exactly; the cpu_name bridge is
		// the fallback and is lossy (one cpu_name spans several JTAG families).
		via := fmt.Sprintf("cpu_name %q", dev.CPUName)
		if len(dev.JTAGIDs) > 0 {
			via = fmt.Sprintf("jtag_id %v", dev.JTAGIDs)
		}
		cands := lib.CandidateLoaders(dev)
		if len(cands) == 0 {
			sibs, _ := c2.Siblings(args[0])
			codes := make([]string, len(sibs))
			for i, s := range sibs {
				codes[i] = s.Codename
			}
			return fmt.Errorf("no loader in library via %s (%s); ingest one from a sibling first "+
				"(library add-loader), donors: %v", via, dev.CPUFamily(), codes)
		}
		lref := &cands[0]
		if loaderBuild != "" {
			lref = nil
			for i := range cands {
				if cands[i].Build == loaderBuild {
					lref = &cands[i]
					break
				}
			}
			if lref == nil {
				return fmt.Errorf("no loader build %q among candidates for %s (%s)", loaderBuild, args[0], via)
			}
		}
		fam := lref.Family
		donor, lref, err := lib.FindLoader(fam, lref.Build)
		if err != nil {
			return err
		}

		var target *blankflash.Target
		var sref *library.StockRef
		if tf.parts != "" || tf.bootloader != "" {
			target, err = drv.HarvestStock(tf.source())
		} else if lib.HasStock(dev.Vendor, dev.Codename) {
			target, sref, err = lib.FindStock(dev.Vendor, dev.Codename, stockBuild)
		} else {
			return fmt.Errorf("no stock for %s in library and no --target-... given; "+
				"add it with library add-stock or pass the target's own images", dev.Codename)
		}
		if err != nil {
			return err
		}
		if stripModel {
			patched, err := stripModels(target)
			if err != nil {
				return err
			}
			fmt.Printf("  stripped QCDT model field from: %v\n", patched)
		}

		provisionData, err := readProvision(provisionFrom)
		if err != nil {
			return err
		}
		// Identity check: compare the chosen loader against the target's own stock
		// signing identity (read from its xbl/abl). OEM mismatch is fatal (won't
		// authenticate); HW/root divergence is advisory (loader-stage acceptance is
		// coarser, provable only on-device).
		if tgID := targetIdentity(target); tgID != nil {
			if ldID, err := secboot.FromELF(donor.Programmer); err == nil {
				oemOK, reasons := secboot.Compatible(ldID, tgID)
				swStr := fmt.Sprintf("SW_ID=%d", ldID.SWID)
				if swName := c2.SWIDName(ldID.SWID); swName != "" {
					swStr = fmt.Sprintf("SW_ID=%d (%s)", ldID.SWID, swName)
				}
				fmt.Printf("  identity: loader OEM=%s HW=%s root=CA %s %s  vs target OEM=%s HW=%s root=CA %s\n",
					ldID.OEMID, ldID.HWID, ldID.Root, swStr, tgID.OEMID, tgID.HWID, tgID.Root)
				for _, r := range reasons {
					fmt.Fprintf(os.Stderr, "  ! %s\n", r)
				}
				if !oemOK {
					return fmt.Errorf("refusing to forge: loader OEM_ID %s != target OEM_ID %s (will not authenticate)", ldID.OEMID, tgID.OEMID)
				}
				rb := secboot.ValidateRollback(ldID, tgID)
				for _, r := range rb.Reasons {
					fmt.Fprintf(os.Stderr, "  ! [anti-rollback] %s\n", r)
				}
			}
		}

		// The vendor driver ingests the loader and harvests stock; the output
		// format is a separate axis. --format qfil re-runs Assemble through the
		// generic Qualcomm driver (bkerler/edl rawprogram bundle) instead of the
		// vendor's native package. The signed programmer authenticates against the
		// fused JTAG_ID regardless of which host tool drives Sahara/Firehose.
		asm := drv
		switch format {
		case "", "native":
		case "qfil", "edl":
			q, ok := vendor.For("qualcomm")
			if !ok {
				return fmt.Errorf("qualcomm driver unavailable")
			}
			asm = q
		default:
			return fmt.Errorf("unknown --format %q (want native, qfil, or edl)", format)
		}
		res, err := asm.Assemble(donor, target, vendor.AssembleOptions{Slot: tf.slot, Storage: storage, Provision: provisionData})
		if err != nil {
			return err
		}
		if err := writeForgeOutput(out, res); err != nil {
			return err
		}
		if len(res.Singleimage) > 0 {
			recs, _ := blankflash.Parse(res.Singleimage)
			fmt.Printf("derived %s (%s) blankflash: %d bytes, %d records\n",
				dev.Codename, dev.Name, len(res.Singleimage), len(blankflash.Index(recs)))
		} else {
			fmt.Printf("derived %s (%s) QFIL recovery bundle: %d files\n",
				dev.Codename, dev.Name, len(res.Aux))
		}
		swStr := fmt.Sprintf("SW_ID=%d", lref.Meta.SWID)
		if swName := c2.SWIDName(lref.Meta.SWID); swName != "" {
			swStr = fmt.Sprintf("SW_ID=%d (%s)", lref.Meta.SWID, swName)
		}
		fmt.Printf("  family: %s  loader: %s@%s %s (from %s)\n", fam, fam, lref.Build, swStr, lref.Meta.Source)
		fmt.Printf("  target: %s  storage=%s\n", target.Source, firstNonEmpty(target.Storage, storage))
		if sref != nil {
			if others := lib.StockBuilds(dev.Vendor, dev.Codename); len(others) > 1 && stockBuild == "" {
				ids := make([]string, len(others))
				for i, s := range others {
					ids[i] = s.Build
				}
				fmt.Printf("  using newest of %d stock builds (%s); select another: --stock <build>\n",
					len(others), strings.Join(ids, ", "))
			}
		}
		if len(cands) > 1 && loaderBuild == "" {
			ladder := make([]string, len(cands))
			for i, b := range cands {
				swDesc := c2.SWIDName(b.Meta.SWID)
				if swDesc != "" {
					ladder[i] = fmt.Sprintf("%s(SW_ID=%d: %s)", b.Build, b.Meta.SWID, swDesc)
				} else {
					ladder[i] = fmt.Sprintf("%s(SW_ID=%d)", b.Build, b.Meta.SWID)
				}
			}
			fmt.Printf("  using lowest SW_ID; if it stalls at Sahara (rejected, harmless), step up: --loader <build>\n")
			fmt.Printf("  ladder: %s\n", strings.Join(ladder, " -> "))
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "  ! %s\n", w)
		}
		fmt.Printf("-> %s  (run blank-flash.bat / blank-flash.sh with the device in EDL 9008)\n", out)
		return nil
	}
	return c
}
