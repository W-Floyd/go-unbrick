package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/qfil"
	"github.com/W-Floyd/go-unbrick/internal/safeguard"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
)

func newSafeguardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "safeguard",
		Short: "Audit partitions, verify anti-rollback fuses, and generate backup manifests",
		Long: `Safeguard suite for per-device calibration, IMEI, and NVRAM protection.
Prevents permanent network/baseband failure and anti-rollback bricking.`,
	}

	cmd.AddCommand(
		newSafeguardInspectCmd(),
		newSafeguardManifestCmd(),
		newSafeguardCheckCmd(),
	)

	return cmd
}

func newSafeguardInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <gpt.bin | bootloader.img | dumps-dir>",
		Short: "audit partition table or harvested dumps for protected calibration and identity partitions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data, err := os.ReadFile(path)
			if err != nil {
				// Check if it's a directory of dumps
				if fi, serr := os.Stat(path); serr == nil && fi.IsDir() {
					return auditDumpDir(path)
				}
				return err
			}

			// 1. Check if it's a blankflash container holding multiple gpt_main*.bin (Motorola UFS GPTs)
			if blankflash.IsContainer(data) {
				if recs, err := blankflash.Parse(data); err == nil {
					var allPartitions []qfil.Partition
					for _, r := range recs {
						if strings.HasPrefix(r.Name, "gpt_main") {
							lun := 0
							fmt.Sscanf(strings.TrimPrefix(strings.TrimSuffix(r.Name, ".bin"), "gpt_main"), "%d", &lun)
							if tbl, err := qfil.ParseGPTWithLUN(r.Data, lun); err == nil {
								allPartitions = append(allPartitions, tbl.Partitions...)
							}
						}
					}
					if len(allPartitions) > 0 {
						mergedTable := &qfil.Table{
							SectorSize: 512,
							Partitions: allPartitions,
						}
						return printGPTAudit(path, mergedTable)
					}
				}
			}

			// 2. Try parsing as single raw GPT table
			if tbl, err := qfil.ParseGPT(data); err == nil {
				return printGPTAudit(path, tbl)
			}

			// Try scanning partition names from GPT
			if names, err := safeguard.PartitionNamesFromGPT(data); err == nil && len(names) > 0 {
				return printPartitionNamesAudit(path, names)
			}

			// Try bootloader.img container
			if t, err := blankflash.FromBootloaderImg(data, nil); err == nil && len(t.Parts) > 0 {
				var partNames []string
				for fn := range t.Parts {
					partNames = append(partNames, strings.TrimSuffix(fn, filepath.Ext(fn)))
				}
				return printPartitionNamesAudit(path, partNames)
			}

			return fmt.Errorf("could not identify partition table in %s (not a valid GPT or bootloader.img)", path)
		},
	}
}

func printGPTAudit(path string, tbl *qfil.Table) error {
	fmt.Printf("Safeguard Audit: %s\n", path)
	fmt.Printf("  Disk GUID: %x-%x-%x-%x-%x  Sector Size: %d bytes  Partitions: %d\n\n",
		tbl.DiskGUID[0:4], tbl.DiskGUID[4:6], tbl.DiskGUID[6:8], tbl.DiskGUID[8:10], tbl.DiskGUID[10:16],
		tbl.SectorSize, len(tbl.Partitions))

	var partNames []string
	partMap := make(map[string]qfil.Partition)
	for _, p := range tbl.Partitions {
		partNames = append(partNames, p.Name)
		partMap[strings.ToLower(p.Name)] = p
	}

	rep := safeguard.Audit(partNames)

	fmt.Printf("  %-18s %-14s %-15s %-16s %-10s %s\n", "PARTITION", "CATEGORY", "CRITICALITY", "SECTORS", "SIZE", "DESCRIPTION")
	fmt.Printf("  %s\n", strings.Repeat("-", 100))

	for _, pa := range rep.Partitions {
		p := partMap[strings.ToLower(pa.Name)]
		sizeKB := float64(p.NumSectors*uint64(tbl.SectorSize)) / 1024.0
		sizeStr := fmt.Sprintf("%.1f KB", sizeKB)
		if sizeKB >= 1024.0 {
			sizeStr = fmt.Sprintf("%.1f MB", sizeKB/1024.0)
		}

		sectorRange := fmt.Sprintf("%d..%d", p.StartLBA, p.EndLBA)
		statusBadge := " "
		if pa.Protected {
			if pa.Criticality == safeguard.CriticalityIrreplaceable {
				statusBadge = "!"
			} else {
				statusBadge = "*"
			}
		}

		fmt.Printf(" %s%-17s %-14s %-15s %-16s %-10s %s\n",
			statusBadge, pa.Name, pa.Category, pa.Criticality, sectorRange, sizeStr, pa.Description)
	}

	fmt.Printf("\n  Summary: %d irreplaceable/protected, %d flashable boot components, %d other\n",
		rep.ProtectedCount, rep.ReplaceableCount, rep.UnknownCount)
	if rep.ProtectedCount > 0 {
		fmt.Printf("  Status: 🛡️  PROTECTED — Backups are required before flashing.\n")
	}
	return nil
}

func printPartitionNamesAudit(path string, names []string) error {
	fmt.Printf("Safeguard Audit: %s (%d partitions)\n\n", path, len(names))
	rep := safeguard.Audit(names)

	fmt.Printf("  %-18s %-14s %-15s %s\n", "PARTITION", "CATEGORY", "CRITICALITY", "DESCRIPTION")
	fmt.Printf("  %s\n", strings.Repeat("-", 80))

	for _, pa := range rep.Partitions {
		statusBadge := " "
		if pa.Protected {
			if pa.Criticality == safeguard.CriticalityIrreplaceable {
				statusBadge = "!"
			} else {
				statusBadge = "*"
			}
		}
		fmt.Printf(" %s%-17s %-14s %-15s %s\n", statusBadge, pa.Name, pa.Category, pa.Criticality, pa.Description)
	}

	fmt.Printf("\n  Summary: %d protected, %d boot components, %d other\n",
		rep.ProtectedCount, rep.ReplaceableCount, rep.UnknownCount)
	return nil
}

func auditDumpDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			base := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			names = append(names, base)
		}
	}
	return printPartitionNamesAudit(dir, names)
}

func newSafeguardManifestCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "manifest <gpt.bin>",
		Short: "generate Qualcomm Firehose readprogram0.xml to dump calibration/IMEI partitions via EDL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// ParseGPT unpacks a SINGLE_N_LONELY container and tags each partition
			// with its LUN and the real sector size (4096 on UFS), so byte offsets
			// in the manifest are correct.
			tbl, err := qfil.ParseGPT(data)
			if err != nil {
				return fmt.Errorf("parsing GPT from %s: %w", path, err)
			}

			manifest, err := qfil.GenerateReadProgram(tbl, nil)
			if err != nil {
				return fmt.Errorf("generating readprogram: %w", err)
			}

			if out != "" {
				if err := os.WriteFile(out, manifest, 0644); err != nil {
					return err
				}
				fmt.Printf("Wrote Firehose read manifest: %s (%d bytes)\n", out, len(manifest))
			} else {
				fmt.Println(string(manifest))
			}
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output filename (default: stdout)")
	return c
}

func newSafeguardCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <donor-loader.elf> <target-boot.elf>",
		Short: "perform anti-rollback and secboot identity check between donor loader and target stock image",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			donorBytes, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading donor %s: %w", args[0], err)
			}
			targetBytes, err := os.ReadFile(args[1])
			if err != nil {
				return fmt.Errorf("reading target %s: %w", args[1], err)
			}

			donorID, err := secboot.FromELF(donorBytes)
			if err != nil {
				return fmt.Errorf("parsing donor secboot: %w", err)
			}
			targetID, err := secboot.FromELF(targetBytes)
			if err != nil {
				return fmt.Errorf("parsing target secboot: %w", err)
			}

			c := activeCatalog()
			donorStage := c.SWIDName(donorID.SWID)
			targetStage := c.SWIDName(targetID.SWID)

			fmt.Println("Anti-Rollback & Identity Pre-Flight Check:")
			fmt.Printf("  Donor Loader:   %s\n", args[0])
			fmt.Printf("    OEM=%s HW_ID=%s (JTAG=%s) root=CA %s\n", donorID.OEMID, donorID.HWID, donorID.JTAGID, donorID.Root)
			fmt.Printf("    SW_ID=%d (stage: %s)  Anti-Rollback Version=%d\n", donorID.SWID, donorStage, donorID.AntiRollback())

			fmt.Printf("  Target Image:   %s\n", args[1])
			fmt.Printf("    OEM=%s HW_ID=%s (JTAG=%s) root=CA %s\n", targetID.OEMID, targetID.HWID, targetID.JTAGID, targetID.Root)
			fmt.Printf("    SW_ID=%d (stage: %s)  Anti-Rollback Version=%d\n\n", targetID.SWID, targetStage, targetID.AntiRollback())

			// 1. Compatibility
			oemOK, compReasons := secboot.Compatible(donorID, targetID)
			fmt.Printf("  OEM Binding:    %s\n", passFail(oemOK))
			for _, r := range compReasons {
				fmt.Printf("    ! %s\n", r)
			}

			// 2. Anti-Rollback
			rb := secboot.ValidateRollback(donorID, targetID)
			fmt.Printf("  Rollback Check: %s\n", rb.Status)
			for _, r := range rb.Reasons {
				fmt.Printf("    ! %s\n", r)
			}

			if rb.Status == secboot.RollbackSafe && oemOK {
				fmt.Println("\n  Verdict: ✅ SAFE — Donor loader satisfies target fuses and signing root.")
			} else if rb.Status == secboot.RollbackWarning {
				fmt.Println("\n  Verdict: ⚠️  WARNING — Donor loader anti-rollback version is lower than target. If device fuses are blown to target's level, Sahara transfer may stall.")
			} else {
				fmt.Println("\n  Verdict: ❌ FATAL — Incompatible signature. Loader will be rejected by PBL.")
			}

			return nil
		},
	}
}

func passFail(b bool) string {
	if b {
		return "PASS"
	}
	return "FAIL"
}
