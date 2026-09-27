package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/bootelf"
	"github.com/W-Floyd/go-unbrick/internal/mediatek"
	"github.com/W-Floyd/go-unbrick/internal/qfil"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// ---- inspect ----

func printBootELF(indent, label string, info *bootelf.Info) {
	entryStr := ""
	if info.Entry != 0 {
		entryStr = fmt.Sprintf("  entry=0x%x", info.Entry)
	}
	fmt.Printf("%s%-16s arch=%-8s (%d-bit %s)%s  segments=%d\n",
		indent, label, info.Arch, info.Class, info.Endian, entryStr, len(info.Segments))

	if info.Identity != nil {
		swidExtra := ""
		if name := activeCatalog().SWIDName(info.Identity.SWID); name != "" {
			swidExtra = fmt.Sprintf(" (%s)", name)
		}
		fmt.Printf("%s  secboot:      root=CA %-4s OEM_ID=%s HW_ID=%s (JTAG=%s) SW_ID=%d%s key=RSA-%d\n",
			indent, info.Identity.Root, info.Identity.OEMID, info.Identity.HWID, info.Identity.JTAGID, info.Identity.SWID, swidExtra, info.Identity.KeyBits)
	}
	if info.Peek != secboot.PeekNone && info.Peek != secboot.PeekUnknown {
		fmt.Printf("%s  peek/poke:    %s\n", indent, info.Peek)
	}
	if info.Topology.Region != "" {
		breakdown := ""
		if info.Topology.CodeBytes > 0 || info.Topology.DataBytes > 0 || info.Topology.BSSBytes > 0 {
			breakdown = fmt.Sprintf(": %d KB code, %d KB data, %d KB BSS",
				(info.Topology.CodeBytes+1023)/1024,
				(info.Topology.DataBytes+1023)/1024,
				(info.Topology.BSSBytes+1023)/1024)
		}
		fmt.Printf("%s  topology:     %s @ 0x%x - 0x%x (%d KB%s)\n",
			indent, info.Topology.Region, info.Topology.BaseAddr, info.Topology.EndAddr, info.Topology.TotalMemKB, breakdown)
	}
	if len(info.Segments) > 0 {
		roleCounts := make(map[string]int)
		for _, s := range info.Segments {
			roleCounts[s.Role]++
		}
		rolesOrder := []string{"Code", "Data", "Rodata", "BSS", "Hash / Certs", "PageTable", "Phdr Table", "ELF Wrapper", "Metadata", "Loadable"}
		var parts []string
		for _, r := range rolesOrder {
			if count := roleCounts[r]; count > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", count, r))
			}
		}
		for r, count := range roleCounts {
			found := false
			for _, ro := range rolesOrder {
				if ro == r {
					found = true
					break
				}
			}
			if !found && count > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", count, r))
			}
		}
		if len(parts) > 0 {
			fmt.Printf("%s  segment_roles:%s\n", indent, " "+strings.Join(parts, ", "))
		}
	}
	if info.Provenance.Builder != "" {
		dateStr := ""
		if info.Provenance.BuildDate != "" {
			dateStr = fmt.Sprintf(" on %s", info.Provenance.BuildDate)
		}
		commitStr := ""
		if info.Provenance.CommitSHA != "" {
			commitStr = fmt.Sprintf(" (commit %s)", info.Provenance.CommitSHA)
		}
		fmt.Printf("%s  provenance:   built by %s%s%s\n", indent, info.Provenance.Builder, dateStr, commitStr)
	}
	if info.TargetSoC != "" || info.Variant != "" {
		tag := info.TargetSoC
		if tag == "" {
			tag = info.Variant
		}
		variantExtra := ""
		if info.Variant != "" && info.Variant != tag {
			variantExtra = " (" + info.Variant + ")"
		}
		fmt.Printf("%s  soc/variant:  %s%s\n", indent, tag, variantExtra)
	}
	if info.QCVersion != "" {
		fmt.Printf("%s  qc_version:   %s\n", indent, info.QCVersion)
	}
	if info.QCBuildTime != "" {
		fmt.Printf("%s  qc_built:     %s\n", indent, info.QCBuildTime)
	}
	if info.OEMBuild != "" {
		fmt.Printf("%s  oem_build:    %s\n", indent, info.OEMBuild)
	}
	if info.TMEVersion != "" || info.TMEBuildTime != "" {
		tmeStr := info.TMEVersion
		if info.TMEBuildTime != "" {
			tmeStr += " (" + info.TMEBuildTime + ")"
		}
		fmt.Printf("%s  tme_fw:       %s\n", indent, tmeStr)
	}
	if len(info.Storage) > 0 {
		fmt.Printf("%s  storage:      %s\n", indent, strings.Join(info.Storage, ", "))
	}
	if len(info.Subsystems.Details) > 0 {
		fmt.Printf("%s  subsystems:   %s\n", indent, strings.Join(info.Subsystems.Details, ", "))
	}
	if len(info.UEFIModules) > 0 {
		fmt.Printf("%s  uefi_mods:    %d module(s) [%s]\n", indent, len(info.UEFIModules), strings.Join(info.UEFIModules, ", "))
	}
	if len(info.KernelParams) > 0 {
		sample := info.KernelParams
		if len(sample) > 4 {
			sample = sample[:4]
		}
		fmt.Printf("%s  kernel_boot:  %d parameter(s) [%s...]\n", indent, len(info.KernelParams), strings.Join(sample, ", "))
	}
}

// inspectBytes reports the bootelf analysis of an ELF, or of every signed ELF
// record inside a SINGLE_N_LONELY container.
func inspectBytes(name string, b []byte) (int, error) {
	if bootelf.IsELF(b) {
		info, err := bootelf.Analyze(b)
		if err != nil {
			return 0, err
		}
		printBootELF("  ", name, info)
		return 1, nil
	}
	if blankflash.IsContainer(b) {
		recs, err := blankflash.Parse(b)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, r := range recs {
			if !bootelf.IsELF(r.Data) {
				continue
			}
			if info, err := bootelf.Analyze(r.Data); err == nil {
				printBootELF("  ", r.Name, info)
				n++
			}
		}
		return n, nil
	}
	return 0, fmt.Errorf("not an ELF or SINGLE_N_LONELY container")
}

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <elf | blankflash | container | stock-partition>",
		Short: "dump architecture, Qualcomm metadata, storage protocols, and secboot identity of images",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			// MediaTek package: derive the chip from the scatter (no Qualcomm secboot).
			if drv, ok := vendor.Detect(path); ok && drv.Platform() == vendor.PlatformMediaTek {
				info, err := mediatek.FromPackage(path)
				if err != nil {
					return err
				}
				fmt.Printf("%s:\n", path)
				fmt.Printf("  platform=mediatek chip=%s project=%s storage=%s partitions=%d\n",
					info.Chip, info.Project, info.Storage, len(info.Partitions))
				return nil
			}
			// A directory or zip donor: inspect the loader inside.
			if fi, err := os.Stat(path); err == nil && fi.IsDir() {
				d, err := blankflash.Ingest(path)
				if err != nil {
					return err
				}
				fmt.Printf("%s (loader from donor):\n", path)
				info, err := bootelf.Analyze(d.Programmer)
				if err != nil {
					return err
				}
				printBootELF("  ", "programmer.elf", info)
				return nil
			}
			b, missing, err := readImage(path)
			if err != nil {
				return err
			}
			if n := splitNote(missing); n != "" {
				fmt.Printf("%s: split image, %s\n", path, n)
			}
			if blankflash.IsContainer(b) {
				if recs, err := blankflash.Parse(b); err == nil {
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
			if bytes.Contains(b, []byte("EFI PART")) {
				if tbl, err := qfil.ParseGPT(b); err == nil {
					return printGPTAudit(path, tbl)
				}
			}
			fmt.Printf("%s:\n", path)
			n, err := inspectBytes(filepath.Base(path), b)
			if err != nil {
				// Last resort: treat as a donor blankflash (zip) and inspect its loader.
				if d, ierr := blankflash.Ingest(path); ierr == nil {
					if info, ferr := bootelf.Analyze(d.Programmer); ferr == nil {
						printBootELF("  ", "programmer.elf", info)
						return nil
					}
				}
				return err
			}
			if n == 0 {
				fmt.Println("  (no signed images found)")
			}
			return nil
		},
	}
}
