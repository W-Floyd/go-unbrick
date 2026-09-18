package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/cid"
	"go-unbrick/internal/edl"
	"go-unbrick/internal/qfil"
)

// Bundle filenames the qfil driver emits (internal/qfil).
const (
	edlLoaderName     = "prog_firehose_lite.elf"
	edlRawProgramName = "rawprogram0.xml"
	edlPatchName      = "patch0.xml"
	edlReadName       = "readprogram0.xml"
	edlCIDName        = "cid.bin"
)

// bundleDirArg requires exactly one positional: the qfil bundle directory. It
// names what is missing instead of cobra's bare "accepts 1 arg(s), received 0".
func bundleDirArg(cmd *cobra.Command, args []string) error {
	switch {
	case len(args) == 0:
		return fmt.Errorf("missing <bundle-dir>: the qfil/edl bundle to %s "+
			"(e.g. out/fogona-edl, produced by `unbrick derive <codename> --format qfil`)", cmd.Name())
	case len(args) > 1:
		return fmt.Errorf("expected one <bundle-dir>, got %d: %s", len(args), strings.Join(args, " "))
	}
	return nil
}

func newEDLCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "edl",
		Short: "provision and drive bkerler/edl to flash a qfil bundle over 9008",
	}
	c.AddCommand(newEDLInstallCmd(), newEDLVerifyCmd(), newEDLBackupCmd(), newEDLFlashCmd(), newEDLSetCIDCmd())
	return c
}

func newEDLVerifyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "verify <bundle-dir>",
		Short: "read-only: confirm the bundle matches the connected device's GPT",
		Long: "Sahara-loads the bundle's programmer, reads the live GPT, and checks that\n" +
			"every partition the bundle would write exists on the device at the same LUN\n" +
			"and offset with room to fit. Writes nothing; a power cycle clears the loader.",
		Args: bundleDirArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if err := validateBundle(dir, edlRawProgramName); err != nil {
				return err
			}
			entries, memory, err := loadRawProgram(dir)
			if err != nil {
				return err
			}
			r, err := ensureEDL(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Printf("Reading device GPT (--memory=%s)...\n", memory)
			dev, err := r.ReadGPT(cmd.Context(), dir, edlLoaderName, memory, os.Stderr)
			if err != nil {
				return err
			}
			return reportVerify(dir, entries, dev)
		},
	}
	return c
}

// loadRawProgram parses the bundle's rawprogram0.xml and infers the memory type
// from its sector size (4096 -> ufs, else emmc).
func loadRawProgram(dir string) ([]qfil.ProgramEntry, string, error) {
	data, err := os.ReadFile(filepath.Join(dir, edlRawProgramName))
	if err != nil {
		return nil, "", err
	}
	entries, err := qfil.ParseRawProgram(data)
	if err != nil {
		return nil, "", fmt.Errorf("parsing %s: %w", edlRawProgramName, err)
	}
	memory := "emmc"
	for _, e := range entries {
		if e.SectorSizeInBytes == 4096 {
			memory = "ufs"
			break
		}
	}
	return entries, memory, nil
}

// reportVerify cross-checks each bundle write against the device GPT and prints a
// per-partition table, returning an error if any check fails.
func reportVerify(dir string, entries []qfil.ProgramEntry, dev *edl.DevGPT) error {
	var problems int
	for _, e := range entries {
		ss := uint64(e.SectorSizeInBytes)
		if e.Label == "PrimaryGPT" {
			if !dev.HasLUN(e.PhysicalPartitionNumber) {
				fmt.Printf("  FAIL  PrimaryGPT -> LUN%d: device has no such LUN\n", e.PhysicalPartitionNumber)
				problems++
			} else {
				fmt.Printf("  ok    PrimaryGPT -> LUN%d\n", e.PhysicalPartitionNumber)
			}
			continue
		}
		p, ok := dev.Find(e.Label)
		if !ok {
			fmt.Printf("  FAIL  %-16s absent on device\n", e.Label)
			problems++
			continue
		}
		imgBytes := imageSize(dir, e.Filename, e.NumPartitionSectors*ss)
		wantOff := e.StartSector * ss
		var notes []string
		if p.LUN != e.PhysicalPartitionNumber {
			notes = append(notes, fmt.Sprintf("LUN %d!=%d", p.LUN, e.PhysicalPartitionNumber))
		}
		if p.Offset != wantOff {
			notes = append(notes, fmt.Sprintf("offset 0x%X!=0x%X", p.Offset, wantOff))
		}
		if imgBytes > p.Length {
			notes = append(notes, fmt.Sprintf("image 0x%X > partition 0x%X", imgBytes, p.Length))
		}
		if len(notes) > 0 {
			fmt.Printf("  FAIL  %-16s %s\n", e.Label, strings.Join(notes, ", "))
			problems++
		} else {
			fmt.Printf("  ok    %-16s LUN%d @0x%X (%s -> 0x%X of 0x%X)\n",
				e.Label, p.LUN, p.Offset, e.Filename, imgBytes, p.Length)
		}
	}
	if problems > 0 {
		return fmt.Errorf("%d partition(s) failed verification; do not flash", problems)
	}
	fmt.Println("\nAll writes match the device — bundle is safe to flash.")
	return nil
}

// imageSize returns the on-disk size of the bundle payload, falling back to the
// rawprogram-declared byte length if the file is unreadable.
func imageSize(dir, filename string, fallback uint64) uint64 {
	if fi, err := os.Stat(filepath.Join(dir, filename)); err == nil {
		return uint64(fi.Size())
	}
	return fallback
}

func newEDLInstallCmd() *cobra.Command {
	var reprovision bool
	c := &cobra.Command{
		Use:   "install",
		Short: "provision the managed edl virtualenv (cached under the user cache dir)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := edlOptions()
			dir, _ := edl.ResolveDir(opts.Dir)
			fmt.Printf("edl cache: %s\n", dir)
			r, err := edl.Ensure(cmd.Context(), opts, os.Stdout, reprovision)
			if err != nil {
				return err
			}
			if err := r.Doctor(cmd.Context()); err != nil {
				return err
			}
			fmt.Printf("edl ready: %s\n", r.BinaryPath())
			return nil
		},
	}
	c.Flags().BoolVar(&reprovision, "reprovision", false, "reinstall even if already present (upgrade/repair)")
	return c
}

func newEDLBackupCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "backup <bundle-dir>",
		Short: "dump the target's calibration/IMEI partitions via readprogram0.xml",
		Args:  bundleDirArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if err := validateBundle(dir, edlReadName); err != nil {
				return err
			}
			r, err := ensureEDL(cmd.Context())
			if err != nil {
				return err
			}
			return runBackup(cmd.Context(), r, dir)
		},
	}
	return c
}

func newEDLFlashCmd() *cobra.Command {
	var yes, skipBackup bool
	c := &cobra.Command{
		Use:   "flash <bundle-dir>",
		Short: "backup, then flash the qfil bundle over EDL 9008 (destructive)",
		Long: "Runs the safeguard backup (readprogram0.xml), verifies the dumps, then\n" +
			"flashes the boot chain and GPTs (rawprogram0.xml + patch0.xml) and resets.\n" +
			"The device must already be at Qualcomm EDL 9008.",
		Args: bundleDirArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if err := validateBundle(dir, edlRawProgramName, edlPatchName); err != nil {
				return err
			}
			r, err := ensureEDL(cmd.Context())
			if err != nil {
				return err
			}

			if skipBackup {
				fmt.Fprintln(os.Stderr, "! skipping backup — irreplaceable partitions are NOT dumped")
			} else if fileExists(filepath.Join(dir, edlReadName)) {
				if err := runBackup(cmd.Context(), r, dir); err != nil {
					return fmt.Errorf("backup failed, refusing to flash: %w", err)
				}
			} else {
				fmt.Fprintf(os.Stderr, "! no %s in bundle; nothing to back up\n", edlReadName)
			}

			if !yes {
				fmt.Printf("\nAbout to flash %s over EDL 9008. This overwrites the boot chain and GPTs.\nType 'flash' to proceed: ", dir)
				if !confirm("flash") {
					return fmt.Errorf("aborted")
				}
			}

			fmt.Println("Flashing boot chain + GPTs...")
			if err := r.Run(cmd.Context(), dir, os.Stdout,
				"--loader="+edlLoaderName,
				"--rawprogram="+edlRawProgramName,
				"--patch="+edlPatchName,
			); err != nil {
				return err
			}
			fmt.Println("Flash complete; rebooting to bootloader...")
			return r.Run(cmd.Context(), dir, os.Stdout, "--reset")
		},
	}
	c.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	c.Flags().BoolVar(&skipBackup, "skip-backup", false, "do not dump calibration/IMEI partitions first (dangerous)")
	return c
}

func newEDLSetCIDCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "setcid <bundle-dir> <value>",
		Short: "write a chosen software channel to the device's cid partition (destructive)",
		Long: "Builds a Motorola CID image for <value> (e.g. 0x33 for cid51, 0x00 for a\n" +
			"neutral channel) and writes it to the live device's cid partition by name.\n" +
			"The CID partition is unsigned and channel-only, so any value flashes; pick\n" +
			"the one your device shipped with. The device must be at EDL 9008.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("usage: setcid <bundle-dir> <value> (value in hex 0x.. or decimal)")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			value, err := parseCIDValue(args[1])
			if err != nil {
				return err
			}
			if err := validateBundle(dir); err != nil {
				return err
			}
			img := cid.Build(value)
			imgPath := filepath.Join(dir, edlCIDName)
			if err := os.WriteFile(imgPath, img, 0o644); err != nil {
				return err
			}
			fmt.Printf("Built %s: CID 0x%04X (%d bytes) -> %s\n", edlCIDName, value, len(img), imgPath)

			r, err := ensureEDL(cmd.Context())
			if err != nil {
				return err
			}
			memory := "emmc"
			if fileExists(filepath.Join(dir, edlRawProgramName)) {
				if _, m, err := loadRawProgram(dir); err == nil {
					memory = m
				}
			}

			if !yes {
				fmt.Printf("\nAbout to overwrite the device's cid partition with 0x%04X over EDL 9008.\n"+
					"This changes the device's carrier/software channel. Type 'cid' to proceed: ", value)
				if !confirm("cid") {
					return fmt.Errorf("aborted")
				}
			}
			fmt.Printf("Writing cid partition (--memory=%s)...\n", memory)
			if err := r.WritePartition(cmd.Context(), dir, edlLoaderName, memory, "cid", edlCIDName, os.Stdout); err != nil {
				return err
			}
			fmt.Printf("cid set to 0x%04X\n", value)
			return nil
		},
	}
	c.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return c
}

// parseCIDValue accepts a hex (0x..) or decimal channel value in the 16-bit range.
func parseCIDValue(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid cid value %q: want hex (0x33) or decimal (51), 0..65535", s)
	}
	return uint16(n), nil
}

// edlOptions reads the edl cache dir and pip spec through viper, so they resolve
// from config file, env (UNBRICK_EDL_DIR, UNBRICK_EDL_VERSION), and flags like
// every other setting.
func edlOptions() edl.Options {
	return edl.Options{Dir: v.GetString("edl-dir"), Spec: v.GetString("edl-version")}
}

// ensureEDL provisions edl and verifies its USB backend.
func ensureEDL(ctx context.Context) (*edl.Runner, error) {
	r, err := edl.Ensure(ctx, edlOptions(), os.Stderr, false)
	if err != nil {
		return nil, err
	}
	if err := r.Doctor(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// runBackup dumps protected partitions and verifies at least one non-empty dump
// landed in the bundle dir.
func runBackup(ctx context.Context, r *edl.Runner, dir string) error {
	fmt.Println("Backing up calibration/IMEI partitions (readprogram0.xml)...")
	if err := r.Run(ctx, dir, os.Stdout, "--loader="+edlLoaderName, "--read="+edlReadName); err != nil {
		return err
	}
	dumps, _ := filepath.Glob(filepath.Join(dir, "backup_*"))
	for _, d := range dumps {
		if fi, err := os.Stat(d); err == nil && fi.Size() > 0 {
			fmt.Printf("Backup OK: %d dump(s) in %s\n", len(dumps), dir)
			return nil
		}
	}
	return fmt.Errorf("no non-empty backup_* dumps produced in %s", dir)
}

// validateBundle checks the dir is a qfil/edl bundle carrying the loader and the
// named files. A qboot bundle (singleimage.bin) is rejected with guidance.
func validateBundle(dir string, required ...string) error {
	if fileExists(filepath.Join(dir, "singleimage.bin")) && !fileExists(filepath.Join(dir, edlLoaderName)) {
		return fmt.Errorf("%s is a qboot bundle (singleimage.bin), not an edl bundle; "+
			"regenerate with `derive <codename> --format qfil`", dir)
	}
	need := append([]string{edlLoaderName}, required...)
	for _, f := range need {
		if !fileExists(filepath.Join(dir, f)) {
			return fmt.Errorf("bundle %s missing %s", dir, f)
		}
	}
	return nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// confirm reads a line from stdin and reports whether it matches want.
func confirm(want string) bool {
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	return strings.TrimSpace(sc.Text()) == want
}
