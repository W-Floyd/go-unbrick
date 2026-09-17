package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/edl"
)

// Bundle filenames the qfil driver emits (internal/qfil).
const (
	edlLoaderName     = "prog_firehose_lite.elf"
	edlRawProgramName = "rawprogram0.xml"
	edlPatchName      = "patch0.xml"
	edlReadName       = "readprogram0.xml"
)

func newEDLCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "edl",
		Short: "provision and drive bkerler/edl to flash a qfil bundle over 9008",
	}
	c.AddCommand(newEDLInstallCmd(), newEDLBackupCmd(), newEDLFlashCmd())
	return c
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
		Args:  cobra.ExactArgs(1),
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
		Args: cobra.ExactArgs(1),
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
