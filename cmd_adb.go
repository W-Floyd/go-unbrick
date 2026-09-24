package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/adb"
	"go-unbrick/internal/catalog"
	"go-unbrick/internal/library"
)

// The adb route: a phone booted into Android. It is the state a phone is most
// often found in, and the one that answers what the firmware *is* — the build
// fingerprint, the patch level, the property system's whole view of the
// hardware — where a bootloader answers what the hardware is.
func newADBCmd() *cobra.Command {
	var o adb.Options
	var f deviceReconFlags

	cmd := &cobra.Command{
		Use:   "adb [command]",
		Short: "Recon a phone booted into Android over adb",
		Long: `Reconnaissance over adb against a phone booted into Android.

Reads the property system (build fingerprint, patch level, the OEM's own names
for the device), /proc/cmdline as the bootloader left it, the SoC as sysfs
reports it, and the partition table by name. With root on the device
(--read-partitions) it also hands over the partition bytes — the identity and
boot-chain partitions are then run through the same recognizers a firmware
package's members go through.

Talks the adb server protocol directly rather than shelling out per command; a
server is started with the adb binary if none is running.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runADBRecon(o, f)
		},
	}

	cmd.PersistentFlags().StringVarP(&o.Serial, "serial", "s", "", "target a specific device serial")
	cmd.PersistentFlags().StringVar(&o.Host, "adb-host", "", "adb server host (default localhost; a remote server is never started for you)")
	cmd.PersistentFlags().IntVar(&o.Port, "adb-port", 0, "adb server port (default 5037)")
	cmd.PersistentFlags().StringVar(&o.ADBPath, "adb", "", "adb binary used to start a server if none is running (\"none\" to never start one)")
	cmd.PersistentFlags().StringVar(&o.Elevate, "elevate", "auto", "root helper for partition reads: auto, su, none")

	sub := newADBReconCmd(&o, &f)
	cmd.AddCommand(sub, newADBDebloatCmd(&o), newADBProvisionCmd(&o))
	cmd.Flags().AddFlagSet(sub.Flags())
	return cmd
}

func newADBReconCmd(o *adb.Options, f *deviceReconFlags) *cobra.Command {
	c := &cobra.Command{
		Use:   "recon",
		Short: "collect what a booted Android userspace says about the device, and derive from it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runADBRecon(*o, *f)
		},
	}
	f.register(c)
	return c
}

func runADBRecon(o adb.Options, f deviceReconFlags) error {
	stop := spin("querying adb…")
	dev, err := adb.Open(o)
	stop()
	if err != nil {
		return err
	}
	return runTransportRecon(dev, f, func() {
		printADBSections(dev, activeCatalog(), library.Open(libraryDir()), f)
	})
}

// printADBSections renders what an Android userspace knows. The shape follows
// the ssh and fastboot reports so all three read alike.
func printADBSections(dev *adb.Device, cat *catalog.Catalog, lib *library.Library, f deviceReconFlags) {
	r := dev.R
	redact := f.redact
	fmt.Printf("Android Device: %s\n", mask(redact, r.Serial))

	fmt.Println(cHdr("  Build:"))
	printField("Fingerprint", r.Fingerprint())
	printField("Display ID", r.Props["ro.build.display.id"])
	printField("Android", strings.TrimSpace(r.Props["ro.build.version.release"]+
		" (SDK "+r.Props["ro.build.version.sdk"]+")"))
	printField("Patch Level", r.Props["ro.build.version.security_patch"])
	printField("Build Type", strings.TrimSpace(r.Props["ro.build.type"]+" "+r.Props["ro.build.tags"]))
	printField("Kernel", firstNonEmpty(r.Props["ro.kernel.version"], r.Sections["uname"]))
	access := r.DescribeLogin()
	switch {
	case r.UID == 0:
		access += " — " + cGood("root shell: partitions readable")
	case r.ElevateOK == "su":
		access += " — " + cGood("su available: partitions readable")
	case r.Elevate == "su":
		access += " — " + cWarn("su present but this shell is not granted root")
	default:
		access += " — " + cWarn("unrooted: no partition reads")
	}
	printField("Access", access)

	fmt.Println("\n" + cHdr("  Device:"))
	codename := r.Codename()
	printField("Codename", codename)
	printField("Model", r.Model())
	printField("Manufacturer", r.Manufacturer())
	if soc := r.SoCTokens(); len(soc) > 0 {
		printField("SoC (as booted)", strings.Join(soc, ", "))
	}
	printField("Device Tree", r.DTModel)
	printField("Carrier", r.Props["ro.carrier"])
	printField("Baseband", firstNonEmpty(r.Props["gsm.version.baseband"], r.Props["ro.boot.baseband"]))
	if pct := r.BatteryPercent(); pct >= 0 {
		printField("Battery", fmt.Sprintf("%d%%", pct))
	}

	if len(r.FWImages) > 0 {
		fmt.Println("\n" + cHdr("  Running Firmware:"))
		printField("Source", r.FWImagesFrom)
		for _, im := range r.FWImages {
			var parts []string
			for _, s := range []string{im.CRM, im.Variant, im.OEM} {
				if s != "" {
					parts = append(parts, s)
				}
			}
			printField(im.Name, strings.Join(parts, "  "))
		}
	}

	printCatalogSections(codename, cat, lib)
	// BootParams, not the cmdline: /proc/cmdline is unreadable to an unrooted
	// adb shell on Android 12 and later, and the ro.boot.* properties that
	// mirror it are the only place this recon learns the slot and lock state.
	printBootStateSection(r.Slot(), r.LockState(), r.BootParams(), r.ABDevice(), redact)

	if len(r.Partitions) > 0 {
		fmt.Println("\n" + cHdr("  Storage & Partitions:"))
		if r.Storage != "" {
			printField("Storage", r.Storage+" (inferred from block devices)")
		}
		printPartitionSections(dev, f.readCap)
	}
	if f.raw {
		printShellRaw(r.Sections, redact)
	}
}
