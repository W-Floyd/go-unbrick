package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/cid"
	"go-unbrick/internal/fastboot"
	"go-unbrick/internal/library"
	"go-unbrick/internal/safeguard"
	"go-unbrick/internal/vendor"
)

func newFastbootCmd() *cobra.Command {
	var serial string
	var fastbootBin string

	cmd := &cobra.Command{
		Use:   "fastboot",
		Short: "Perform reconnaissance and control devices connected in Fastboot mode",
		Long: `Fastboot suite for device reconnaissance, dual-slot diagnostics,
and transitioning from ABL bootloader mode into Qualcomm EDL (9008) mode.
Resolves 'fastboot' binary directly from system PATH.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default to running reconnaissance
			return runFastbootRecon(fastbootBin, serial, false)
		},
	}

	cmd.PersistentFlags().StringVarP(&serial, "serial", "s", "", "target specific device serial number")
	cmd.PersistentFlags().StringVar(&fastbootBin, "fastboot", "", "custom path to fastboot binary (defaults to PATH)")

	cmd.AddCommand(
		newFastbootReconCmd(&fastbootBin, &serial),
		newFastbootPartitionsCmd(&fastbootBin, &serial),
		newFastbootHashCmd(&fastbootBin, &serial),
		newFastbootSlotCmd(&fastbootBin, &serial),
		newFastbootEDLCmd(&fastbootBin, &serial),
		newFastbootUnlockDataCmd(&fastbootBin, &serial),
		newFastbootSetCIDCmd(&fastbootBin, &serial),
	)

	return cmd
}

func newFastbootReconCmd(fastbootBin, serial *string) *cobra.Command {
	var raw bool
	c := &cobra.Command{
		Use:   "recon",
		Short: "query device variables, audit dual-slot health, and cross-reference catalog & library",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFastbootRecon(*fastbootBin, *serial, raw)
		},
	}
	c.Flags().BoolVar(&raw, "raw", false, "also dump the device's raw output (every getvar var and oem probe line)")
	return c
}

func runFastbootRecon(fastbootBin, serial string, raw bool) error {
	client, err := fastboot.NewClient(fastbootBin)
	if err != nil {
		return err
	}

	devs, err := client.Devices()
	if err != nil {
		return fmt.Errorf("querying fastboot devices: %w", err)
	}

	if len(devs) == 0 {
		fmt.Println("No fastboot devices detected.")
		fmt.Println("  • Ensure your device is in bootloader/fastboot mode (Power + Volume Down).")
		fmt.Println("  • Verify the USB cable connection.")
		fmt.Println("  • Check host detection using: fastboot devices")
		return nil
	}

	targetDevices := devs
	if serial != "" {
		targetDevices = []fastboot.Device{{Serial: serial, State: "fastboot"}}
	}

	cat := activeCatalog()
	lib := library.Open(libraryDir())

	for i, d := range targetDevices {
		if i > 0 {
			fmt.Println(strings.Repeat("=", 80))
		}

		recon, err := client.GetVarAll(d.Serial)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error querying device %s: %v\n", d.Serial, err)
			continue
		}

		printReconReport(d.Serial, recon, cat, lib, raw)
	}

	return nil
}

func printReconReport(serial string, r *fastboot.DeviceRecon, cat *catalog.Catalog, lib *library.Library, raw bool) {
	fmt.Printf("Fastboot Device: %s\n", serial)

	// 1. Hardware
	fmt.Println("  Hardware:")
	printField("Product / Board", r.Product)
	printField("HW Revision", r.HWRev)
	printField("SKU", r.SKU)
	printField("Carrier", r.Carrier)
	printField("CPU / SoC", r.CPU)
	if r.StorageType != "" {
		ufsOrEmmc := r.StorageType
		if r.RawVars["ufs"] != "" && r.RawVars["ufs"] != "false" {
			ufsOrEmmc = fmt.Sprintf("%s (%s)", r.StorageType, r.RawVars["ufs"])
		}
		printField("Storage", ufsOrEmmc)
	}
	printField("RAM", r.RAM)
	if r.BatteryVoltage != "" {
		socText := ""
		if r.BatterySocOK != "" {
			socText = fmt.Sprintf(" (OK: %s)", r.BatterySocOK)
		}
		voltStr := r.BatteryVoltage
		if !strings.HasSuffix(voltStr, "mV") && !strings.HasSuffix(voltStr, "V") {
			voltStr += " mV"
		}
		printField("Battery", voltStr+socText)
	}
	if r.UID != "" {
		uidDesc := r.UID
		if r.JTAGID != "" {
			uidDesc = fmt.Sprintf("%s (JTAG ID: %s)", r.UID, r.JTAGID)
		}
		printField("Silicon UID", uidDesc)
	}
	printField("Chip ID", r.ChipID)
	printField("IMEI", r.IMEI)
	printField("Manufactured", r.ManufactureDate)
	printField("Display Panel", r.PrimaryDisplay)
	if r.PCBPartNo != "" || r.BattID != "" {
		printField("Part Numbers", strings.TrimSpace(fmt.Sprintf("PCB %s  Battery %s", r.PCBPartNo, r.BattID)))
	}

	if r.HardwareFeatures != nil {
		hw := r.HardwareFeatures
		var feats []string
		if hw.FPS {
			feats = append(feats, "Fingerprint (FPS)")
		}
		if hw.ECompass {
			feats = append(feats, "E-Compass")
		}
		if hw.NFC {
			feats = append(feats, "NFC")
		}
		if hw.ESIM {
			feats = append(feats, "eSIM")
		}
		if hw.DualSIM {
			feats = append(feats, "Dual-SIM")
		}
		featStr := strings.Join(feats, ", ")
		if featStr == "" {
			featStr = "None detected"
		}
		printField("Features / Sensors", featStr)
	}

	// 2. Security & Bootloader
	fmt.Println("\n  Security & Bootloader:")
	printField("Bootloader Version", r.BootloaderVersion)
	printField("XBL Build", r.XBLBuild)
	if r.SecurityVersions != nil && (r.SecurityVersions.RIL0 > 0 || r.SecurityVersions.RIL2 > 0) {
		printField("Anti-Rollback (RIL)", fmt.Sprintf("#0: %d, #2: %d (Active)", r.SecurityVersions.RIL0, r.SecurityVersions.RIL2))
	}
	lockStr := "LOCKED"
	if r.Unlocked {
		lockStr = "UNLOCKED"
	}
	if r.SecureState != "" {
		lockStr = fmt.Sprintf("%s (state: %s)", lockStr, r.SecureState)
	}
	printField("Lock Status", lockStr)
	cidDesc := r.CarrierID
	if norm := library.NormalizeCID(r.CarrierID); norm == "0xDEAD" || norm == "0xFFFF" {
		// A corrupt/tampered cid partition; ABL sets 0xDEAD and blocks AP fastboot.
		// Recoverable via `fastboot oem cid_prov_req` -> signed cid_prov_data.
		cidDesc = fmt.Sprintf("%s — CORRUPT (0xDEAD): cid partition tampered, AP flashing blocked", cidDesc)
	} else if name := cat.CarrierIDName(r.CarrierID); name != "" {
		cidDesc = fmt.Sprintf("%s — %s", cidDesc, name)
	} else if slcf := lib.CarrierIDs()[library.NormalizeCID(r.CarrierID)]; slcf != "" {
		// Uncatalogued CID, but a stored package declared it: name it from that.
		cidDesc = fmt.Sprintf("%s — subsidy lock %s (from stored build)", cidDesc, slcf)
	}
	printField("Carrier ID (CID)", cidDesc)
	if cp := r.CIDProvReq; cp != nil {
		var parts []string
		if cp.SoCID != "" {
			soc := cp.SoCID
			if r.JTAGID != "" && strings.EqualFold(cp.SoCID, r.JTAGID) {
				soc += " (= JTAG_ID)"
			}
			parts = append(parts, "SoC "+soc)
		}
		if cp.FormatVersion != 0 {
			parts = append(parts, fmt.Sprintf("fmt v%d", cp.FormatVersion))
		}
		if cp.Digest != "" {
			parts = append(parts, "digest "+cp.Digest)
		}
		kv := make([]string, 0, len(cp.Fields))
		for k, v := range cp.Fields {
			kv = append(kv, k+"="+v)
		}
		sort.Strings(kv)
		parts = append(parts, kv...)
		if len(parts) == 0 {
			parts = append(parts, fmt.Sprintf("available (%d line(s), pass --raw for the dump)", len(cp.RawLines)))
		}
		printField("CID Prov Req (moto)", strings.Join(parts, ", "))
	}
	printField("Channel ID", r.ChannelID)
	printField("FRP State", r.FRPState)
	printField("Verity State", r.VerityState)
	printField("Life Cycle State", r.LCSState)
	printField("Unlock Token", r.TokenState)
	if r.FactoryModes != "" || r.WarrantyVoid != "" || r.FDRAllowed != "" {
		printField("Factory Flags", fmt.Sprintf("modes %s, warranty void %s, FDR allowed %s",
			orUnknown(r.FactoryModes), orUnknown(r.WarrantyVoid), orUnknown(r.FDRAllowed)))
	}
	if r.MaxDownloadSize > 0 || r.LogicalBlockSize > 0 {
		// What a flash must respect: the largest single transfer the bootloader
		// accepts, the chunk size it wants sparse images split into, and the
		// block size a rawprogram's sector maths has to line up with.
		printField("Flash Geometry", fmt.Sprintf("max-download %s, max-sparse %s, block %s",
			formatSizeKB(r.MaxDownloadSize/1024), formatSizeKB(r.MaxSparseSize/1024), formatSizeKB(r.LogicalBlockSize/1024)))
	}
	if r.BootLUN != "" {
		printField("Boot LUN", r.BootLUN)
	}
	printField("Boot Reason", r.BootReason)
	envStr := "Bootloader (ABL)"
	if r.IsUserspace {
		envStr = "Userspace (recovery fastbootd)"
	}
	printField("Environment", envStr)

	// 3. Dual-Slot Health
	hasUnbootableSlot := false
	if r.SlotCount > 0 || r.CurrentSlot != "" || len(r.SlotStatus) > 0 {
		fmt.Println("\n  Dual-Slot Health:")
		if r.CurrentSlot != "" {
			printField("Active Slot", "_"+r.CurrentSlot)
		}
		for _, s := range []string{"a", "b"} {
			if info, ok := r.SlotStatus[s]; ok {
				status := "Bootable"
				if !info.Bootable() {
					status = "UNBOOTABLE"
					hasUnbootableSlot = true
					if !info.Unbootable {
						// Derived, not flagged: say so, or the line reads as if
						// the bootloader had marked the slot itself.
						status += " — no retries left"
					}
				}
				succStr := "no"
				if info.Successful {
					succStr = "yes"
				}
				fmt.Printf("    %-20s Slot %s: %s (Successful: %s, Retries: %d)\n",
					"", s, status, succStr, info.RetryCount)
			}
		}
		if r.UnpopulatedSlotB {
			fmt.Printf("    [!] Root Cause for Slot B: Dynamic partitions in 'super' are unpopulated (0 KB):\n")
			fmt.Printf("        %s\n", strings.Join(r.UnpopulatedParts, ", "))
			fmt.Println("        Slot B has no installed Android OS system image; it is expected to be unbootable.")
			if note := confirmUnpopulated(r); note != "" {
				fmt.Printf("        %s\n", note)
			}
		} else if hasUnbootableSlot {
			fmt.Println("    [!] Warning: An inactive slot is flagged UNBOOTABLE (update failed or retry limit exceeded).")
		}
	}

	// 4. Software Build
	if r.DisplayID != "" || r.Fingerprint != "" || r.Baseband != "" {
		fmt.Println("\n  Installed Firmware:")
		printField("Display ID", r.DisplayID)
		printField("Fingerprint", r.Fingerprint)
		printField("Baseband", r.Baseband)
		printField("Qualcomm Baseline", r.QCBaseline)
	}

	// 4b. Per-component boot chain stamps
	if dates := r.BootChainDates(); len(dates) > 0 {
		fmt.Println("\n  Boot Chain Stamps:")
		for _, d := range sortedDatesDesc(dates) {
			printField("Built "+d, fmt.Sprintf("%d component(s): %s", len(dates[d]), strings.Join(dates[d], ", ")))
		}
		if len(dates) > 1 {
			fmt.Println("    [!] Components come from more than one release — the boot chain was")
			fmt.Println("        flashed in pieces, and the odd ones out are what a repair must replace.")
		}
	}

	// 4c. Hardware variant space, from the device's own utags. Only utags with
	// more than one option, or a fused hwid derivation, say anything about the
	// family — a fixed single-value utag is just this SKU restating itself.
	if r.HardwareFeatures != nil {
		var rows []fastboot.UTag
		for _, u := range r.HardwareFeatures.UTags {
			if len(u.Range) > 1 || u.HWIDMap != "" {
				rows = append(rows, u)
			}
		}
		if len(rows) > 0 {
			fmt.Println("\n  Hardware Variants (utags):")
			for _, u := range rows {
				val := u.Value
				if val == "" {
					val = "(unset)"
				}
				desc := val
				if len(u.Range) > 1 {
					desc = fmt.Sprintf("%s  of {%s}", val, strings.Join(u.Range, ", "))
				}
				if u.HWIDMap != "" {
					desc += "  [" + u.HWIDMap + "]"
				}
				printField(u.Name, desc)
			}
		}
	}

	// 5. Knowledge Base Matching
	var libMatch *fastboot.LibraryMatchResult
	var matchedDev *catalog.Device
	fmt.Println("\n  go-unbrick Knowledge Base:")
	matchedDev, _ = fastboot.MatchCatalog(cat, r)
	if matchedDev != nil {
		socDesc := matchedDev.CPUName
		// The Qualcomm LA baseline names the SoC family on its own, so it
		// resolves devices whose cpu_name the catalog does not carry.
		if resolved := cat.ResolveVariant(matchedDev.CPUName, r.QCBaseline); resolved != "" {
			socDesc = fmt.Sprintf("%s (%s)", matchedDev.CPUName, resolved)
		}
		fmt.Printf("    Catalog Match:       %s (%s) [%s]\n", matchedDev.Name, matchedDev.Codename, socDesc)

		libMatch = fastboot.CheckLibrary(lib, matchedDev, r)
		if len(libMatch.StockBuilds) > 0 {
			stockDesc := fmt.Sprintf("%d build(s) stored (%s)", len(libMatch.StockBuilds), strings.Join(libMatch.StockBuilds, ", "))
			switch {
			case libMatch.ExactStockMatch != "":
				stockDesc = fmt.Sprintf("%d build(s) stored [EXACT INSTALLED MATCH: %s]", len(libMatch.StockBuilds), libMatch.ExactStockMatch)
			case libMatch.BootChainMatch != "":
				stockDesc = fmt.Sprintf("%d build(s) stored [SAME XBL HASH: %s — packaged on another date / AP build]", len(libMatch.StockBuilds), libMatch.BootChainMatch)
			}
			fmt.Printf("    Library Stock:       %s\n", stockDesc)
			if len(libMatch.CIDCompatible) > 0 || len(libMatch.CIDForeign) > 0 {
				cidDesc := fmt.Sprintf("%d of %d build(s) declare cid %s", len(libMatch.CIDCompatible), len(libMatch.StockBuilds), r.CarrierID)
				if len(libMatch.CIDCompatible) > 0 {
					cidDesc += ": " + strings.Join(libMatch.CIDCompatible, ", ")
				}
				fmt.Printf("    CID Compatibility:   %s\n", cidDesc)
				if len(libMatch.CIDForeign) > 0 {
					fmt.Printf("        [!] Foreign CID, bootloader will refuse: %s\n", strings.Join(libMatch.CIDForeign, ", "))
				}
			}
		} else {
			fmt.Printf("    Library Stock:       None stored (use 'unbrick stock unpack' to add)\n")
		}

		if libMatch.LoaderCount > 0 {
			loaderDesc := fmt.Sprintf("%d available (e.g. %s)", libMatch.LoaderCount, libMatch.CandidateLoader)
			if libMatch.JTAGMatch {
				loaderDesc = fmt.Sprintf("%d available [EXACT JTAG SILICON MATCH: %s]", libMatch.LoaderCount, libMatch.CandidateLoader)
			}
			fmt.Printf("    Candidate Loaders:   %s\n", loaderDesc)
		} else {
			fmt.Printf("    Candidate Loaders:   None in library (use 'unbrick library add-loader' to add)\n")
		}
	} else {
		fmt.Println("    Catalog Match:       None (unknown codename/SKU)")
	}

	// 6. Action Recommendations
	fmt.Println("\n  Actionable Options:")
	if r.CurrentSlot == "a" {
		fmt.Println("    • Switch to slot B:          unbrick fastboot slot b")
	} else if r.CurrentSlot == "b" {
		fmt.Println("    • Switch to slot A:          unbrick fastboot slot a")
	}
	if build := stockBuildForInspect(libMatch); matchedDev != nil && build != "" {
		stockPath := lib.StockBuildDir(matchedDev.Vendor, matchedDev.Codename, build)
		if _, err := os.Stat(stockPath + "/gpt.bin"); err == nil {
			fmt.Printf("    • Inspect Stock GPT:         unbrick safeguard inspect %s/gpt.bin\n", stockPath)
		}
	}
	if len(r.LivePartitions) > 0 {
		fmt.Println("    • View Live Partitions:      unbrick fastboot partitions")
	}
	if edlRouteKnown(matchedDev) {
		edlLine := "    • Drop into EDL (9008):      unbrick fastboot edl"
		// On fogona (U1TF34.100-35-14) `oem blankflash` answers "Command
		// Restricted" on BOTH a locked and an unlocked unit — it is behind the
		// same factory/engineering-mode gate as the other restricted oem
		// commands, which the lock state does not touch. Flag it regardless of
		// lock so the operator is not sent to unlock in vain.
		if matchedDev != nil && matchedDev.Vendor == "motorola" {
			edlLine += "   [oem blankflash is factory-gated; unlocking will not lift it]"
		}
		fmt.Println(edlLine)
	}
	if strings.Contains(strings.ToLower(r.Fingerprint), "motorola") || strings.HasPrefix(r.CarrierID, "0x") {
		fmt.Println("    • Fetch OEM unlock data:     unbrick fastboot oem-unlock-data")
		if !r.Unlocked {
			fmt.Printf("      redeem the token at:       %s\n", motorolaUnlockPortal)
			if outlook := unlockOutlook(r, cat, lib); outlook != "" {
				fmt.Printf("      %s\n", outlook)
			}
		}
	}
	if raw {
		printRawDump(r)
	}
}

// printRawDump shows everything the device reported that the curated report leaves out:
// every getvar variable, and the oem-probe lines (cid_prov_req as a hex dump).
func printRawDump(r *fastboot.DeviceRecon) {
	fmt.Println("\n  Raw Device Output:")
	if len(r.RawVars) > 0 {
		fmt.Println("    getvar all:")
		keys := make([]string, 0, len(r.RawVars))
		for k := range r.RawVars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("      %s: %s\n", k, r.RawVars[k])
		}
	}
	if cp := r.CIDProvReq; cp != nil {
		fmt.Printf("    oem cid_prov_req (%d bytes):\n", len(cp.Raw))
		if len(cp.Raw) > 0 {
			for off := 0; off < len(cp.Raw); off += 16 {
				row := cp.Raw[off:min(off+16, len(cp.Raw))]
				var asc strings.Builder
				for _, b := range row {
					if b >= 32 && b < 127 {
						asc.WriteByte(b)
					} else {
						asc.WriteByte('.')
					}
				}
				fmt.Printf("      %04x: %-47s  %s\n", off, hexSpaced(row), asc.String())
			}
		} else {
			for _, l := range cp.RawLines {
				fmt.Printf("      %s\n", l)
			}
		}
	}
	if r.SecurityVersions != nil && len(r.SecurityVersions.RawLines) > 0 {
		fmt.Println("    oem read_sv:")
		for _, l := range r.SecurityVersions.RawLines {
			fmt.Printf("      %s\n", l)
		}
	}
}

func hexSpaced(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}

// stockBuildForInspect names the stored build worth pointing the operator at:
// the installed one, or failing that the one running the same boot chain.
func stockBuildForInspect(m *fastboot.LibraryMatchResult) string {
	if m == nil {
		return ""
	}
	if m.ExactStockMatch != "" {
		return m.ExactStockMatch
	}
	return m.BootChainMatch
}

func printField(label, val string) {
	if val != "" {
		fmt.Printf("    %-20s %s\n", label+":", val)
	}
}

func newFastbootSlotCmd(fastbootBin, serial *string) *cobra.Command {
	return &cobra.Command{
		Use:   "slot [a | b]",
		Short: "query active slot or switch to slot a / b",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := fastboot.NewClient(*fastbootBin)
			if err != nil {
				return err
			}

			if len(args) == 0 {
				slot, err := client.GetVar(*serial, "current-slot")
				if err != nil {
					return err
				}
				fmt.Printf("Current active slot: %s\n", slot)
				return nil
			}

			targetSlot := strings.TrimPrefix(strings.ToLower(args[0]), "_")
			if targetSlot != "a" && targetSlot != "b" {
				return fmt.Errorf("slot must be 'a' or 'b', got %q", args[0])
			}

			if err := client.SetActiveSlot(*serial, targetSlot); err != nil {
				return err
			}
			fmt.Printf("Switched active slot to '_%s'. Run 'fastboot reboot' to boot this slot.\n", targetSlot)
			return nil
		},
	}
}

func newFastbootEDLCmd(fastbootBin, serial *string) *cobra.Command {
	return &cobra.Command{
		Use:   "edl",
		Short: "command the device to reboot into Qualcomm Emergency Download (9008) mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := fastboot.NewClient(*fastbootBin)
			if err != nil {
				return err
			}

			targetSerial, err := resolveSerial(client, *serial)
			if err != nil {
				return err
			}
			if err := requireBootloader(client, targetSerial, "EDL entry"); err != nil {
				return err
			}
			drv, dev, err := identifyVendor(client, targetSerial)
			if err != nil {
				return err
			}
			cmds := vendor.EDLCommands(drv)
			if len(cmds) == 0 {
				return fmt.Errorf("%s (%s) has no known fastboot route into EDL; the hardware test point is the remaining option", dev, drv.ID())
			}

			fmt.Printf("Device identified as %s (%s driver). Instructing the bootloader into EDL (9008) with: %s\n",
				dev, drv.ID(), describeCommands(cmds))
			if err := client.RebootEDL(targetSerial, cmds); err != nil {
				return err
			}
			fmt.Println("Device transitioned to EDL. Screen should be off and enumerating as 05c6:9008.")
			return nil
		},
	}
}

// motorolaUnlockPortal is where the token from `oem get_unlock_data` is
// redeemed. The portal decides eligibility from the device's own CID, so a
// carrier-subsidised unit can produce a valid token and still be refused.
const motorolaUnlockPortal = "https://motorola-global-portal.custhelp.com/app/standalone/bootloader/unlock-your-device-a"

func newFastbootUnlockDataCmd(fastbootBin, serial *string) *cobra.Command {
	return &cobra.Command{
		Use:   "oem-unlock-data",
		Short: "retrieve Motorola OEM unlock token string for bootloader unlocking",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := fastboot.NewClient(*fastbootBin)
			if err != nil {
				return err
			}

			targetSerial, err := resolveSerial(client, *serial)
			if err != nil {
				return err
			}

			if err := requireBootloader(client, targetSerial, "'oem get_unlock_data'"); err != nil {
				return err
			}

			data, err := client.GetUnlockData(targetSerial)
			if err != nil {
				return err
			}

			fmt.Println("Motorola OEM Unlock Data:")
			fmt.Println(data)
			fmt.Printf("\nPaste this token string into Motorola's Unlock Your Bootloader portal:\n  %s\n", motorolaUnlockPortal)

			// Say up front whether the portal is likely to honour it, so a
			// refusal reads as the expected outcome rather than a failed step.
			if recon, err := client.GetVarAll(targetSerial); err == nil {
				if recon.Unlocked {
					fmt.Println("\nNote: this device already reports an unlocked bootloader.")
				} else if outlook := unlockOutlook(recon, activeCatalog(), library.Open(libraryDir())); outlook != "" {
					fmt.Printf("\nOutlook: %s\n", outlook)
				}
			}
			return nil
		},
	}
}

// newFastbootSetCIDCmd writes a chosen software channel to the cid partition via
// fastboot. Unlike the EDL route, this needs an unlocked bootloader — a locked
// Motorola bootloader rejects flashing cid, in which case `edl setcid` is the way.
func newFastbootSetCIDCmd(fastbootBin, serial *string) *cobra.Command {
	var yes, force bool
	c := &cobra.Command{
		Use:   "setcid <value>",
		Short: "flash a chosen software channel to the cid partition (needs unlocked bootloader)",
		Long: "Builds a Motorola CID image for <value> (e.g. 0x33 for cid51) and flashes it\n" +
			"to the cid partition. The bootloader must be in bootloader mode and unlocked;\n" +
			"a locked device rejects this — use `edl setcid` instead, which bypasses the lock.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: setcid <value> (value in hex 0x.. or decimal)")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			value, err := parseCIDValue(args[0])
			if err != nil {
				return err
			}
			client, err := fastboot.NewClient(*fastbootBin)
			if err != nil {
				return err
			}
			targetSerial, err := resolveSerial(client, *serial)
			if err != nil {
				return err
			}
			if err := requireBootloader(client, targetSerial, "cid flashing"); err != nil {
				return err
			}
			if force {
				fmt.Fprintln(os.Stderr, "! --force: skipping the unlock precheck; the device may still reject this")
			} else if recon, err := client.GetVarAll(targetSerial); err == nil && !recon.Unlocked {
				return fmt.Errorf("bootloader is locked; it will reject flashing cid. Use `edl setcid` (bypasses the lock), or --force to try anyway")
			}

			f, err := os.CreateTemp("", "cid-*.bin")
			if err != nil {
				return err
			}
			defer os.Remove(f.Name())
			if _, err := f.Write(cid.Build(value)); err != nil {
				f.Close()
				return err
			}
			f.Close()
			fmt.Printf("Built CID 0x%04X (%d bytes: %s)\n", value, cid.Size, filepath.Base(f.Name()))

			if !yes {
				fmt.Printf("\nAbout to flash the cid partition with 0x%04X. Type 'cid' to proceed: ", value)
				if !confirm("cid") {
					return fmt.Errorf("aborted")
				}
			}
			if err := client.Flash(targetSerial, "cid", f.Name()); err != nil {
				return err
			}
			fmt.Printf("cid set to 0x%04X\n", value)
			return nil
		},
	}
	c.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	c.Flags().BoolVar(&force, "force", false, "attempt the flash even if the bootloader reports locked (let the device reject it)")
	return c
}

// newFastbootHashCmd exposes the bootloader's own hashing of a partition in
// place: the one way to read a partition's content back on a device that will
// not dump it, since the digest crosses the wire instead of the image.
func newFastbootHashCmd(fastbootBin, serial *string) *cobra.Command {
	var algo, offset, size string
	c := &cobra.Command{
		Use:   "hash <partition>",
		Short: "hash a live partition in place ('fastboot oem partition sha256|md5')",
		Long: `Hash a partition on the device, without transferring it.

'oem partition md5|sha256' is present in Motorola's ABL but absent from its own
help output, and is refused on a locked device ("Command restricted!"). Offset
and size are passed through as given; the partition listing reports geometry in
KB, and this command does not reinterpret the values.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch strings.ToLower(algo) {
			case "sha256", "md5":
			default:
				return fmt.Errorf("unsupported algorithm %q (want sha256 or md5)", algo)
			}
			client, err := fastboot.NewClient(*fastbootBin)
			if err != nil {
				return err
			}
			targetSerial, err := resolveSerial(client, *serial)
			if err != nil {
				return err
			}
			if err := requireBootloader(client, targetSerial, "'oem partition "+strings.ToLower(algo)+"'"); err != nil {
				return err
			}
			d, err := client.OEMPartitionHash(targetSerial, strings.ToLower(algo), args[0], offset, size)
			switch {
			case errors.Is(err, fastboot.ErrOEMRestricted):
				// Observed identical on locked and unlocked fogona units, so do
				// not send the operator to unlock — it will not help.
				return err
			case err != nil:
				return err
			}
			rangeDesc := "whole partition"
			if d.Range != "" {
				rangeDesc = d.Range
			}
			fmt.Printf("%s %s (%s): %s\n", d.Partition, d.Algorithm, rangeDesc, d.Digest)
			return nil
		},
	}
	c.Flags().StringVar(&algo, "algo", "sha256", "digest algorithm: sha256 or md5")
	c.Flags().StringVar(&offset, "offset", "", "start offset, as the bootloader reads it (see 'fastboot partitions')")
	c.Flags().StringVar(&size, "size", "", "length to hash, requires --offset")
	return c
}

// confirmUnpopulated checks the empty-slot-B diagnosis, which is otherwise read
// off one text dump, against what the bootloader answers per partition. A
// disagreement matters more than the confirmation: it would mean the partitions
// are populated and something else is keeping slot B down.
func confirmUnpopulated(r *fastboot.DeviceRecon) string {
	if len(r.PartitionFacts) == 0 || len(r.UnpopulatedParts) == 0 {
		return ""
	}
	var disagree []string
	checked := 0
	for _, name := range r.UnpopulatedParts {
		f, ok := r.PartitionFacts[name]
		if !ok {
			continue
		}
		checked++
		if f.SizeBytes > 0 || !f.IsLogical {
			disagree = append(disagree, name)
		}
	}
	switch {
	case checked == 0:
		return ""
	case len(disagree) > 0:
		return fmt.Sprintf("[!] but the device reports these as present: %s — the emptiness is not confirmed", strings.Join(disagree, ", "))
	default:
		return fmt.Sprintf("Confirmed against the device: all %d report is-logical=yes, partition-size=0.", checked)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// sortedDatesDesc orders YYMMDD build dates newest first, so the current
// release leads and any straggler components read as the exception.
func sortedDatesDesc(dates map[string][]string) []string {
	out := make([]string, 0, len(dates))
	for d := range dates {
		out = append(out, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

// identifyVendor names the device from the catalog and hands back the driver
// that speaks for it, so vendor-specific commands are chosen rather than tried.
// A device the catalog does not carry falls back to the generic Qualcomm driver
// only when it looks like a Qualcomm target at all; nothing is assumed about a
// device that reports neither.
func identifyVendor(client *fastboot.Client, serial string) (vendor.Driver, string, error) {
	recon, err := client.GetVarAll(serial)
	if err != nil {
		return nil, "", err
	}
	if dev, _ := fastboot.MatchCatalog(activeCatalog(), recon); dev != nil {
		drv, ok := vendor.For(dev.Vendor)
		if !ok {
			return nil, "", fmt.Errorf("catalog names vendor %q for %s, but no driver is registered for it", dev.Vendor, dev.Codename)
		}
		return drv, fmt.Sprintf("%s (%s)", dev.Name, dev.Codename), nil
	}
	if recon.ChipID == "" && recon.UID == "" {
		return nil, "", fmt.Errorf("device %q is not in the catalog and reports no Qualcomm identity; refusing to guess its vendor", recon.Product)
	}
	drv, ok := vendor.For("qualcomm")
	if !ok {
		return nil, "", fmt.Errorf("no generic Qualcomm driver registered")
	}
	return drv, fmt.Sprintf("uncatalogued %q, JTAG %s", recon.Product, recon.JTAGID), nil
}

// unlockOutlook says whether the portal is likely to honour this device's token,
// from the one signal the device and library actually carry: the subsidy lock its
// CID ships. A channel that installs a subsidy-lock config is a carrier unit, and
// Motorola's portal declines those. This is an expectation drawn from the CID, not
// a recorded refusal, and it says so — the token costs nothing to try.
func unlockOutlook(r *fastboot.DeviceRecon, cat *catalog.Catalog, lib *library.Library) string {
	if r.CarrierID == "" {
		return ""
	}
	slcf := lib.CarrierIDs()[library.NormalizeCID(r.CarrierID)]
	name := cat.CarrierIDName(r.CarrierID)

	// Motorola's published allow-list decides it; the subsidy lock harvested from
	// firmware is independent corroboration, worth printing when it agrees and
	// worth knowing about when it is all we have.
	because := ""
	switch {
	case slcf != "":
		because = fmt.Sprintf(", and it ships subsidy lock %s (carrier unit)", slcf)
	case name != "":
		because = fmt.Sprintf(" (%s)", name)
	}

	if eligible, known := cat.UnlockEligible(r.CarrierID); known {
		if eligible {
			return fmt.Sprintf("eligible: cid %s is on Motorola's unlock allow-list%s", r.CarrierID, because)
		}
		return fmt.Sprintf("expect refusal: cid %s is absent from Motorola's unlock allow-list%s", r.CarrierID, because)
	}

	switch {
	case slcf != "":
		return fmt.Sprintf("expect refusal: cid %s ships subsidy lock %s (carrier unit) — untested, try anyway", r.CarrierID, slcf)
	case strings.Contains(strings.ToLower(name), "subsidy"):
		return fmt.Sprintf("expect refusal: cid %s is a subsidy channel (%s) — untested, try anyway", r.CarrierID, name)
	case name != "":
		return fmt.Sprintf("no subsidy lock recorded for cid %s (%s); eligibility unknown until tried", r.CarrierID, name)
	default:
		return fmt.Sprintf("cid %s is uncatalogued; nothing here predicts eligibility", r.CarrierID)
	}
}

// edlRouteKnown reports whether this device's vendor driver knows a fastboot
// route into EDL, so recon does not offer the option to a device that has none.
// An unmatched device keeps the offer: the generic Qualcomm routes are the best
// guess available, and trying is the only way to learn.
func edlRouteKnown(dev *catalog.Device) bool {
	if dev == nil {
		return true
	}
	drv, ok := vendor.For(dev.Vendor)
	return !ok || len(vendor.EDLCommands(drv)) > 0
}

func describeCommands(cmds [][]string) string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, "'fastboot "+strings.Join(c, " ")+"'")
	}
	return strings.Join(out, " then ")
}

// requireBootloader refuses a command that only the bootloader's fastboot
// serves. Run against userspace fastbootd the oem commands simply do not exist,
// and the device answers with a bare "Command failed" that reads as a defect
// rather than as being in the wrong fastboot.
func requireBootloader(client *fastboot.Client, serial, what string) error {
	if !client.InUserspace(serial) {
		return nil
	}
	return fmt.Errorf("%s is served by the bootloader, but this device is in userspace fastbootd (recovery)\n"+
		"Run 'fastboot reboot bootloader' and try again", what)
}

// resolveSerial picks the device to act on: the one asked for, or the only one
// attached.
func resolveSerial(client *fastboot.Client, serial string) (string, error) {
	if serial != "" {
		return serial, nil
	}
	devs, err := client.Devices()
	if err != nil {
		return "", err
	}
	if len(devs) == 0 {
		return "", fmt.Errorf("no fastboot devices detected")
	}
	return devs[0].Serial, nil
}

func newFastbootPartitionsCmd(fastbootBin, serial *string) *cobra.Command {
	var probe bool
	c := &cobra.Command{
		Use:   "partitions",
		Short: "query live partition geometry from device storage and display safeguard risk status",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := fastboot.NewClient(*fastbootBin)
			if err != nil {
				return err
			}

			targetSerial, err := resolveSerial(client, *serial)
			if err != nil {
				return err
			}
			if err := requireBootloader(client, targetSerial, "'oem partition'"); err != nil {
				return err
			}

			parts, unpop, unpopList, err := client.OEMPartitions(targetSerial)
			if err != nil {
				return fmt.Errorf("querying partitions from fastboot: %w\n(Note: requires device supporting 'fastboot oem partition')", err)
			}

			if len(parts) == 0 {
				fmt.Println("No partitions returned by device.")
				return nil
			}

			fmt.Printf("Live Partition Table (Device: %s)\n\n", targetSerial)
			fmt.Printf("%-3s %-20s %-12s %-14s %-10s %-15s %s\n",
				"", "PARTITION", "OFFSET", "SIZE", "TYPE", "RISK", "DESCRIPTION")
			fmt.Println(strings.Repeat("-", 95))

			// Offsets are per-LUN, so they restart several times down the table
			// and the same "128 KB" means a different place each time. A drop in
			// offset is where one LUN ends and the next begins; dynamic entries
			// all report super's offset and are exempt.
			// The dynamic/physical split in the listing is inferred from offsets
			// coinciding with super's. Probing replaces that guess with the
			// bootloader's own is-logical answer, and disagreement is worth
			// seeing rather than silently overwriting.
			var facts map[string]fastboot.PartitionFacts
			if probe {
				names := make([]string, 0, len(parts))
				for _, p := range parts {
					names = append(names, p.Name)
				}
				facts = client.ProbePartitions(targetSerial, names)
			}

			region, prevOffset := 0, uint64(0)
			lunHeader := func(n int) {
				fmt.Printf("    %s LUN %d %s\n", strings.Repeat("-", 8), n, strings.Repeat("-", 74))
			}

			for i, p := range parts {
				if !p.IsSuper {
					if i == 0 {
						lunHeader(region)
					} else if p.OffsetKB < prevOffset {
						region++
						lunHeader(region)
					}
					prevOffset = p.OffsetKB
				}
				meta := safeguard.Classify(p.Name)

				flag := " "
				riskStr := meta.Criticality
				if meta.Criticality == safeguard.CriticalityIrreplaceable {
					flag = "!"
					riskStr = "IRREPLACEABLE"
				} else if meta.Criticality == safeguard.CriticalityImportant {
					flag = "*"
					riskStr = "IMPORTANT"
				} else {
					riskStr = "Replaceable"
				}

				partType := "Physical"
				if p.IsSuper {
					partType = "Dynamic"
				}
				if f, ok := facts[p.Name]; ok {
					if f.IsLogical {
						partType = "Dynamic"
					} else if p.IsSuper {
						partType = "Dynamic?" // offset says super, the device says no
					} else {
						partType = "Physical"
					}
					if f.Type != "" && !strings.EqualFold(f.Type, "raw") {
						partType += "/" + f.Type
					}
				}

				offsetStr := formatOffsetKB(p.OffsetKB, p.IsSuper)
				sizeStr := formatSizeKB(p.SizeKB)
				if p.SizeKB == 0 {
					sizeStr = "0 KB (EMPTY)"
				}

				desc := meta.Description
				if desc == "" {
					desc = "Android system partition"
				}

				fmt.Printf("%-3s %-20s %-12s %-14s %-10s %-15s %s\n",
					flag, p.Name, offsetStr, sizeStr, partType, riskStr, desc)
			}
			fmt.Println(strings.Repeat("-", 95))

			if probe {
				fmt.Println("\nProbed from the bootloader: is-logical and partition-size are authoritative here,")
				fmt.Println("but ABL has no filesystem knowledge and answers partition-type 'raw' for everything.")
				fmt.Println("Real filesystem types come from userspace fastbootd ('fastboot reboot fastboot').")
			}

			if unpop {
				fmt.Printf("\n[!] Diagnostic Notice: Slot B dynamic partitions are unpopulated (0 KB):\n    %s\n    Slot B cannot boot without these OS system images.\n",
					strings.Join(unpopList, ", "))
			}

			return nil
		},
	}
	c.Flags().BoolVar(&probe, "probe", false,
		"ask the bootloader about each partition by name (partition-type, is-logical, has-slot); "+
			"these variables are absent from 'getvar all' but answer on a locked device")
	return c
}

func formatSizeKB(kb uint64) string {
	if kb == 0 {
		return "0 KB"
	}
	if kb < 1024 {
		return fmt.Sprintf("%d KB", kb)
	}
	if kb < 1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(kb)/1024)
	}
	return fmt.Sprintf("%.2f GB", float64(kb)/(1024*1024))
}

func formatOffsetKB(kb uint64, isSuper bool) string {
	if isSuper {
		return "(super)"
	}
	if kb < 1024 {
		return fmt.Sprintf("%d KB", kb)
	}
	if kb < 1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(kb)/1024)
	}
	return fmt.Sprintf("%.2f GB", float64(kb)/(1024*1024))
}
