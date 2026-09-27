package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/fastboot"
	"github.com/W-Floyd/go-unbrick/internal/library"
	"github.com/W-Floyd/go-unbrick/internal/safeguard"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
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
			return runFastbootRecon(fastbootBin, serial, false, false, "", false, "")
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
		newFastbootSetCIDCmd(&fastbootBin, &serial),
	)

	// Stack vendor-contributed subcommands onto the neutral tree; a neutral
	// command of the same name wins.
	taken := map[string]bool{}
	for _, sub := range cmd.Commands() {
		taken[sub.Name()] = true
	}
	cmd.AddCommand(vendor.FastbootCommands(&fastbootEnv{bin: &fastbootBin, serial: &serial}, taken)...)

	return cmd
}

// fastbootEnv adapts the command layer's helpers to vendor.FastbootEnv, so a
// vendor's contributed commands reach the client, serial resolution, and the
// catalog/library without importing the main package.
type fastbootEnv struct {
	bin    *string
	serial *string
}

func (e *fastbootEnv) Client() (*fastboot.Client, error) { return fastboot.NewClient(*e.bin) }

func (e *fastbootEnv) ResolveSerial(c *fastboot.Client) (string, error) {
	return resolveSerial(c, *e.serial)
}

func (e *fastbootEnv) RequireBootloader(c *fastboot.Client, serial, what string) error {
	return requireBootloader(c, serial, what)
}

func (e *fastbootEnv) InstallProfile(c *fastboot.Client, serial string) fastboot.Profile {
	return installProfile(c, serial)
}

func (e *fastbootEnv) Catalog() *catalog.Catalog { return activeCatalog() }

func (e *fastbootEnv) Library() *library.Library { return library.Open(libraryDir()) }

func newFastbootReconCmd(fastbootBin, serial *string) *cobra.Command {
	var raw, redact, noLearn bool
	var pin string
	var why string
	c := &cobra.Command{
		Use:   "recon",
		Short: "query device variables, audit dual-slot health, and cross-reference catalog & library",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFastbootRecon(*fastbootBin, *serial, raw, redact, why, noLearn, pin)
		},
	}
	c.Flags().StringVar(&why, "why", "", "explain how one fact was derived (e.g. --why soc), with every corroborating source")
	c.Flags().BoolVar(&raw, "raw", false, "also dump the device's raw output (every getvar var and oem probe line)")
	c.Flags().BoolVar(&redact, "redact", false, "mask per-device identifiers and secrets (serial, IMEI, UID, chip id, cid_prov_req digest, unlock challenge) for sharing")
	c.Flags().BoolVar(&noLearn, "no-learn", false, "do not record this device's non-identifying facts to the library knowledge store")
	c.Flags().StringVar(&pin, "pin", "", "tie this recon to a named device session (stitched with edl/adb/ssh recons of the same physical device under the same label)")
	return c
}

// colorEnabled is true when stdout is a terminal and NO_COLOR is unset, so the
// report stays plain text when piped or redirected.
var colorEnabled = func() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func paint(code, s string) string {
	if !colorEnabled || s == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func cGood(s string) string { return paint("32", s) }   // green
func cBad(s string) string  { return paint("31", s) }   // red
func cWarn(s string) string { return paint("33", s) }   // yellow
func cHdr(s string) string  { return paint("1", s) }    // bold — section headers
func cTag(s string) string  { return paint("1;36", s) } // bold cyan — verdict tags

// health paints a yes/no-style value by meaning, not literal truth: goodAffirm
// says whether the affirmative answer (yes/true/enabled/…) is the healthy one,
// so `Successful: yes` and `warranty void: no` both come out green. Unrecognized
// values pass through uncolored.
func health(val string, goodAffirm bool) string {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "yes", "true", "enabled", "ok", "1":
		return paintPolar(val, goodAffirm)
	case "no", "false", "disabled", "0":
		return paintPolar(val, !goodAffirm)
	default:
		return val
	}
}

func boolYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func paintPolar(s string, good bool) string {
	if good {
		return cGood(s)
	}
	return cBad(s)
}

// hwRevPhase expands a hardware build-phase code into a short gloss. hwrev names
// the unit's place on the prototype→production maturity ladder; Motorola stamps
// it with an optional trailing number (e.g. PVT1). Unknown values return "".
// Ladder: https://instrumental.com/build-better-handbook/evt-dvt-pvt
func hwRevPhase(rev string) string {
	r := strings.TrimRight(strings.ToUpper(strings.TrimSpace(rev)), "0123456789")
	switch r {
	case "EVT":
		return "Engineering Validation Test — early prototype"
	case "DVT":
		return "Design Validation Test — near-final design"
	case "PVT":
		return "Production Validation Test — production build"
	case "MP":
		return "Mass Production"
	case "PROTO", "P":
		return "prototype"
	default:
		return ""
	}
}

func runFastbootRecon(fastbootBin, serial string, raw, redact bool, why string, noLearn bool, pin string) error {
	client, err := fastboot.NewClient(fastbootBin)
	if err != nil {
		return err
	}
	client.SetProgress(stderrProgress())

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

		// Gather and print in two passes so output streams: the neutral getvar
		// sections appear immediately, the progress bar covers the paced OEM
		// probes, then the probe-fed and analysis sections follow.
		recon, drv, err := reconWithProfile(client, d.Serial)
		if err != nil {
			clearProgress()
			fmt.Fprintf(os.Stderr, "Error querying device %s: %v\n", d.Serial, err)
			continue
		}
		vendorID := ""
		if drv != nil {
			vendorID = drv.ID() // scopes the Motorola-only CID/carrier/channel lookups
		}
		printReconDeviceSections(d.Serial, recon, cat, lib, vendorID, redact)
		client.RunProbes(recon.Serial, recon)
		clearProgress()
		printReconAnalysis(client, recon, cat, lib, raw, redact, why, noLearn, pin)
	}

	return nil
}

// printReportSections prints vendor report sections produced by a profile's
// reporter, so the command layer stays vendor-agnostic.
func printReportSections(secs []fastboot.ReportSection) {
	for _, s := range secs {
		if s.Title != "" {
			fmt.Printf("\n%s\n", cHdr("  "+s.Title+":"))
		}
		for _, ln := range s.Lines {
			printField(ln.Label, ln.Value)
		}
		for _, n := range s.Notes {
			fmt.Printf("    %s\n", n)
		}
	}
}

// printReconDeviceSections prints everything derived from the single neutral
// `getvar all` (hardware, security, slots, firmware, boot-chain stamps). It runs
// before the paced OEM probes so this bulk streams out immediately; the probe-fed
// vendor sections and the local analysis follow in printReconAnalysis.
func printReconDeviceSections(serial string, r *fastboot.DeviceRecon, cat *catalog.Catalog, lib *library.Library, vendorID string, redact bool) {
	fmt.Printf("Fastboot Device: %s\n", mask(redact, serial))

	// 1. Hardware
	fmt.Println(cHdr("  Hardware:"))
	printField("Product / Board", r.Product)
	if p := hwRevPhase(r.HWRev); p != "" {
		printField("HW Revision", r.HWRev+" — "+p)
	} else {
		printField("HW Revision", r.HWRev)
	}
	printField("SKU", r.SKU)
	carrierDesc := r.Carrier
	if ch := cat.SoftwareChannelName(vendorID, r.Carrier); ch != "" {
		carrierDesc = fmt.Sprintf("%s — %s", r.Carrier, ch)
	}
	printField("Carrier", carrierDesc)
	cpuDesc := r.CPU
	if fields := strings.Fields(r.CPU); len(fields) > 0 {
		// getvar cpu is the qboot token plus a rev ("SM_DIVAR 1.0"); resolve the
		// token to its marketing SoC, same mapping the Catalog Match line uses.
		if soc := cat.ResolveVariant(fields[0], r.QCBaseline); soc != "" {
			cpuDesc = fmt.Sprintf("%s (%s)", r.CPU, soc)
		}
	}
	printField("CPU / SoC", cpuDesc)
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
		uidDesc := mask(redact, r.UID)
		if r.JTAGID != "" {
			// JTAG_ID is SoC-wide, not per-device — never redacted.
			uidDesc = fmt.Sprintf("%s (JTAG ID: %s)", mask(redact, r.UID), r.JTAGID)
		}
		printField("Silicon UID", uidDesc)
	}
	printField("Chip ID", mask(redact, r.ChipID))
	printField("IMEI", mask(redact, r.IMEI))
	printField("Manufactured", r.ManufactureDate)
	printField("Display Panel", r.PrimaryDisplay)
	if r.PCBPartNo != "" || r.BattID != "" {
		printField("Part Numbers", strings.TrimSpace(fmt.Sprintf("PCB %s  Battery %s", mask(redact, r.PCBPartNo), mask(redact, r.BattID))))
	}

	// 2. Security & Bootloader
	fmt.Println("\n" + cHdr("  Security & Bootloader:"))
	printField("Bootloader Version", r.BootloaderVersion)
	printField("XBL Build", r.XBLBuild)
	lockStr := cWarn("LOCKED")
	if r.Unlocked {
		lockStr = cGood("UNLOCKED")
	}
	if r.SecureState != "" {
		lockStr = fmt.Sprintf("%s (state: %s)", lockStr, r.SecureState)
	}
	printField("Lock Status", lockStr)
	cidDesc := r.CarrierID
	if norm := library.NormalizeCID(r.CarrierID); norm == "0xDEAD" || norm == "0xFFFF" {
		// A corrupt/tampered cid partition; ABL sets 0xDEAD and blocks AP fastboot.
		// Recoverable via `fastboot oem cid_prov_req` -> signed cid_prov_data.
		cidDesc = fmt.Sprintf("%s — %s", cidDesc, cBad("CORRUPT (0xDEAD): cid partition tampered, AP flashing blocked"))
	} else if name := cat.CarrierIDName(vendorID, r.CarrierID); name != "" {
		cidDesc = fmt.Sprintf("%s — %s", cidDesc, name)
	} else if slcf := lib.CarrierIDs()[library.NormalizeCID(r.CarrierID)]; slcf != "" {
		// Uncatalogued CID, but a stored package declared it: name it from that.
		cidDesc = fmt.Sprintf("%s — subsidy lock %s (from stored build)", cidDesc, slcf)
	} else if ref := cat.CarrierIDReference(vendorID, r.CarrierID); ref != "" {
		// Nothing attested; name it from the forum CID table (trusted for now).
		cidDesc = fmt.Sprintf("%s — %s", cidDesc, ref)
	}
	printField("Carrier ID (CID)", cidDesc)
	printField("Channel ID", r.ChannelID)
	printField("FRP State", r.FRPState)
	printField("Verity State", r.VerityState)
	printField("Life Cycle State", r.LCSState)
	printField("Unlock Token", r.TokenState)
	if r.FactoryModes != "" || r.WarrantyVoid != "" || r.FDRAllowed != "" {
		printField("Factory Flags", fmt.Sprintf("modes %s, warranty void %s, FDR allowed %s",
			orUnknown(r.FactoryModes), health(orUnknown(r.WarrantyVoid), false), orUnknown(r.FDRAllowed)))
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
		fmt.Println("\n" + cHdr("  Dual-Slot Health:"))
		if r.CurrentSlot != "" {
			printField("Active Slot", "_"+r.CurrentSlot)
		}
		for _, s := range []string{"a", "b"} {
			if info, ok := r.SlotStatus[s]; ok {
				status := cGood("Bootable")
				if !info.Bootable() {
					unboot := "UNBOOTABLE"
					hasUnbootableSlot = true
					if !info.Unbootable {
						// Derived, not flagged: say so, or the line reads as if
						// the bootloader had marked the slot itself.
						unboot += " — no retries left"
					}
					status = cBad(unboot)
				}
				fmt.Printf("    %-20s Slot %s: %s (Successful: %s, Retries: %d)\n",
					"", s, status, health(boolYesNo(info.Successful), true), info.RetryCount)
			}
		}
		if hasUnbootableSlot {
			fmt.Println("    " + cWarn("[!] Warning: An inactive slot is flagged UNBOOTABLE (update failed or retry limit exceeded)."))
		}
		// The vendor-specific root cause (e.g. Motorola's unpopulated 'super'
		// dynamic partitions) is rendered from the profile reporter, below.
	}

	// 4. Software Build
	if r.DisplayID != "" || r.Fingerprint != "" || r.Baseband != "" {
		fmt.Println("\n" + cHdr("  Installed Firmware:"))
		printField("Display ID", r.DisplayID)
		printField("Fingerprint", r.Fingerprint)
		printField("Baseband", r.Baseband)
		printField("Qualcomm Baseline", r.QCBaseline)
	}

	// 4b. Per-component boot chain stamps
	if dates := r.BootChainDates(); len(dates) > 0 {
		fmt.Println("\n" + cHdr("  Boot Chain Stamps:"))
		for _, d := range sortedDatesDesc(dates) {
			printField("Built "+d, fmt.Sprintf("%d component(s): %s", len(dates[d]), strings.Join(dates[d], ", ")))
		}
		if len(dates) > 1 {
			fmt.Println("    " + cWarn("[!] Components come from more than one release — the boot chain was"))
			fmt.Println("        " + cWarn("flashed in pieces, and the odd ones out are what a repair must replace."))
		}
	}
}

// printReconAnalysis prints the sections that depend on the slow paced OEM probes
// (vendor sections) plus the local catalog/library analysis. Split from the
// getvar-derived device sections so the latter can stream out before the probes
// run — see runFastbootRecon.
func printReconAnalysis(client *fastboot.Client, r *fastboot.DeviceRecon, cat *catalog.Catalog, lib *library.Library, raw, redact bool, why string, noLearn bool, pin string) {
	// 4c. Vendor-specific sections (sensors, anti-rollback, CID provisioning,
	// utag variant space) come from the installed profile's reporter — the
	// command layer prints them without naming a vendor.
	printReportSections(client.ReconSections(r, redact))

	// 5. Knowledge Base Matching
	var libMatch *fastboot.LibraryMatchResult
	var matchedDev *catalog.Device
	fmt.Println("\n" + cHdr("  go-unbrick Knowledge Base:"))
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
				stockDesc = fmt.Sprintf("%d build(s) stored [%s]", len(libMatch.StockBuilds), cTag("EXACT INSTALLED MATCH: "+libMatch.ExactStockMatch))
			case libMatch.BootChainMatch != "":
				stockDesc = fmt.Sprintf("%d build(s) stored [SAME XBL HASH: %s — packaged on another date / AP build]", len(libMatch.StockBuilds), libMatch.BootChainMatch)
			}
			fmt.Printf("    Library Stock:       %s\n", stockDesc)
			if len(libMatch.CIDCompatible) > 0 || len(libMatch.CIDForeign) > 0 {
				fit := len(libMatch.CIDCompatible)
				fmt.Printf("    CID Compatibility:   device CID %s — %d of %d stored build(s) will flash\n",
					r.CarrierID, fit, len(libMatch.StockBuilds))
				if fit > 0 {
					fmt.Printf("        %s\n", cGood("✓ flashable (CID matches):    "+strings.Join(libMatch.CIDCompatible, ", ")))
				}
				if len(libMatch.CIDForeign) > 0 {
					// CIDForeign entries already carry their own "(0x…)" CID suffix.
					fmt.Printf("        %s\n", cBad("✗ refused (foreign CID):      "+strings.Join(libMatch.CIDForeign, ", ")))
				}
			}
		} else {
			fmt.Printf("    Library Stock:       None stored (use 'unbrick stock unpack' to add)\n")
		}

		if libMatch.LoaderCount > 0 {
			loaderDesc := fmt.Sprintf("%d available (e.g. %s)", libMatch.LoaderCount, libMatch.CandidateLoader)
			if libMatch.JTAGMatch {
				loaderDesc = fmt.Sprintf("%d available [%s]", libMatch.LoaderCount, cTag("EXACT JTAG SILICON MATCH: "+libMatch.CandidateLoader))
			}
			fmt.Printf("    Candidate Loaders:   %s\n", loaderDesc)
		} else {
			fmt.Printf("    Candidate Loaders:   None in library (use 'unbrick library add-loader' to add)\n")
		}
	} else {
		fmt.Println("    Catalog Match:       None (unknown codename/SKU)")
	}

	// 6. Action Recommendations
	fmt.Println("\n" + cHdr("  Actionable Options:"))
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
	if _, ok := client.Profile().(vendor.PartitionLister); ok {
		fmt.Println("    • View Live Partitions:      unbrick fastboot partitions")
	}
	if edlRouteKnown(matchedDev) {
		edlLine := "    • Drop into EDL (9008):      unbrick fastboot edl"
		// On fogona (U1TF34.100-35-14) `oem blankflash` answers "Command
		// Restricted" on BOTH a locked and an unlocked unit — it is behind the
		// same factory/engineering-mode gate as the other restricted oem
		// commands, which the lock state does not touch. Flag it regardless of
		// lock so the operator is not sent to unlock in vain.
		if note := client.EDLNote(); note != "" {
			edlLine += "   [" + note + "]"
		}
		fmt.Println(edlLine)
	}
	if udp, ok := client.Profile().(vendor.UnlockDataProvider); ok {
		fmt.Println("    • Fetch OEM unlock data:     unbrick fastboot oem-unlock-data")
		if !r.Unlocked {
			fmt.Printf("      redeem the token at:       %s\n", udp.UnlockPortal())
			if outlook := udp.UnlockOutlook(r, cat, lib); outlook != "" {
				fmt.Printf("      %s\n", outlook)
			}
		}
	}
	// 7. Cross-checks. Everything above is what the device said; this is what the
	// derivation graph makes of it — the same graph the file-side recon runs, so a
	// device fact and a package fact are checked against each other by one set of
	// rules. Only the judgments print here; the values already have their sections.
	printDeviceFacts(r, cat, why, redact, noLearn, pin)

	if raw {
		printRawDump(client, r, redact)
	}
}

// printDeviceFacts resolves the collected recon through the derivation graph and
// prints what it found wrong, plus a --why trace when one was asked for.
func printDeviceFacts(r *fastboot.DeviceRecon, cat *catalog.Catalog, why string, redact, noLearn bool, pin string) {
	bag := facts.NewBag()
	facts.Set(bag, fastboot.SourceRecon, r,
		facts.Provenance{Source: "getvar all", Authority: facts.Attested})
	if cat != nil {
		facts.Set(bag, facts.SourceCatalog, cat,
			facts.Provenance{Source: "catalog", Authority: facts.Reference})
	}
	res := reconGraph().ResolveAll(bag, facts.Options{})
	if len(res.Findings) > 0 {
		fmt.Println("\n" + cHdr("  Cross-checks:"))
		printFindings(res.Findings)
	}
	if why != "" {
		fmt.Println("\n" + cHdr("  Derivation of "+why+":"))
		for _, line := range facts.Explain(bag, why) {
			fmt.Println("    " + mask(redact, line))
		}
	}
	if !noLearn {
		learnFromRecon(bag, pin, []string{r.Serial})
	}
}

// sensitiveVar names getvar variables that carry a per-device identifier, masked under
// --redact so a shared raw dump does not leak them.
var sensitiveVar = map[string]bool{
	"imei": true, "imei2": true, "meid": true, "uid": true, "chipid": true,
	"serialno": true, "serial": true, "battid": true, "iccid": true, "esimid": true,
}

// printRawDump shows everything the device reported that the curated report leaves out:
// every getvar variable, and the oem-probe lines (cid_prov_req as a hex dump).
func printRawDump(client *fastboot.Client, r *fastboot.DeviceRecon, redact bool) {
	fmt.Println("\n" + cHdr("  Raw Device Output:"))
	if len(r.RawVars) > 0 {
		fmt.Println("    getvar all:")
		keys := make([]string, 0, len(r.RawVars))
		for k := range r.RawVars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := r.RawVars[k]
			if sensitiveVar[strings.ToLower(k)] {
				v = mask(redact, v)
			}
			fmt.Printf("      %s: %s\n", k, v)
		}
	}
	// Vendor raw output (OEM command bytes) from the installed profile's reporter.
	printReportSections(client.RawSections(r, redact))
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

// mask hides the middle of a per-device identifier or secret, keeping enough at each
// end to correlate two dumps without exposing the full value. Only when redact is set.
func mask(redact bool, s string) string {
	if !redact || s == "" {
		return s
	}
	if len(s) <= 8 {
		return strings.Repeat("•", len(s))
	}
	return s[:4] + "…" + s[len(s)-4:]
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
			if _, err := f.Write(vendor.CIDBuild(value)); err != nil {
				f.Close()
				return err
			}
			f.Close()
			fmt.Printf("Built CID 0x%04X (%d bytes: %s)\n", value, vendor.CIDSize, filepath.Base(f.Name()))

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
			prof := installProfile(client, targetSerial)
			ph, ok := prof.(vendor.PartitionHasher)
			if !ok {
				return fmt.Errorf("this device's fastboot profile (%s) has no partition-hash command", prof.Name())
			}
			d, err := ph.OEMPartitionHash(client, targetSerial, strings.ToLower(algo), args[0], offset, size)
			switch {
			case errors.Is(err, vendor.ErrOEMRestricted):
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
// driverForRecon picks the vendor driver for a recon: catalog match first, else
// the generic Qualcomm driver when the device shows a Qualcomm identity, else nil.
func driverForRecon(recon *fastboot.DeviceRecon) vendor.Driver {
	if dev, _ := fastboot.MatchCatalog(activeCatalog(), recon); dev != nil {
		if drv, ok := vendor.For(dev.Vendor); ok {
			return drv
		}
	}
	if recon.ChipID != "" || recon.UID != "" {
		if drv, ok := vendor.For("qualcomm"); ok {
			return drv
		}
	}
	return nil
}

// reconWithProfile runs the neutral getvar all, resolves the device's vendor
// driver, and installs its fastboot profile. The vendor recon probes are left
// for the caller to run (RunProbes) so device sections can print in between.
func reconWithProfile(client *fastboot.Client, serial string) (*fastboot.DeviceRecon, vendor.Driver, error) {
	recon, err := client.GetVarAll(serial)
	if err != nil {
		return nil, nil, err
	}
	drv := driverForRecon(recon)
	client.UseProfile(vendor.FastbootProfile(drv))
	// Probes are run by the caller (RunProbes) after the neutral getvar sections
	// have been printed, so recon output streams rather than blocking on the
	// paced OEM probes. See runFastbootRecon.
	return recon, drv, nil
}

// installProfile resolves and installs the vendor fastboot profile for a live
// device, returning it so a caller can assert a capability (unlock-data,
// partition hash/list). It is the seam that keeps vendor commands out of the
// command layer's own logic.
func installProfile(client *fastboot.Client, serial string) fastboot.Profile {
	var drv vendor.Driver
	if recon, err := client.GetVarAll(serial); err == nil {
		drv = driverForRecon(recon)
	}
	p := vendor.FastbootProfile(drv)
	client.UseProfile(p)
	return p
}

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

			prof := installProfile(client, targetSerial)
			pl, ok := prof.(vendor.PartitionLister)
			if !ok {
				return fmt.Errorf("this device's fastboot profile (%s) has no partition listing", prof.Name())
			}
			parts, unpop, unpopList, err := pl.OEMPartitions(client, targetSerial)
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
