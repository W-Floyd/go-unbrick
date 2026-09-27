package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
	"github.com/W-Floyd/go-unbrick/internal/library"
	"github.com/W-Floyd/go-unbrick/internal/transport"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// The half of a device recon that does not care how the device was reached.
// Whatever the route — a bootloader over fastboot, a Linux distribution over
// ssh, an Android userspace over adb — the shape is the same: collect the
// route's source facts, render what that route uniquely knows, optionally read
// the identity partitions, then resolve the graph and print its judgments.
//
// So that shape is written once here, and a transport's command contributes
// only the part that is genuinely its own: its report sections.

// deviceReconFlags are the knobs every transport recon shares.
type deviceReconFlags struct {
	raw       bool
	redact    bool
	verify    bool
	why       string
	readParts bool
	readCap   uint64
	// saveParts is a directory to write each read partition into as
	// <name>.img, in the layout forge --target-parts consumes — so a live
	// device's own boot chain can seed a blankflash. Implies --read-partitions.
	saveParts string
	// against is a firmware package to read into the same Bag as the device.
	// A file is a route like any other (see imgfacts.File), so comparing a
	// device with the firmware it should be running needs no comparison code:
	// both sides' facts land in one Bag and the graph's same-fact pass does it.
	against string
	// noLearn disables the default accumulation of a device's non-identifying
	// facts into the library knowledge store.
	noLearn bool
	// pin ties this recon to a named device session: every route reconned under
	// the same --pin label is stitched into one matching set, because the
	// operator has declared them the same physical unit.
	pin string
}

// register declares the shared flags on a command.
func (f *deviceReconFlags) register(c *cobra.Command) {
	c.Flags().StringVar(&f.why, "why", "", "explain how one fact was derived (e.g. --why soc), with every corroborating source")
	c.Flags().BoolVar(&f.raw, "raw", false, "also dump everything the device returned, unparsed")
	c.Flags().BoolVar(&f.redact, "redact", false, "mask per-device identifiers (serial, IMEI, hostname) for sharing")
	c.Flags().BoolVar(&f.verify, "verify", false, "run redundant derivations for their cross-check value")
	c.Flags().BoolVar(&f.readParts, "read-partitions", false,
		"read the identity and boot-chain partitions and derive from their content (needs root on the device)")
	c.Flags().Uint64Var(&f.readCap, "read-cap", transport.DefaultReadCap, "skip partitions larger than this many bytes when reading")
	c.Flags().StringVar(&f.saveParts, "save", "",
		"write each read partition to this dir as <name>.img (forge --target-parts layout); implies --read-partitions")
	c.Flags().StringVar(&f.against, "against", "",
		"also read a firmware package/image into the same recon, so device and firmware cross-check each other")
	c.Flags().BoolVar(&f.noLearn, "no-learn", false,
		"do not record this device's non-identifying facts to the library knowledge store")
	c.Flags().StringVar(&f.pin, "pin", "",
		"tie this recon to a named device session: recons of the one physical device across edl/adb/fastboot/ssh under the same label are stitched into one matching set")
}

// reader is the optional capability of settling privileges before a run of
// reads, so a route that cannot read any partition says so once rather than
// discovering it per partition.
type readPreparer interface{ PrepareReads() error }

// runTransportRecon is the whole recon over one route. printSections renders
// what that route knows and nothing else; everything here is common.
func runTransportRecon(tr transport.Transport, f deviceReconFlags, printSections func()) error {
	defer tr.Close()

	bag := facts.NewBag()
	if cat := activeCatalog(); cat != nil {
		facts.Set(bag, facts.SourceCatalog, cat,
			facts.Provenance{Source: "catalog", Authority: facts.Reference})
	}
	gaps := tr.Sources(bag)

	// The firmware the device is supposed to be running, read as a second route
	// into the same Bag. Nothing here compares the two: every fact both sides
	// produce is compared by the graph, and the disagreements print with the
	// rest of the cross-checks.
	if f.against != "" {
		bar := newBar()
		file := &imgfacts.File{Path: f.against, Recognizers: reconRecognizers(), Progress: bar}
		gaps = append(gaps, file.Sources(bag)...)
		bar.Clear()
		fmt.Printf("Against: %s\n", file.Describe())
	}

	printSections()

	var readErrs []error
	if f.readParts || f.saveParts != "" { // --save implies a read
		readErrs = ingestTransportPartitions(tr, bag, f)
	}
	if f.readParts {
		recoverStockFirmware(tr, bag)
	}

	res := reconGraph().ResolveAll(bag, facts.Options{Verify: f.verify})

	fmt.Println("\n" + cHdr("  Facts:"))
	printIdentityFacts(bag, "    ")
	if !f.readParts {
		// Only where there is a table to read from: EDL without a loader has
		// the capability but no Firehose session to use it.
		lister, listed := tr.(transport.PartitionLister)
		if _, ok := tr.(transport.PartitionReader); ok && listed && len(lister.Partitions()) > 0 {
			fmt.Println("    " + cWarn("(bootloader-level identity — CID, signing, anti-rollback — needs --read-partitions)"))
		}
	}
	if len(res.Findings) > 0 {
		fmt.Println("\n" + cHdr("  Cross-checks:"))
		printFindings(res.Findings)
	}
	for _, err := range readErrs {
		fmt.Println(cWarn("  [!] " + err.Error()))
	}
	printFindings(gaps)

	if f.why != "" {
		fmt.Println("\n" + cHdr("  Derivation of "+f.why+":"))
		for _, line := range facts.Explain(bag, f.why) {
			fmt.Println("    " + mask(f.redact, line))
		}
	}

	if !f.noLearn {
		learnFromRecon(bag, f.pin, transportSerials(tr))
	}
	return nil
}

// transportSerials is every stable hardware id the route exposes (serial,
// storage serial, chip serial), for auto-stitching a session; nil otherwise.
func transportSerials(tr transport.Transport) []string {
	if s, ok := tr.(interface{ DeviceSerials() []string }); ok {
		return s.DeviceSerials()
	}
	return nil
}

// learnFromRecon folds the recon's non-identifying facts into the library
// knowledge store, keyed by the device's stable model name (codename, else
// JTAG). With a pin label it first merges this route's facts into that named
// device session and commits the accumulated union instead, so recons of one
// physical unit across routes stitch into a single matching set. It is
// best-effort: a device with neither key, or a write failure, is silently
// skipped — learning must never break a recon.
func learnFromRecon(bag *facts.Bag, pin string, serials []string) {
	key := "" // codename is the model-level key; JTAG is the fallback
	if v, ok := facts.Get(bag, facts.Codename); ok {
		key = v
	}
	vendorID := ""
	if v, ok := facts.Get(bag, facts.OEMID); ok {
		if drv, ok := vendor.ForOEMID(v); ok {
			vendorID = drv.ID()
		}
	}
	// Over ssh/adb the OEM_ID is not derived (it needs a partition read), so
	// fall back to the catalog's own vendor for this codename.
	if vendorID == "" && key != "" {
		if dev, ok := activeCatalog().Device(key); ok {
			vendorID = dev.Vendor
		}
	}
	if key == "" {
		if v, ok := facts.Get(bag, facts.JTAGID); ok {
			key = v
		}
	}
	lib := library.Open(libraryDir())
	learned := facts.Learnable(bag)

	// Stitching commits the union of a session's routes rather than each partial
	// set, so the growing full tuple subsumes the partials. An explicit --pin
	// groups by a label; otherwise the hardware ids do it automatically — recons
	// of one unit share a serial or storage serial and merge on their own. The
	// ids are hashed, never stored; the committed knowledge stays raw and
	// non-identifying.
	stitched := ""
	switch {
	case pin != "":
		p, conflict, err := lib.AddToPin(pin, vendorID, key, learned)
		if err != nil {
			return
		}
		if conflict != "" {
			fmt.Printf("\n  %s pin %q holds %s, but this device is %s — not stitched; use a different --pin\n",
				cWarn("[!]"), pin, conflict, orUnknown(key))
			return
		}
		key, vendorID, learned = p.Key, p.Vendor, p.Facts
		stitched = fmt.Sprintf(" (pin %q, %d fact(s) stitched)", pin, len(learned))
	default:
		if hashes := hashedIDs(serials); len(hashes) > 0 && key != "" {
			if p, err := lib.AddToPinAuto(vendorID, key, hashes, learned); err == nil && p != nil {
				key, vendorID, learned = p.Key, p.Vendor, p.Facts
				stitched = fmt.Sprintf(" (stitched with this unit's other recons, %d fact(s))", len(learned))
			}
		}
	}
	if key == "" {
		return
	}
	added, err := lib.Learn(vendorID, key, learned)
	if err != nil {
		return
	}
	if len(added) > 0 {
		fmt.Printf("\n  knowledge %s: learned %d new fact(s)%s\n", key, len(added), stitched)
	}
}

// hashedIDs turns raw hardware serials into stable hashes, so a session can be
// stitched by identity without the serials ever being stored.
func hashedIDs(serials []string) []string {
	var out []string
	for _, s := range serials {
		if s == "" {
			continue
		}
		sum := sha256.Sum256([]byte("unbrick-serial:" + s))
		out = append(out, hex.EncodeToString(sum[:])[:12])
	}
	return out
}

// stockRecoverer is a route that can recover the stock firmware's build.prop
// from a device whose booted OS is not the stock one (ssh to a live/SD-booted
// phone, where the original Android is intact on the internal disk).
type stockRecoverer interface {
	RecoverStockProps() map[string]string
}

// stockPropToFact maps a recovered build.prop key onto the fact it feeds.
var stockPropToFact = map[string]facts.Fact[string]{
	"ro.build.fingerprint":            facts.BuildFingerprint,
	"ro.system.build.fingerprint":     facts.SystemFingerprint,
	"ro.build.version.security_patch": facts.SecurityPatch,
	"ro.build.date":                   facts.BuildDate,
}

// recoverStockFirmware folds the stock firmware facts read off the internal
// disk into the bag, so a device booted into another OS still learns the
// firmware it shipped with. Attested: it is the on-disk build.prop, not a guess.
func recoverStockFirmware(tr transport.Transport, bag *facts.Bag) {
	sr, ok := tr.(stockRecoverer)
	if !ok {
		return
	}
	props := sr.RecoverStockProps()
	if len(props) == 0 {
		return
	}
	n := 0
	for key, val := range props {
		if f, ok := stockPropToFact[key]; ok {
			facts.Set(bag, f, val, facts.Provenance{Source: "internal stock build.prop", Authority: facts.Attested})
			n++
		}
	}
	if n > 0 {
		fmt.Printf("\n  %s %d fact(s) recovered from the untouched internal firmware\n", cHdr("Stock Firmware:"), n)
	}
}

// ingestTransportPartitions reads the identity partitions this route can reach
// and folds what they *are* into the Bag — the same recognizers a firmware
// package's members go through, so a live read and a packaged image derive
// facts by one set of rules.
func ingestTransportPartitions(tr transport.Transport, bag *facts.Bag, f deviceReconFlags) []error {
	lister, ok := tr.(transport.PartitionLister)
	if !ok {
		return []error{fmt.Errorf("--read-partitions: the %s route does not know the partition table", tr.Name())}
	}
	reader, ok := tr.(transport.PartitionReader)
	if !ok {
		// fastboot is the case: it will describe a partition all day and never
		// hand one over. Saying which route *would* is more use than the refusal.
		return []error{fmt.Errorf("--read-partitions: the %s route cannot read partition bytes — boot the device into Linux (ssh) or Android (adb), or use EDL", tr.Name())}
	}
	if p, ok := tr.(readPreparer); ok {
		if err := p.PrepareReads(); err != nil {
			return []error{fmt.Errorf("--read-partitions: %w", err)}
		}
	}
	parts := transport.IdentityPartitions(lister.Partitions(), lister.Slot(), f.readCap)
	if len(parts) == 0 {
		return []error{fmt.Errorf("--read-partitions found nothing to read (no identity partitions in the live table under the %s cap)",
			formatSizeKB(f.readCap/1024))}
	}
	var save func(transport.Partition, []byte) error
	if f.saveParts != "" {
		if err := os.MkdirAll(f.saveParts, 0o755); err != nil {
			return []error{fmt.Errorf("--save: %w", err)}
		}
		save = func(p transport.Partition, data []byte) error {
			return os.WriteFile(filepath.Join(f.saveParts, p.Name+".img"), data, 0o644)
		}
	}
	bar := newBar()
	bar.Begin(len(parts))
	set, errs := transport.Ingest(reader, tr.Describe(), bag, reconRecognizers(), parts, f.readCap,
		func(i, n int, p transport.Partition) {
			if i > 0 {
				bar.Advance()
			}
			bar.Describe(fmt.Sprintf("reading %s (%s)", p.Name, formatSizeKB(p.SizeBytes/1024)))
		}, save)
	bar.Advance()
	bar.Clear()
	if f.saveParts != "" && len(set) > 0 {
		fmt.Printf("\n  Saved %d partition(s) to %s (forge --target-parts %s)\n", len(set), f.saveParts, f.saveParts)
	}

	if len(set) > 0 {
		fmt.Println("\n" + cHdr("  Partitions Read:"))
		for _, name := range sortedKeys(set) {
			printField(name, strings.Join(set[name], ", "))
		}
	}
	return errs
}

// printPartitionSections renders what any route that knows the table can show:
// the protected/identity partitions, and what a read would cover.
func printPartitionSections(tr transport.Transport, readCap uint64) {
	lister, ok := tr.(transport.PartitionLister)
	if !ok {
		return
	}
	parts := lister.Partitions()
	if len(parts) == 0 {
		return
	}
	cat := activeCatalog()
	printField("Partitions", fmt.Sprintf("%d in the live table", len(parts)))
	// Only the protected ones, the way the fastboot GPT traversal reports: the
	// identity and calibration partitions are what a repair must not lose, and
	// the rest is a wall of names.
	var shown []string
	var sized int
	for _, p := range parts {
		if p.SizeBytes > 0 {
			sized++
		}
		if !cat.IsProtected(p.Base()) {
			continue
		}
		// A size of 0 is a size the device would not report (an unrooted adb
		// shell cannot read /sys/class/block), not an empty partition — so it is
		// left out rather than printed as "0 KB".
		if p.SizeBytes == 0 {
			shown = append(shown, p.Name)
		} else {
			shown = append(shown, fmt.Sprintf("%s (%s)", p.Name, formatSizeKB(p.SizeBytes/1024)))
		}
	}
	if sized == 0 {
		printField("Sizes", cWarn("not readable by this login — partition sizes need root"))
	}
	if len(shown) > 0 {
		fmt.Printf("    %-20s %s\n", "Protected:", strings.Join(shown, ", "))
	}
	// What --read-partitions would fetch, named up front: the operator should
	// know what a read covers before asking for it.
	if _, canRead := tr.(transport.PartitionReader); !canRead {
		return
	}
	if sel := transport.IdentityPartitions(parts, lister.Slot(), readCap); len(sel) > 0 {
		var names []string
		for _, p := range sel {
			names = append(names, p.Name)
		}
		printField("Readable Identity", fmt.Sprintf("%d under the %s cap: %s",
			len(names), formatSizeKB(readCap/1024), strings.Join(names, ", ")))
	}
}
