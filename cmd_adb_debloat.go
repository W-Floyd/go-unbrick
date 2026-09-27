package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/adb"
	"github.com/W-Floyd/go-unbrick/internal/bloat"
)

// Debloating over adb. The whole feature rests on one property: `pm uninstall
// --user 0` removes a package *for the current user* and nothing else. No
// partition is written, dm-verity and the bootloader lock are untouched, the
// APK stays in the image, and `install-existing` (or a factory reset) puts it
// back. That is why this can be offered for a locked, unrooted, carrier-subsidy
// device at all — and why it must never grow into anything that flashes.
//
// The command prints a plan and stops. Applying is a separate act, gated on
// --apply plus a typed confirmation, and it writes a record that --restore
// reads back.
func newADBDebloatCmd(o *adb.Options) *cobra.Command {
	var apply, yes, listAll, showUnknown bool
	var cats []string
	var maxRisk string
	var only, record, restore string

	c := &cobra.Command{
		Use:   "debloat",
		Short: "list and remove preloaded carrier/OEM packages (per-user, reversible, no root)",
		Long: `Remove preloaded packages for the current user over adb.

Every removal is ` + "`pm uninstall --user 0`" + `: a per-user state change that writes no
partition, leaves dm-verity and the bootloader lock alone, and is undone by
--restore or by a factory reset. No root, no unlocked bootloader, no flashing.

The default run prints a plan and changes nothing. What may be proposed comes
from catalog/bloat.yaml, read off a real device rather than a forum list; a
package the table does not name is reported as unknown and never proposed.
Telephony, IMS, provisioning, setup and the carrier-unlock client are protected
in code, so editing the catalog cannot select them.

Selection has two axes. --category says what to consider: ads (the sponsored-app
installers), preload (third-party apps the channel shipped), oem-extra (the
manufacturer's optional software), carrier (this unit's own carrier apps),
carrier-foreign (another carrier's client on this unit), updates (the OTA
machinery). --max-risk says how much a removal may cost: safe (nothing depends
on it), caution (a named feature goes away), invasive (activation, updates or a
carrier feature).

The default is ads,preload,oem-extra at risk safe — everything nothing depends
on. Anything that costs a feature is listed with what it costs, and waits to be
asked for. carrier, carrier-foreign and updates stay out of the default because
those categories carry a consequence no risk label captures.

    unbrick adb debloat                          # the plan, nothing else
    unbrick adb debloat --list                   # every package, classified
    unbrick adb debloat --apply                  # everything safe
    unbrick adb debloat --max-risk caution --apply
    unbrick adb debloat --category updates --max-risk invasive --apply
    unbrick adb debloat --only com.einnovation.temu --apply
    unbrick adb debloat --restore debloat-ZL83.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if restore != "" {
				return runADBRestore(*o, restore, yes)
			}
			selected, err := bloat.ParseCategories(cats)
			if err != nil {
				return err
			}
			if len(selected) == 0 {
				selected = bloat.DefaultCategories()
			}
			risk, err := bloat.ParseRisk(maxRisk)
			if err != nil {
				return err
			}
			return runADBDebloat(*o, debloatOpts{
				categories:  selected,
				maxRisk:     risk,
				only:        splitList(only),
				apply:       apply,
				yes:         yes,
				listAll:     listAll,
				showUnknown: showUnknown,
				record:      record,
			})
		},
	}
	c.Flags().StringArrayVar(&cats, "category", nil,
		"categories to consider: ads, preload, oem-extra, carrier, carrier-foreign, updates (default ads,preload,oem-extra)")
	c.Flags().StringVar(&maxRisk, "max-risk", string(bloat.DefaultMaxRisk()),
		"how much a removal may cost: safe (nothing depends on it), caution (a named feature goes away), invasive (activation, updates or a carrier feature)")
	c.Flags().StringVar(&only, "only", "", "comma-separated package names to act on, instead of whole categories")
	c.Flags().BoolVar(&apply, "apply", false, "actually remove the packages in the plan (default: print the plan and stop)")
	c.Flags().BoolVar(&yes, "yes", false, "skip the typed confirmation")
	c.Flags().BoolVar(&listAll, "list", false, "list every installed package with its classification")
	c.Flags().BoolVar(&showUnknown, "unknown", false, "list the packages the catalog does not name (what to add to it)")
	c.Flags().StringVar(&record, "record", "", "where to write the undo record (default debloat-<serial>.json in the working directory)")
	c.Flags().StringVar(&restore, "restore", "", "reinstall every package listed in a record written by a previous --apply")
	return c
}

type debloatOpts struct {
	categories  []bloat.Category
	maxRisk     bloat.Risk
	only        []string
	apply       bool
	yes         bool
	listAll     bool
	showUnknown bool
	record      string
}

func runADBDebloat(o adb.Options, f debloatOpts) error {
	dev, err := adb.Open(o)
	if err != nil {
		return err
	}
	defer dev.Close()

	progressLine("listing packages…")
	pkgs, err := adb.Packages(dev.C)
	clearProgressLine()
	if err != nil && len(pkgs) == 0 {
		return err
	}

	// Scoped to this device's OEM: a com.motorola.* rule has nothing to say
	// about a Samsung, and an out-of-scope rule is dropped rather than trusted.
	table := bloat.New(activeCatalog().Bloat(), dev.R.VendorID())
	plan := table.Build(dev.R.Serial, inventory(pkgs), f.categories, f.maxRisk)

	fmt.Printf("Android Device: %s", mask(false, dev.R.Serial))
	if fp := dev.R.Props["ro.build.display.id"]; fp != "" {
		fmt.Printf("  (%s, carrier %s)", fp, orUnknown(dev.R.Props["ro.carrier"]))
	}
	// Count what is actually installed, not what the inventory holds: the
	// package list is gathered with -u so a second run can see what it already
	// removed, which means len(pkgs) includes those. Calling that "installed"
	// made the header sit still at 440 across a run that removed 21 packages.
	installed, removed := 0, 0
	for _, p := range pkgs {
		if p.Uninstalled {
			removed++
			continue
		}
		installed++
	}
	fmt.Printf("\n  %d packages installed for user 0", installed)
	if removed > 0 {
		fmt.Printf(", %d more in the image but removed for this user", removed)
	}
	fmt.Println()

	if f.listAll {
		printDebloatInventory(plan)
		return nil
	}
	if f.showUnknown {
		installed, inactive := plan.UnknownsByState()
		fmt.Printf("\n%s\n", cHdr(fmt.Sprintf("  Not in catalog/bloat.yaml, still installed (%d):", len(installed))))
		for _, p := range installed {
			fmt.Println("    " + p)
		}
		if len(inactive) > 0 {
			fmt.Printf("\n%s\n", cHdr(fmt.Sprintf("  Not in the catalog, and already removed or disabled (%d):", len(inactive))))
			for _, p := range inactive {
				fmt.Println("    " + p)
			}
		}
		fmt.Println("\n    None of these is ever proposed. Add an entry to catalog/bloat.yaml to classify one;")
		fmt.Println("    the still-installed list is the one worth working through.")
		return nil
	}

	// --only narrows to named packages, which still must pass the protections:
	// naming a package does not make it safe to remove.
	removals := plan.Removals()
	if len(f.only) > 0 {
		removals = narrowTo(plan, f.only)
		if len(removals) == 0 {
			return fmt.Errorf("--only matched nothing removable; run --list to see how each package is classified")
		}
	}

	printDebloatPlan(plan, removals)
	if len(removals) == 0 {
		return nil
	}
	if !f.apply {
		fmt.Println("\n    Nothing was changed. Add --apply to remove these.")
		return nil
	}

	// A device mutation, even a reversible one, is confirmed rather than
	// assumed: the count is what an operator should be made to read.
	if !f.yes {
		fmt.Printf("\nAbout to uninstall %d packages for user 0 on %s. Type 'debloat' to proceed: ",
			len(removals), dev.R.Serial)
		if !confirm("debloat") {
			return fmt.Errorf("aborted")
		}
	}

	rec := &bloat.Record{Device: dev.R.Serial, Applied: plan.Created}
	fmt.Println()
	for i, e := range removals {
		progressLine("removing %d/%d: %s", i+1, len(removals), e.Package)
		err := adb.Uninstall(dev.C, e.Package)
		if err == nil {
			rec.Note(e)
			continue
		}
		// A privileged system package the shell may not uninstall answers
		// DELETE_FAILED_INTERNAL_ERROR or "package is non-disable". Disabling it
		// reaches the same end — it does not run — so that is tried rather than
		// reported as a dead end, and recorded so --restore re-enables it.
		progressLine("disabling %d/%d: %s (uninstall refused)", i+1, len(removals), e.Package)
		if derr := adb.Disable(dev.C, e.Package); derr != nil {
			e.Err = fmt.Sprintf("%v; disabling instead: %v", err, derr)
			rec.Failed = append(rec.Failed, e)
			continue
		}
		rec.NoteDisabled(e.Package)
	}
	clearProgressLine()

	done := len(rec.Removed) + len(rec.RemovedFromData)
	fmt.Printf("  %s %d removed", cGood("✓"), done)
	if len(rec.Disabled) > 0 {
		fmt.Printf(", %s %d disabled instead (privileged system packages)", cGood("✓"), len(rec.Disabled))
	}
	if len(rec.Failed) > 0 {
		fmt.Printf(", %s %d refused by the device", cWarn("!"), len(rec.Failed))
	}
	fmt.Println()
	for _, e := range rec.Failed {
		fmt.Println("    " + cWarn("[!] "+e.Err))
	}
	if n := len(rec.RemovedFromData); n > 0 {
		fmt.Printf("    %s\n", cWarn(fmt.Sprintf("%d of these were installed in /data, so their APKs are gone: --restore cannot", n)))
		fmt.Printf("    %s\n", cWarn("bring them back, the Play Store can. The record lists which."))
	}

	if done == 0 && len(rec.Disabled) == 0 {
		return nil
	}
	path := f.record
	if path == "" {
		path = fmt.Sprintf("debloat-%s.json", sanitize(dev.R.Serial))
	}
	fh, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("writing the undo record: %w", err)
	}
	defer fh.Close()
	if err := bloat.WriteRecord(fh, rec); err != nil {
		return fmt.Errorf("writing the undo record: %w", err)
	}
	fmt.Printf("\n  Undo record: %s\n", path)
	fmt.Printf("  Put everything back with: unbrick adb debloat --restore %s\n", path)
	return nil
}

// runADBRestore reinstalls what a previous apply removed. It is the reason the
// removal is offered at all, so it is not an afterthought: it reads the record,
// reinstalls each package for user 0, and says which came back.
func runADBRestore(o adb.Options, path string, yes bool) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	rec, err := bloat.ReadRecord(fh)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	dev, err := adb.Open(o)
	if err != nil {
		return err
	}
	defer dev.Close()

	if rec.Device != "" && rec.Device != dev.R.Serial {
		// A record is per device: the APKs it names live in *that* device's
		// image, and install-existing can only restore what is already there.
		return fmt.Errorf("%s was written for device %s, but %s is attached", path, rec.Device, dev.R.Serial)
	}
	total := len(rec.Removed) + len(rec.Disabled)
	fmt.Printf("Restoring %d packages on %s (from %s)\n", total, dev.R.Serial, path)
	if !yes {
		fmt.Print("Type 'restore' to proceed: ")
		if !confirm("restore") {
			return fmt.Errorf("aborted")
		}
	}
	var back, failed int
	step := 0
	for _, pkg := range rec.Removed {
		step++
		progressLine("restoring %d/%d: %s", step, total, pkg)
		if err := adb.Reinstall(dev.C, pkg); err != nil {
			clearProgressLine()
			fmt.Println("    " + cWarn("[!] "+err.Error()))
			failed++
			continue
		}
		back++
	}
	// The ones that were disabled rather than uninstalled are re-enabled, which
	// is the exact inverse of what was done to them.
	for _, pkg := range rec.Disabled {
		step++
		progressLine("re-enabling %d/%d: %s", step, total, pkg)
		if err := adb.Enable(dev.C, pkg); err != nil {
			clearProgressLine()
			fmt.Println("    " + cWarn("[!] "+err.Error()))
			failed++
			continue
		}
		back++
	}
	clearProgressLine()
	fmt.Printf("  %s %d restored", cGood("✓"), back)
	if failed > 0 {
		fmt.Printf(", %s %d could not be", cWarn("!"), failed)
	}
	fmt.Println()
	if len(rec.RemovedFromData) > 0 {
		fmt.Printf("\n  %d were installed in /data and cannot be restored from the image.\n", len(rec.RemovedFromData))
		fmt.Println("  Reinstall these from the Play Store if you want them back:")
		for _, pkg := range rec.RemovedFromData {
			fmt.Println("    " + pkg)
		}
	}
	return nil
}

// inventory adapts the package list to what the classifier needs.
func inventory(pkgs []adb.Package) []bloat.Inventory {
	out := make([]bloat.Inventory, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, bloat.Inventory{
			Package:     p.Name,
			FromImage:   p.FromImage(),
			Uninstalled: p.Uninstalled,
			Disabled:    p.Disabled,
		})
	}
	return out
}

// narrowTo keeps only the named packages, and explains each name it drops:
// naming a package does not override a protection.
func narrowTo(plan *bloat.Plan, only []string) []bloat.Entry {
	want := map[string]bool{}
	for _, n := range only {
		want[n] = true
	}
	var out []bloat.Entry
	for _, e := range plan.Entries {
		if !want[e.Package] {
			continue
		}
		delete(want, e.Package)
		if e.State == bloat.Remove || (e.Category() != bloat.Protected && e.Category() != bloat.Unknown && e.State == bloat.Keep) {
			// A named package in a category that was simply not selected is
			// what --only is for; a protected or unknown one is not.
			e.State = bloat.Remove
			out = append(out, e)
			continue
		}
		fmt.Println("  " + cWarn("[!] skipping "+e.Package+": "+e.Reason))
	}
	for n := range want {
		fmt.Println("  " + cWarn("[!] "+n+" is not installed on this device"))
	}
	return out
}

func printDebloatPlan(plan *bloat.Plan, removals []bloat.Entry) {
	fmt.Printf("\n%s\n", cHdr(fmt.Sprintf("  Plan (categories: %s; risk up to %s):",
		strings.Join(plan.Categories, ", "), plan.MaxRisk)))
	if len(removals) == 0 {
		fmt.Println("    nothing to remove — everything in these categories is already gone")
	}
	byCat := map[bloat.Category][]bloat.Entry{}
	for _, e := range removals {
		byCat[e.Category()] = append(byCat[e.Category()], e)
	}
	for _, cat := range []bloat.Category{bloat.Ads, bloat.Preload, bloat.CarrierOwn,
		bloat.CarrierForeign, bloat.OEMExtra, bloat.Updates} {
		es := byCat[cat]
		if len(es) == 0 {
			continue
		}
		fmt.Printf("    %s (%d)\n", cTag(string(cat)), len(es))
		// One note per rule, not per package: a prefix rule covering seven Aura
		// packages has one reason, and printing it seven times buries the plan.
		lastNote := ""
		for _, e := range es {
			var tags []string
			switch e.Risk() {
			case bloat.Caution:
				tags = append(tags, cWarn("caution"))
			case bloat.Invasive:
				tags = append(tags, cBad("invasive"))
			}
			if !e.FromImage {
				tags = append(tags, cWarn("in /data: not locally restorable"))
			}
			line := "      " + e.Package
			if len(tags) > 0 {
				line = fmt.Sprintf("      %-52s [%s]", e.Package, strings.Join(tags, ", "))
			}
			fmt.Println(line)
			if n := squash(e.Note()); n != "" && n != lastNote {
				fmt.Printf("        %s\n", n)
				lastNote = n
			}
		}
	}

	// What was considered and kept, counted rather than listed: the detail is
	// --list, and the summary is what makes the plan trustworthy.
	kept, groups := plan.ByCategory(bloat.Keep)
	var parts []string
	for _, c := range kept {
		parts = append(parts, fmt.Sprintf("%d %s", len(groups[c]), c))
	}
	if len(parts) > 0 {
		fmt.Printf("\n    Kept: %s (--list to see why each)\n", strings.Join(parts, ", "))
	}
	// One line, two dispositions: what is unclassified *and running* is what a
	// maintainer should look at, and saying only the total made this line look
	// as though it disagreed with the "kept" count above.
	if installed, inactive := plan.UnknownsByState(); len(installed)+len(inactive) > 0 {
		line := fmt.Sprintf("    %d packages are not in catalog/bloat.yaml, so are never proposed: %d still installed",
			len(installed)+len(inactive), len(installed))
		if len(inactive) > 0 {
			line += fmt.Sprintf(", %d already removed or disabled", len(inactive))
		}
		fmt.Println(line + " (--unknown to list)")
	}
	// Bloat the device itself refuses: worth naming once, since the operator
	// would otherwise wonder why it is not in the plan.
	if _, blocked := plan.ByCategory(bloat.Blocked); len(blocked) > 0 {
		var names []string
		for _, es := range blocked {
			for _, e := range es {
				names = append(names, e.Package)
			}
		}
		sort.Strings(names)
		fmt.Printf("    %s\n", cWarn("This build protects "+strings.Join(names, ", ")+": it refuses both"))
		fmt.Printf("    %s\n", cWarn("uninstall and disable for them, so they are reported rather than proposed."))
	}
}

func printDebloatInventory(plan *bloat.Plan) {
	for _, state := range []bloat.State{bloat.Remove, bloat.Keep, bloat.Blocked, bloat.Off,
		bloat.Gone, bloat.NotPreloaded} {
		cats, groups := plan.ByCategory(state)
		if len(cats) == 0 {
			continue
		}
		fmt.Printf("\n%s\n", cHdr("  "+string(state)+":"))
		for _, c := range cats {
			fmt.Printf("    %s\n", cTag(string(c)))
			for _, e := range groups[c] {
				fmt.Printf("      %-52s %s\n", e.Package, squash(e.Reason))
			}
		}
	}
}

// squash puts a wrapped catalog note on one line.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
