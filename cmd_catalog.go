package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/bootelf"
	"go-unbrick/internal/catalog"
	"go-unbrick/internal/library"
)

// ---- catalog ----

func newCatalogCmd() *cobra.Command {
	c := &cobra.Command{Use: "catalog", Short: "browse the vendor/SoC/device catalog"}
	c.AddCommand(newCatalogListCmd(), newCatalogFamilyCmd(), newCatalogStubCmd(), newCatalogBackfillCmd(), newCatalogMineVariantsCmd())
	return c
}

var (
	reCodename = regexp.MustCompile(`(?i)blankflash[_-]`)
)

// codenameFromSource matches a device codename from the catalog YAML, falling
// back to parsing the donor filename if the device is uncatalogued.
func codenameFromSource(cat *catalog.Catalog, src string) string {
	if cat != nil {
		if code := cat.CodenameFromFilename(src); code != "" {
			return code
		}
	}
	base := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
	if loc := reCodename.FindStringIndex(base); loc != nil {
		base = base[loc[1]:]
	}
	if i := strings.IndexAny(base, "_-. "); i >= 0 {
		base = base[:i]
	}
	if len(base) == 16 && strings.Trim(base, "0123456789abcdefABCDEF") == "" {
		return ""
	}
	return strings.ToLower(base)
}

// modelFromSource finds a device model number in the filename based on the models
// defined in the catalog YAML (no hardcoded model prefixes or patterns).
func modelFromSource(cat *catalog.Catalog, src string) string {
	if cat != nil {
		if m := cat.ModelFromFilename(src); m != "" {
			return m
		}
	}
	return ""
}

// isRealJTAG accepts only a genuine fused MSM id: 8 hex digits, not all-zero.
// It rejects both the wildcard id a generic fhprg carries and the cpu_name a
// loader is keyed on when its cert is unparseable (library add-loader fallback),
// neither of which is a device's silicon id.
func isRealJTAG(j string) bool {
	return len(j) == 8 && strings.TrimLeft(strings.ToUpper(j), "0123456789ABCDEF") == "" && strings.Trim(j, "0") != ""
}

func newCatalogStubCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "stub",
		Short: "generate flat catalog device stubs from the loader library (for uncatalogued families)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := catalog.Load(catalogDir())
			if err != nil {
				return err
			}
			lib := library.Open(libraryDir())

			byCode := map[string]*catalog.Device{}
			for _, fam := range lib.Loaders() {
				for _, b := range lib.Builds(fam) {
					code := codenameFromSource(cat, b.Meta.Source)
					if code == "" || code == "from" { // "from" = generic/unknown donor name
						continue
					}
					if _, known := cat.Device(code); known {
						continue // already catalogued
					}
					d := byCode[code]
					if d == nil {
						d = &catalog.Device{Codename: code, Vendor: fam.Vendor, CPUName: b.Meta.CPUName}
						byCode[code] = d
					}
					// The loader's family JTAG_ID is this device's own silicon (the
					// source names the device), so pin it exactly.
					if isRealJTAG(fam.JTAGID) && !slices.Contains(d.JTAGIDs, fam.JTAGID) {
						d.JTAGIDs = append(d.JTAGIDs, fam.JTAGID)
					}
					if m := modelFromSource(cat, b.Meta.Source); m != "" && len(d.Models) == 0 {
						d.Models = []string{m}
					}
					if b.Meta.Storage != "" && len(d.Storage) == 0 {
						d.Storage = []string{strings.ToLower(b.Meta.Storage)}
					}
				}
			}
			if len(byCode) == 0 {
				fmt.Fprintln(os.Stderr, "no uncatalogued devices in the library; nothing to stub")
				return nil
			}
			devs := make([]*catalog.Device, 0, len(byCode))
			for _, d := range byCode {
				slices.Sort(d.JTAGIDs)
				devs = append(devs, d)
			}
			y, err := catalog.Render(devs) // name/soc left blank to VERIFY
			if err != nil {
				return err
			}
			if out == "" {
				fmt.Print(string(y))
				return nil
			}
			if err := write(out, y); err != nil {
				return err
			}
			fmt.Printf("wrote %d device stubs -> %s (catalog.Load merges all *.yaml)\n", len(devs), out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write to a catalog file (default: stdout)")
	return c
}

// newCatalogBackfillCmd records each device's jtag_id from library loaders that
// are provably its own — a full donor whose source filename names the device's
// codename or model, so its cert-derived JTAG_ID is that device's silicon. It
// deliberately does NOT use the cpu_name bridge, which over-groups sibling JTAGs
// and would pin the wrong ones. Renders the whole catalog (merging all *.yaml);
// review the diff before committing.
func newCatalogBackfillCmd() *cobra.Command {
	var out string
	var overwrite, fromStock bool
	c := &cobra.Command{
		Use:   "backfill",
		Short: "record each device's jtag_id from its own stock, or from loaders provably its own",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := catalog.Load(catalogDir())
			if err != nil {
				return err
			}
			lib, err := stockLibrary()
			if err != nil {
				return err
			}

			// (vendor, codename|model) -> set of JTAG_IDs seen in loaders whose
			// source names that identifier.
			type key struct{ vendor, ident string }
			byIdent := map[key]map[string]bool{}
			add := func(vendor, ident, jtag string) {
				if ident == "" || !isRealJTAG(jtag) {
					return
				}
				k := key{vendor, ident}
				if byIdent[k] == nil {
					byIdent[k] = map[string]bool{}
				}
				byIdent[k][jtag] = true
			}
			for _, fam := range lib.Loaders() {
				for _, b := range lib.Builds(fam) {
					add(fam.Vendor, codenameFromSource(cat, b.Meta.Source), fam.JTAGID)
					add(fam.Vendor, modelFromSource(cat, b.Meta.Source), fam.JTAGID)
				}
			}

			// Stock read from the device's own signed boot chain outranks every
			// filename heuristic: the cert in a device's own xbl states the
			// silicon its PBL enforces. Where the two disagree, the filename was
			// wrong, so a stock reading replaces rather than joins.
			fromStockJTAG := map[key]string{}
			if fromStock {
				for _, s := range lib.Stock() {
					t, _, err := lib.FindStock(s.Vendor, s.Codename, s.Build)
					if err != nil {
						continue
					}
					id := targetIdentity(t)
					if id == nil || !isRealJTAG(id.JTAGID) {
						continue
					}
					fromStockJTAG[key{s.Vendor, s.Codename}] = id.JTAGID
				}
			}

			devs := cat.AllDevices()
			changed := 0
			for _, d := range devs {
				if j, ok := fromStockJTAG[key{d.Vendor, d.Codename}]; ok {
					if slices.Equal([]string{j}, d.JTAGIDs) {
						continue
					}
					if len(d.JTAGIDs) > 0 {
						fmt.Fprintf(os.Stderr, "  %s: jtag_id %v -> [%s]  (CORRECTED from its own stock)\n",
							d.Codename, d.JTAGIDs, j)
					} else {
						fmt.Fprintf(os.Stderr, "  %s: jtag_id=[%s]  (from its own stock)\n", d.Codename, j)
					}
					d.JTAGIDs = []string{j}
					changed++
					continue
				}
				if len(d.JTAGIDs) > 0 && !overwrite {
					continue
				}
				disc := map[string]bool{}
				for j := range byIdent[key{d.Vendor, d.Codename}] {
					disc[j] = true
				}
				for _, m := range d.Models {
					mClean := strings.TrimSpace(m)
					for j := range byIdent[key{d.Vendor, mClean}] {
						disc[j] = true
					}
				}
				if len(disc) == 0 {
					continue
				}
				list := make([]string, 0, len(disc))
				for j := range disc {
					list = append(list, j)
				}
				slices.Sort(list)
				if slices.Equal(list, d.JTAGIDs) {
					continue
				}
				d.JTAGIDs = list
				changed++
				fmt.Fprintf(os.Stderr, "  %s: jtag_id=%v\n", d.Codename, list)
			}
			if changed == 0 {
				fmt.Fprintln(os.Stderr, "no jtag_id backfilled (no library loader names a catalogued device by source)")
				return nil
			}
			y, err := catalog.Render(devs)
			if err != nil {
				return err
			}
			if out == "" {
				fmt.Print(string(y))
				return nil
			}
			if err := write(out, y); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "backfilled jtag_id for %d device(s) -> %s\n", changed, out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write the full rendered catalog to this file (default: stdout)")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "also replace jtag_id on devices that already have one")
	c.Flags().BoolVar(&fromStock, "from-stock", false,
		"read jtag_id from each device's own stock boot chain (authoritative; corrects wrong entries)")
	return c
}

func newCatalogListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "vendors / SoCs / devices, with loader,stock status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := catalog.Load(catalogDir())
			if err != nil {
				return err
			}
			lib := library.Open(libraryDir())
			var lastVendor, lastCPU string
			for _, d := range c.AllDevices() {
				if d.Vendor != lastVendor {
					fmt.Printf("%s\n", d.Vendor)
					lastVendor, lastCPU = d.Vendor, ""
				}
				if d.CPUName != lastCPU {
					soc := d.SoC
					if soc == "" {
						soc = "(SoC name unknown)"
					}
					fmt.Printf("  %s  cpu_name=%s  family=%s\n", soc, d.CPUName, d.CPUFamily())
					lastCPU = d.CPUName
				}
				fmt.Printf("    %-10s %-22s %-16s storage=%-9s loader:%s stock:%s\n",
					d.Codename, d.Name, strings.Join(d.Models, ","), strings.Join(d.Storage, ","),
					mark(len(lib.CandidateLoaders(d)) > 0), mark(lib.HasStock(d.Vendor, d.Codename)))
			}
			return nil
		},
	}
}

func newCatalogFamilyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "family <codename>",
		Short: "show a device's family and its candidate donor siblings",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := catalog.Load(catalogDir())
			if err != nil {
				return err
			}
			d, ok := c.Device(args[0])
			if !ok {
				return fmt.Errorf("unknown codename %q", args[0])
			}
			sibs, _ := c.Siblings(args[0])
			fmt.Printf("%s (%s) family %s\n", d.Codename, d.Name, d.CPUFamily())
			fmt.Println("siblings (candidate loader donors):")
			if len(sibs) == 0 {
				fmt.Println("  (none in catalog)")
			}
			for _, s := range sibs {
				fmt.Printf("  %-10s %s %s\n", s.Codename, s.Name, strings.Join(s.Models, ","))
			}
			return nil
		},
	}
}

func newCatalogMineVariantsCmd() *cobra.Command {
	var writeInPlace bool
	var outFile string
	c := &cobra.Command{
		Use:   "mine-variants",
		Short: "harvest unmapped variant strings from library loaders and correlate with catalog SoCs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := catalog.Load(catalogDir())
			if err != nil {
				return err
			}

			// Find all programmer.elf binaries in library/loaders
			pattern := filepath.Join(libraryDir(), "loaders", "*", "*", "*", "programmer.elf")
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return err
			}

			type discovery struct {
				token    string
				soc      string
				evidence string
			}
			discovered := make(map[string]discovery)

			for _, p := range matches {
				data, err := os.ReadFile(p)
				if err != nil {
					continue
				}
				info, err := bootelf.Analyze(data)
				if err != nil || info.Variant == "" {
					continue
				}

				// Check if already mapped in variants.yaml
				cleanToken := strings.ToLower(strings.TrimSpace(info.Variant))
				if cat.ResolveVariant(cleanToken, "") != "" {
					continue
				}

				// Try to correlate to a known SoC:
				var targetSoC, evidence string

				// 1. Via secboot JTAG ID from attestation cert
				if info.Identity != nil && isRealJTAG(info.Identity.JTAGID) {
					if soc, ok := cat.SoCByJTAG(info.Identity.JTAGID); ok && soc != "" {
						targetSoC = soc
						d, _ := cat.DeviceByJTAG(info.Identity.JTAGID)
						devName := ""
						if d != nil {
							devName = fmt.Sprintf(" (%s / %s)", d.Codename, d.CPUName)
						}
						evidence = fmt.Sprintf("secboot JTAG %s%s", info.Identity.JTAGID, devName)
					}
				}

				// 2. Via directory path JTAG or CPU
				if targetSoC == "" {
					parts := strings.Split(filepath.ToSlash(p), "/")
					// .../loaders/<vendor>/<dirJTAG>/<buildDir>/programmer.elf
					if len(parts) >= 5 {
						dirJTAG := parts[len(parts)-3]
						buildDir := parts[len(parts)-2]
						devCode := strings.Split(buildDir, "_")[0]
						vendor := parts[len(parts)-4]

						if isRealJTAG(dirJTAG) {
							if soc, ok := cat.SoCByJTAG(dirJTAG); ok && soc != "" {
								targetSoC = soc
								evidence = fmt.Sprintf("directory JTAG %s", dirJTAG)
							}
						} else if soc, ok := cat.SoCByCPUName(vendor, dirJTAG); ok && soc != "" {
							targetSoC = soc
							evidence = fmt.Sprintf("directory cpu_name %s", dirJTAG)
						}

						if targetSoC == "" && devCode != "" {
							if d, ok := cat.Device(strings.ToLower(devCode)); ok {
								if d.SoC != "" {
									targetSoC = d.SoC
								} else {
									targetSoC = cat.ResolveVariant(d.CPUName, "")
								}
								if targetSoC != "" {
									evidence = fmt.Sprintf("donor device %s (%s)", d.Codename, d.CPUName)
								}
							}
						}
					}
				}

				if targetSoC != "" {
					if _, exists := discovered[cleanToken]; !exists {
						discovered[cleanToken] = discovery{
							token:    cleanToken,
							soc:      targetSoC,
							evidence: evidence,
						}
					}
				}
			}

			if len(discovered) == 0 {
				fmt.Println("No unmapped variants found in loader library.")
				return nil
			}

			// Sort discovered tokens for stable display and persistence
			tokens := make([]string, 0, len(discovered))
			for t := range discovered {
				tokens = append(tokens, t)
			}
			slices.Sort(tokens)

			fmt.Fprintf(os.Stderr, "Discovered %d unmapped variant(s):\n", len(discovered))
			for _, t := range tokens {
				disc := discovered[t]
				fmt.Fprintf(os.Stderr, "  %-14s -> %s  (via %s)\n", disc.token, disc.soc, disc.evidence)
			}

			// Write to catalog/variants.yaml or target file if requested
			targetPath := outFile
			if writeInPlace {
				targetPath = filepath.Join(catalogDir(), "variants.yaml")
			}

			if targetPath == "" {
				fmt.Fprintln(os.Stderr, "\nUse -w / --write to persist into catalog/variants.yaml, or -o / --out to write to a file.")
				return nil
			}

			// Read existing variants.yaml
			var existingText string
			if b, err := os.ReadFile(targetPath); err == nil {
				existingText = string(b)
			} else {
				existingText = "variants:\n"
			}

			// Append new variants cleanly
			var toAppend []string
			for _, t := range tokens {
				disc := discovered[t]
				if !strings.Contains(existingText, "  "+disc.token+":") {
					toAppend = append(toAppend, fmt.Sprintf("  %s: %s", disc.token, disc.soc))
				}
			}

			if len(toAppend) > 0 {
				if !strings.HasSuffix(existingText, "\n") {
					existingText += "\n"
				}
				existingText += "\n  # Discovered Platform Variants (via unbrick catalog mine-variants)\n"
				for _, line := range toAppend {
					existingText += line + "\n"
				}
				if err := write(targetPath, []byte(existingText)); err != nil {
					return fmt.Errorf("writing %s: %w", targetPath, err)
				}
				fmt.Fprintf(os.Stderr, "\nUpdated %s with %d new variant mapping(s).\n", targetPath, len(toAppend))
			} else {
				fmt.Fprintf(os.Stderr, "\nAll discovered variants are already present in %s.\n", targetPath)
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&writeInPlace, "write", "w", false, "write discovered variants directly into catalog/variants.yaml")
	c.Flags().StringVarP(&outFile, "out", "o", "", "write updated variants YAML to this file")
	return c
}
