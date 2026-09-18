package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/catalog"
	"go-unbrick/internal/library"
	"go-unbrick/internal/secboot"
	"go-unbrick/internal/upstream"
	"go-unbrick/internal/vendor"
)

// ---- library ----

func newLibraryCmd() *cobra.Command {
	c := &cobra.Command{Use: "library", Short: "manage the local loader + stock store"}
	c.AddCommand(newLibraryAddLoaderCmd(), newLibraryAddStockCmd(), newLibraryAddStockZipCmd(),
		newLibraryHarvestDonorsCmd(), newLibraryListCmd(), newLibrarySyncCmd(), newLibraryImportLoadersCmd())
	return c
}

// newLibrarySyncCmd pulls signed loaders from the upstream bkerler/Loaders DB
// (the only network path in the tool) and ingests them keyed by JTAG_ID.
func newLibrarySyncCmd() *cobra.Command {
	var vendorID string
	var dryRun, includeVariants bool
	var limit int
	c := &cobra.Command{
		Use:   "sync",
		Short: "fetch signed loaders from the upstream bkerler/Loaders database",
		RunE: func(cmd *cobra.Command, args []string) error {
			drv, ok := vendor.For(vendorID)
			if !ok {
				return fmt.Errorf("no vendor driver for %q", vendorID)
			}
			dir := upstream.ResolveVendorDir(vendorID)
			if dir == "" {
				return fmt.Errorf("no upstream directory mapped for vendor %q", vendorID)
			}
			oems := drv.OEMIDs()
			if len(oems) == 0 {
				return fmt.Errorf("vendor %q declares no OEM_IDs; cannot filter upstream loaders safely", vendorID)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			entries, err := upstream.List(ctx, dir, oems)
			if err != nil {
				return err
			}
			// Stock (unpatched) loaders first; peek/edlauth research builds only
			// with --include-variants (they won't authenticate on secure boot).
			var todo []upstream.Entry
			for _, e := range entries {
				if e.Stock() || includeVariants {
					todo = append(todo, e)
				}
			}
			sort.Slice(todo, func(i, j int) bool { return todo[i].Name < todo[j].Name })
			fmt.Printf("upstream %s/%s: %d loaders match OEM %v (%d after variant filter)\n",
				"bkerler/Loaders", dir, len(entries), oems, len(todo))

			lib := library.Open(libraryDir())
			var added, dup, skipped int
			for i, e := range todo {
				if limit > 0 && i >= limit {
					break
				}
				tag := e.JTAGID
				if e.Variant != "" {
					tag += " [" + e.Variant + "]"
				}
				if dryRun {
					fmt.Printf("  would fetch %s  JTAG=%s OEM=%s %dB\n", e.Name, e.JTAGID, e.OEMID, e.Size)
					continue
				}
				blob, err := upstream.Download(ctx, e)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ! %s: %v\n", e.Name, err)
					skipped++
					continue
				}
				id, err := secboot.FromELF(blob)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ! %s: unparseable loader cert, skipping: %v\n", e.Name, err)
					skipped++
					continue
				}
				// The cert is authoritative over the filename; key on it.
				fam := catalog.Family{Vendor: vendorID, JTAGID: id.JTAGID}
				donor := &blankflash.Donor{Programmer: blob, Source: "bkerler/Loaders/" + dir + "/" + e.Name}
				before := len(lib.Builds(fam))
				ref, err := lib.AddLoader(fam, donor, e.Name)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ! %s: %v\n", e.Name, err)
					skipped++
					continue
				}
				if len(lib.Builds(fam)) == before {
					dup++
					continue
				}
				added++
				fmt.Printf("  + %s@%s  JTAG=%s OEM=%s SW_ID=%d %dB\n",
					fam, ref.Build, id.JTAGID, id.OEMID, id.SWID, len(blob))
			}
			if dryRun {
				fmt.Printf("dry run: %d loaders would be fetched\n", len(todo))
			} else {
				fmt.Printf("synced: %d added, %d already present, %d skipped\n", added, dup, skipped)
			}
			return nil
		},
	}
	c.Flags().StringVar(&vendorID, "vendor", "motorola", "vendor id to sync (maps to an upstream directory)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "list what would be fetched without downloading")
	c.Flags().BoolVar(&includeVariants, "include-variants", false, "also fetch peek/edlauth research builds (won't authenticate on secure boot)")
	c.Flags().IntVar(&limit, "limit", 0, "max loaders to ingest (0 = all)")
	return c
}

func newLibraryAddLoaderCmd() *cobra.Command {
	var vendorHint string
	c := &cobra.Command{
		Use:   "add-loader <blankflash>",
		Short: "ingest a blankflash, detect its family, store the signed loader",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := catalog.Load(catalogDir())
			if err != nil {
				return err
			}
			drv, ok := vendor.Detect(args[0])
			if !ok {
				return fmt.Errorf("unrecognized blankflash package (no vendor driver matched): %s", args[0])
			}
			d, err := drv.IngestDonor(args[0])
			if err != nil {
				return err
			}
			// Vendor comes from the detected package format (or --vendor); the loader
			// need not be pre-catalogued — the catalog is for targets/derive.
			vendorID := vendorHint
			if vendorID == "" {
				vendorID = drv.ID()
			}
			// Key on the silicon the loader authenticates against (JTAG_ID from the
			// cert), not the qboot cpu_name label. A 32-bit/eMMC loader whose cert
			// our secboot can't parse falls back to keying on cpu_name (needs the
			// donor's index.xml); a bare fhprg with neither cannot be placed.
			var swid uint64
			key := ""
			if id, err := secboot.FromELF(d.Programmer); err == nil {
				key, swid = id.JTAGID, id.SWID
			} else if d.CPUName != "" {
				key = d.CPUName
				fmt.Fprintf(os.Stderr, "  ! cert unparseable (%v); keying on cpu_name %q\n", err, d.CPUName)
			} else {
				return fmt.Errorf("cannot read loader JTAG_ID from cert and no cpu.name to fall back on: %w", err)
			}
			fam := catalog.Family{Vendor: vendorID, JTAGID: key}
			ref, err := library.Open(libraryDir()).AddLoader(fam, d, args[0])
			if err != nil {
				return err
			}
			note := ""
			if d.CPUName != "" {
				if _, cataloged := c.SoCByCPUName(vendorID, d.CPUName); !cataloged {
					note = "  (cpu_name not in catalog — add a device entry to enable `derive`)"
				}
			}
			swidStr := fmt.Sprintf("SW_ID=%d", swid)
			if swName := c.SWIDName(swid); swName != "" {
				swidStr = fmt.Sprintf("SW_ID=%d (%s)", swid, swName)
			}
			fmt.Printf("stored loader %s@%s (cpu.name=%q storage=%s %s, %dB, sha256=%s)%s\n",
				fam, ref.Build, d.CPUName, d.Storage, swidStr, len(d.Programmer), ref.Meta.SHA256[:12], note)
			return nil
		},
	}
	c.Flags().StringVar(&vendorHint, "vendor", "", "vendor id, to disambiguate a shared cpu_name")
	return c
}

// stockLibrary opens the library with a vendor-dispatching build namer, so
// stored and migrated stock builds carry each OEM's own build id, and converts
// any device still in the old flat layout.
func stockLibrary() (*library.Library, error) {
	lib := library.Open(libraryDir())
	lib.BuildNamer = func(vendorID string, t *blankflash.Target) string {
		drv, ok := vendor.For(vendorID)
		if !ok {
			return ""
		}
		return vendor.StockBuildID(drv, t)
	}
	return lib, lib.MigrateStock()
}

// printStockStored reports a stored stock build, naming the build id so the
// operator can select it later with --stock.
func printStockStored(ref *library.StockRef, t *blankflash.Target) {
	cid := ""
	if ref.Meta.CID != "" {
		cid = fmt.Sprintf(" cid=%s", ref.Meta.CID)
		if ref.Meta.SubsidyLock != "" {
			cid += " slcf=" + ref.Meta.SubsidyLock
		}
	}
	fmt.Printf("stored stock %s/%s@%s: parts=%d gpt=%s storage=%s%s\n",
		ref.Vendor, ref.Codename, ref.Build, len(t.Parts), yesno(t.GPT != nil), t.Storage, cid)
}

func newLibraryAddStockCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "add-stock <codename>",
		Short: "harvest a catalog device's stock and store it",
		Args:  cobra.ExactArgs(1),
	}
	tf := addTargetFlags(c)
	c.RunE = func(cmd *cobra.Command, args []string) error {
		c2, err := catalog.Load(catalogDir())
		if err != nil {
			return err
		}
		d, ok := c2.Device(args[0])
		if !ok {
			return fmt.Errorf("unknown codename %q; add it to the catalog first", args[0])
		}
		drv, ok := vendor.For(d.Vendor)
		if !ok {
			return fmt.Errorf("no vendor driver for %q", d.Vendor)
		}
		t, err := drv.HarvestStock(tf.source())
		if err != nil {
			return err
		}
		lib, err := stockLibrary()
		if err != nil {
			return err
		}
		ref, err := lib.AddStock(d.Vendor, d.Codename, vendor.StockBuildID(drv, t), t)
		if err != nil {
			return err
		}
		printStockStored(ref, t)
		return nil
	}
	return c
}

// newLibraryAddStockZipCmd harvests a catalog device's stock straight from the
// OEM's retail firmware zip, so the boot chain need not be unpacked by hand.
// The package names the device itself (Motorola stamps a PROD field into its
// gpt.bin), so --codename is only needed when that tag is absent.
func newLibraryAddStockZipCmd() *cobra.Command {
	var codename string
	c := &cobra.Command{
		Use:   "add-stock-zip <stock.zip>",
		Short: "harvest a device's stock directly from an OEM firmware zip",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			drv, sp, ok := vendor.DetectStock(path)
			if !ok {
				return fmt.Errorf("unrecognized stock package (no vendor driver matched): %s", path)
			}
			t, err := sp.HarvestStockPackage(path)
			if err != nil {
				return err
			}
			// The package's own product tag is authoritative over anything the
			// filename or the operator says; disagreement means the wrong zip.
			tagged := vendor.CodenameFromStock(drv, t)
			switch {
			case tagged == "" && codename == "":
				return fmt.Errorf("package carries no product tag; pass --codename")
			case tagged == "":
				fmt.Fprintf(os.Stderr, "  ! package carries no product tag; trusting --codename %q\n", codename)
			case codename == "":
				codename = tagged
				fmt.Printf("  package identifies as %q\n", tagged)
			case codename != tagged:
				return fmt.Errorf("package is for %q but --codename says %q; refusing to store one device's boot chain as another's", tagged, codename)
			}
			cat, err := catalog.Load(catalogDir())
			if err != nil {
				return err
			}
			dev, ok := cat.Device(codename)
			if !ok {
				return fmt.Errorf("unknown codename %q; add it to the catalog first", codename)
			}
			if dev.Vendor != drv.ID() {
				return fmt.Errorf("package is %s but %s is a %s device", drv.ID(), dev.Codename, dev.Vendor)
			}
			lib, err := stockLibrary()
			if err != nil {
				return err
			}
			before := len(lib.StockBuilds(dev.Vendor, dev.Codename))
			ref, err := lib.AddStock(dev.Vendor, dev.Codename, vendor.StockBuildID(drv, t), t)
			if err != nil {
				return err
			}
			if len(lib.StockBuilds(dev.Vendor, dev.Codename)) == before {
				fmt.Printf("already stored as %s/%s@%s; nothing to do\n", ref.Vendor, ref.Codename, ref.Build)
				return nil
			}
			printStockStored(ref, t)
			for _, fn := range sortedKeys(t.Parts) {
				fmt.Printf("  %-14s %d bytes\n", fn, len(t.Parts[fn]))
			}
			return nil
		},
	}
	c.Flags().StringVar(&codename, "codename", "", "catalog codename (default: read from the package's product tag)")
	return c
}

// newLibraryHarvestDonorsCmd mines the stored donors for stock. A blankflash
// carries the signed boot chain and GPT of the device it was built for, not
// just the loader, so the donor library is also a stock library -- and the GPT
// names the device, so each one files itself.
func newLibraryHarvestDonorsCmd() *cobra.Command {
	var from, vendorID string
	var dryRun bool
	c := &cobra.Command{
		Use:   "harvest-donors",
		Short: "recover each donor's own stock boot chain and store it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			drv, ok := vendor.For(vendorID)
			if !ok {
				return fmt.Errorf("no vendor driver for %q", vendorID)
			}
			dh, ok := drv.(vendor.DonorStockHarvester)
			if !ok {
				return fmt.Errorf("%s donors cannot be harvested yet: %w", vendorID, vendor.ErrUnsupported)
			}
			dir := from
			if dir == "" {
				dir = filepath.Join(libraryDir(), "donors")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			cat, err := catalog.Load(catalogDir())
			if err != nil {
				return err
			}
			lib, err := stockLibrary()
			if err != nil {
				return err
			}

			var added, dup, unnamed, uncatalogued, noChain int
			for _, e := range entries {
				if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				path := filepath.Join(dir, e.Name())
				t, err := dh.HarvestDonorStock(path)
				if err != nil {
					noChain++
					continue
				}
				code := vendor.CodenameFromStock(drv, t)
				if code == "" {
					unnamed++
					fmt.Fprintf(os.Stderr, "  ? %s: boot chain present but no product tag; skipping\n", e.Name())
					continue
				}
				dev, ok := cat.Device(code)
				if !ok {
					uncatalogued++
					fmt.Fprintf(os.Stderr, "  ? %s: %q not in catalog; skipping\n", e.Name(), code)
					continue
				}
				if dev.Vendor != drv.ID() {
					continue
				}
				build := vendor.StockBuildID(drv, t)
				if dryRun {
					fmt.Printf("  would store %s/%s@%s (parts=%d storage=%s) from %s\n",
						dev.Vendor, dev.Codename, build, len(t.Parts), t.Storage, e.Name())
					added++
					continue
				}
				before := len(lib.StockBuilds(dev.Vendor, dev.Codename))
				ref, err := lib.AddStock(dev.Vendor, dev.Codename, build, t)
				if err != nil {
					return fmt.Errorf("%s: %w", e.Name(), err)
				}
				if len(lib.StockBuilds(dev.Vendor, dev.Codename)) == before {
					dup++
					continue
				}
				added++
				fmt.Printf("  + %s/%s@%s  parts=%d storage=%s\n",
					ref.Vendor, ref.Codename, ref.Build, len(t.Parts), t.Storage)
			}
			verb := "stored"
			if dryRun {
				verb = "would store"
			}
			fmt.Printf("%s %d stock build(s); %d already present, %d unnamed, %d uncatalogued, %d without a boot chain\n",
				verb, added, dup, unnamed, uncatalogued, noChain)
			return nil
		},
	}
	c.Flags().StringVar(&from, "from", "", "directory of donor packages (default: <library>/donors)")
	c.Flags().StringVar(&vendorID, "vendor", "motorola", "vendor id")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be stored without writing")
	return c
}

func newLibraryListCmd() *cobra.Command {
	var format, what string
	c := &cobra.Command{
		Use:   "list",
		Short: "loaders (by family) and stock (by device) on hand",
		Long: "Lists the library. With no flags, prints the grouped text view.\n" +
			"--format csv|tsv|md|json emits a flat table for scripting or a report,\n" +
			"and --what selects loaders (default), stock, or a per-vendor summary.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lib, err := stockLibrary()
			if err != nil {
				return err
			}
			if format == "text" {
				if what == "loaders" || what == "all" {
					printLoadersText(lib)
				}
				if what == "stock" || what == "all" {
					printStockText(lib)
				}
				return nil
			}
			// "all" is a multi-section document, not a single table, so it is only
			// meaningful for the document formats. csv/tsv/json need one section.
			if what == "all" {
				if format != "md" {
					return fmt.Errorf("--what all needs --format text or md; pick loaders/stock/summary for %s", format)
				}
				return renderAllMarkdown(os.Stdout, lib)
			}
			header, rows := libraryRows(lib, what)
			if header == nil {
				return fmt.Errorf("unknown --what %q (loaders, stock, summary, all)", what)
			}
			return renderTable(os.Stdout, format, header, rows)
		},
	}
	c.Flags().StringVarP(&format, "format", "f", "text", "output format: text, csv, tsv, md, json")
	c.Flags().StringVar(&what, "what", "all", "which rows: loaders, stock, summary, all")
	return c
}

func printLoadersText(lib *library.Library) {
	fmt.Println("loaders (by family; builds low SW_ID first = derive default):")
	for _, f := range lib.Loaders() {
		fmt.Printf("  %s\n", f)
		for _, b := range lib.Builds(f) {
			fmt.Printf("    SW_ID=%-4d %-26s OEM=%s HW=%s root=CA %s sha=%s\n",
				b.Meta.SWID, b.Build, b.Meta.OEMID, b.Meta.HWID, b.Meta.Root, b.Meta.SHA256[:12])
		}
	}
}

func printStockText(lib *library.Library) {
	fmt.Println("stock (by device; builds oldest first, newest = derive default):")
	lastDev := ""
	for _, s := range lib.Stock() {
		if dev := s.Vendor + "/" + s.Codename; dev != lastDev {
			fmt.Printf("  %s\n", dev)
			lastDev = dev
		}
		fmt.Printf("    %-22s %s\n", s.Build, s.Meta.Source)
	}
}

// libraryRows flattens the library into a header + string rows for tabular export.
// "all" defaults to loaders, the primary artifact; stock and summary are explicit.
func libraryRows(lib *library.Library, what string) ([]string, [][]string) {
	switch what {
	case "loaders":
		header := []string{"vendor", "jtag_id", "build", "sw_id", "oem_id", "hw_id", "root", "cpu_name", "storage", "sha256", "source"}
		var rows [][]string
		for _, f := range lib.Loaders() {
			for _, b := range lib.Builds(f) {
				rows = append(rows, []string{
					f.Vendor, f.JTAGID, b.Build, fmt.Sprintf("%d", b.Meta.SWID),
					b.Meta.OEMID, b.Meta.HWID, b.Meta.Root, b.Meta.CPUName,
					b.Meta.Storage, b.Meta.SHA256, filepath.Base(b.Meta.Source),
				})
			}
		}
		return header, rows
	case "stock":
		header := []string{"vendor", "codename", "build", "cid", "storage", "source"}
		var rows [][]string
		for _, s := range lib.Stock() {
			rows = append(rows, []string{
				s.Vendor, s.Codename, s.Build, s.Meta.CID, s.Meta.Storage, filepath.Base(s.Meta.Source),
			})
		}
		return header, rows
	case "summary":
		// families and builds per vendor — the "what do we have" overview.
		type agg struct{ families, builds int }
		byVendor := map[string]*agg{}
		var order []string
		for _, f := range lib.Loaders() {
			a := byVendor[f.Vendor]
			if a == nil {
				a = &agg{}
				byVendor[f.Vendor] = a
				order = append(order, f.Vendor)
			}
			a.families++
			a.builds += len(lib.Builds(f))
		}
		sort.Slice(order, func(i, j int) bool {
			return byVendor[order[i]].builds > byVendor[order[j]].builds
		})
		header := []string{"vendor", "families", "builds"}
		var rows [][]string
		var tf, tb int
		for _, v := range order {
			a := byVendor[v]
			tf += a.families
			tb += a.builds
			rows = append(rows, []string{v, fmt.Sprintf("%d", a.families), fmt.Sprintf("%d", a.builds)})
		}
		rows = append(rows, []string{"TOTAL", fmt.Sprintf("%d", tf), fmt.Sprintf("%d", tb)})
		return header, rows
	}
	return nil, nil
}

// renderTable writes rows in the requested format. csv/tsv are machine-readable;
// md is a GitHub table for pasting into a report; json is an array of objects
// keyed by header.
func renderTable(w io.Writer, format string, header []string, rows [][]string) error {
	switch format {
	case "csv", "tsv":
		cw := csv.NewWriter(w)
		if format == "tsv" {
			cw.Comma = '\t'
		}
		_ = cw.Write(header)
		if err := cw.WriteAll(rows); err != nil {
			return err
		}
		cw.Flush()
		return cw.Error()
	case "md":
		fmt.Fprintf(w, "| %s |\n", strings.Join(header, " | "))
		sep := make([]string, len(header))
		for i := range sep {
			sep[i] = "---"
		}
		fmt.Fprintf(w, "| %s |\n", strings.Join(sep, " | "))
		for _, r := range rows {
			fmt.Fprintf(w, "| %s |\n", strings.Join(r, " | "))
		}
		return nil
	case "json":
		objs := make([]map[string]string, 0, len(rows))
		for _, r := range rows {
			m := make(map[string]string, len(header))
			for i, h := range header {
				if i < len(r) {
					m[h] = r[i]
				}
			}
			objs = append(objs, m)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(objs)
	}
	return fmt.Errorf("unknown --format %q (text, csv, tsv, md, json)", format)
}

// renderAllMarkdown writes the whole library as one checkable markdown document:
// a per-vendor summary, then the full loader and stock tables. This is the form
// committed as the inventory; regenerate with `library list --what all -f md`.
func renderAllMarkdown(w io.Writer, lib *library.Library) error {
	fmt.Fprintln(w, "# Loader library inventory")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Generated by `go-unbrick library list --what all --format md`. Do not edit by hand.")
	fmt.Fprintln(w)
	sections := []struct {
		title, what string
	}{
		{"Summary (by vendor)", "summary"},
		{"Loaders", "loaders"},
		{"Stock", "stock"},
	}
	for _, s := range sections {
		header, rows := libraryRows(lib, s.what)
		fmt.Fprintf(w, "## %s — %d row(s)\n\n", s.title, len(rows))
		if err := renderTable(w, "md", header, rows); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}
	return nil
}

type manifestLoaderRecord struct {
	Signer    string `json:"signer"`
	SHA256    string `json:"sha256"`
	FileMD5   string `json:"file_md5"`
	Type      string `json:"type"`
	Site      string `json:"site"`
	Path      string `json:"path"`
	SavedFile string `json:"saved_file"`
}

func normalizeSignerVendor(signer, oemID string) string {
	s := strings.ToLower(strings.TrimSpace(signer))
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		if r == ' ' || r == '-' || r == '_' {
			return '_'
		}
		return -1
	}, s)
	s = strings.Trim(s, "_")
	switch s {
	case "motorola_lenovo":
		return "motorola"
	case "lenovo_motorola":
		return "lenovo"
	case "xiaomi_redmi_poco", "redmi", "poco":
		return "xiaomi"
	case "hihonor":
		return "honor"
	case "qc_test", "qualcomm_reference", "reference", "qualcomm", "qc", "":
		// Generic or absent signer: the cert's OEM_ID names the actual OEM the
		// loader is provisioned for, so it outranks the generic label. Only
		// OEM_ID 0000 (and unmapped ids) stay in the generic bucket.
		if v, ok := oemVendor[strings.ToUpper(oemID)]; ok {
			return v
		}
		return "qualcomm"
	default:
		return s
	}
}

// oemVendor maps a Qualcomm attestation OEM_ID to the vendor it identifies,
// derived from the corpus: how loaders carrying each OEM_ID and a Temblast
// signer are attributed. It is consulted only when the signer itself is generic
// (QC test/reference) or absent, so an explicit signer always wins. Shared IDs
// take the dominant brand, since the OEM_ID alone cannot split a conglomerate:
// 0051 is BBK (oneplus > oppo), 02E8 is Lenovo/Motorola (motorola > lenovo),
// 0042 is TCL and its Nokia/Alcatel lines.
var oemVendor = map[string]string{
	"0001": "wingtech",
	"0004": "zte",
	"0016": "nokia",
	"0020": "samsung",
	"0028": "motorola",
	"0029": "asus",
	"0031": "lg",
	"0035": "nokia",
	"0038": "sharp",
	"0040": "lenovo",
	"0042": "tcl",
	"0043": "hisense",
	"0048": "yulong",
	"0051": "oneplus",
	"0072": "xiaomi",
	"0073": "vivo",
	"0090": "borqs",
	"0138": "meizu",
	"0144": "blackshark",
	"0149": "hydrogen",
	"0168": "motorola",
	"02E8": "motorola",
	"0328": "motorola",
	"0368": "motorola",
	"0636": "ontim",
	"1043": "asus",
	"1111": "asus",
	"143A": "asus",
	"1520": "huaqin",
	"1590": "huaqin",
	"1978": "blackphone",
	"2016": "wingtech",
	"2A96": "micromax",
	"6000": "lenovo",
}

func fallbackJTAGFromFilename(filename, currentJTAG string) string {
	if currentJTAG != "" && currentJTAG != "00000000" {
		return currentJTAG
	}
	base := filepath.Base(filename)
	parts := strings.Split(base, "_")
	for _, p := range parts {
		if len(p) == 16 && isHex(p) && strings.Trim(p[:8], "0") != "" {
			return strings.ToUpper(p[:8])
		}
	}
	if currentJTAG != "" {
		return currentJTAG
	}
	return "00000000"
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func newLibraryImportLoadersCmd() *cobra.Command {
	var vendorFilter string
	var dryRun bool
	var limit int
	c := &cobra.Command{
		Use:   "import-loaders [directory]",
		Short: "import bare loader files (e.g. from temblast_loaders) into the library store",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "temblast_loaders"
			if len(args) > 0 {
				dir = args[0]
			}
			lib := library.Open(libraryDir())

			type workItem struct {
				path   string
				signer string
				source string
			}
			var items []workItem

			manifestPath := filepath.Join(dir, "manifest.json")
			if mBytes, err := os.ReadFile(manifestPath); err == nil {
				var records []manifestLoaderRecord
				if err := json.Unmarshal(mBytes, &records); err == nil {
					for _, rec := range records {
						target := filepath.Join(dir, rec.SavedFile)
						items = append(items, workItem{
							path:   target,
							signer: rec.Signer,
							source: filepath.Base(rec.SavedFile),
						})
					}
				}
			}

			if len(items) == 0 {
				_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
					if err == nil && !info.IsDir() {
						ext := strings.ToLower(filepath.Ext(p))
						if ext == ".elf" || ext == ".bin" || ext == ".mbn" || ext == ".melf" {
							items = append(items, workItem{
								path:   p,
								signer: filepath.Base(filepath.Dir(p)),
								source: filepath.Base(p),
							})
						}
					}
					return nil
				})
			}

			if len(items) == 0 {
				return fmt.Errorf("no loader files found in %s", dir)
			}

			fmt.Printf("Scanning %d loader files in %s...\n", len(items), dir)
			var added, dup, skipped int

			for i, item := range items {
				if limit > 0 && i >= limit {
					break
				}
				blob, err := os.ReadFile(item.path)
				if err != nil {
					skipped++
					continue
				}
				id, err := secboot.FromImage(blob)
				if err != nil {
					skipped++
					continue
				}
				v := normalizeSignerVendor(item.signer, id.OEMID)
				if vendorFilter != "" && v != strings.ToLower(vendorFilter) {
					continue
				}
				jtag := fallbackJTAGFromFilename(item.source, id.JTAGID)
				fam := catalog.Family{Vendor: v, JTAGID: jtag}
				if dryRun {
					fmt.Printf("  would import %s  JTAG=%s OEM=%s SW_ID=%d (%dB)\n",
						fam, id.JTAGID, id.OEMID, id.SWID, len(blob))
					added++
					continue
				}

				donor := &blankflash.Donor{
					Programmer: blob,
					Source:     item.source,
				}
				before := len(lib.Builds(fam))
				ref, err := lib.AddLoader(fam, donor, item.source)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ! error storing %s: %v\n", item.path, err)
					skipped++
					continue
				}
				if len(lib.Builds(fam)) == before {
					dup++
					continue
				}
				added++
				fmt.Printf("  + %s@%s  JTAG=%s OEM=%s SW_ID=%d (%dB)\n",
					fam, ref.Build, id.JTAGID, id.OEMID, id.SWID, len(blob))
			}

			verb := "imported"
			if dryRun {
				verb = "would import"
			}
			fmt.Printf("\n%s %d loader(s); %d already present, %d skipped (unparseable or unreadable).\n",
				verb, added, dup, skipped)
			return nil
		},
	}
	c.Flags().StringVar(&vendorFilter, "vendor", "", "filter by vendor id (e.g. motorola, xiaomi, samsung)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "simulate import without modifying the library")
	c.Flags().IntVar(&limit, "limit", 0, "max loaders to import (0 = all)")
	return c
}
