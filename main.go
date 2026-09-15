// Command bfforge: unpack/pack the SINGLE_N_LONELY container, and the
// ingest -> harvest -> forge / catalog -> library -> derive pipeline that builds
// a device blankflash from a same-SoC sibling's signed loader.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"blankflash-forge/internal/bfforge"
	"blankflash-forge/internal/catalog"
	"blankflash-forge/internal/library"
	"blankflash-forge/internal/mtk"
	"blankflash-forge/internal/qcdt"
	"blankflash-forge/internal/secboot"
	"blankflash-forge/internal/upstream"
	"blankflash-forge/internal/vendor"
)

// v holds global config, resolved from flags, env (BFFORGE_*), and an optional
// config file. Persistent flags (--catalog, --library) are bound to it.
var v = viper.New()

func catalogDir() string { return v.GetString("catalog") }
func libraryDir() string { return v.GetString("library") }

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "bfforge",
		Short:         "Build a device blankflash from a same-SoC sibling's signed loader",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("catalog", "catalog", "catalog directory (env BFFORGE_CATALOG)")
	root.PersistentFlags().String("library", "library", "library directory (env BFFORGE_LIBRARY)")

	// Config plumbing: flags < env < config file resolve through viper.
	v.SetEnvPrefix("BFFORGE")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	_ = v.BindPFlag("catalog", root.PersistentFlags().Lookup("catalog"))
	_ = v.BindPFlag("library", root.PersistentFlags().Lookup("library"))
	cobra.OnInitialize(func() {
		v.SetConfigName(".bfforge")
		v.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home)
		}
		if err := v.ReadInConfig(); err != nil {
			if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound {
				fmt.Fprintln(os.Stderr, "warning: config:", err)
			}
		}
	})

	root.AddCommand(
		newUnpackCmd(), newPackCmd(), newIngestCmd(),
		newHarvestCmd(), newForgeCmd(), newInspectCmd(),
		newCatalogCmd(), newLibraryCmd(), newDeriveCmd(),
	)
	return root
}

// ---- shared helpers ----

func write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

type manifestEntry struct {
	Name string `json:"name"`
	Size int    `json:"size"`
}

// targetFlags holds the shared target-source flags (harvest/forge/derive/add-stock).
type targetFlags struct {
	bootloader, parts, gpt, slot string
}

func addTargetFlags(c *cobra.Command) *targetFlags {
	t := &targetFlags{}
	c.Flags().StringVar(&t.bootloader, "target-bootloader", "", "target stock bootloader.img")
	c.Flags().StringVar(&t.parts, "target-parts", "", "dir of raw target dumps (xbl_a.img ...)")
	c.Flags().StringVar(&t.gpt, "target-gpt", "", "target gpt.bin (from stock package)")
	c.Flags().StringVar(&t.slot, "slot", "a", "slot: a or b")
	return t
}

func (t *targetFlags) source() vendor.TargetSource {
	return vendor.TargetSource{Parts: t.parts, Bootloader: t.bootloader, GPT: t.gpt, Slot: t.slot}
}

func (t *targetFlags) load() (*bfforge.Target, error) {
	var gpt []byte
	if t.gpt != "" {
		var err error
		if gpt, err = os.ReadFile(t.gpt); err != nil {
			return nil, err
		}
	}
	switch {
	case t.parts != "":
		return bfforge.FromDumps(t.parts, t.slot, gpt)
	case t.bootloader != "":
		img, err := os.ReadFile(t.bootloader)
		if err != nil {
			return nil, err
		}
		return bfforge.FromBootloaderImg(img, gpt)
	default:
		return nil, fmt.Errorf("need --target-bootloader or --target-parts")
	}
}

func readProvision(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}

// writeForgeOutput writes singleimage.bin + aux and prints the standard summary.
func writeForgeOutput(outDir string, res *bfforge.ForgeResult) error {
	if err := write(filepath.Join(outDir, "singleimage.bin"), res.Singleimage); err != nil {
		return err
	}
	for n, b := range res.Aux {
		if err := write(filepath.Join(outDir, n), b); err != nil {
			return err
		}
	}
	return nil
}

// stripModels patches any extended-QCDT device-tree parts in place so a sibling
// model's boot chain matches the target (see internal/qcdt). Returns the names of
// the parts it changed.
func stripModels(t *bfforge.Target) ([]string, error) {
	var patched []string
	for fn, data := range t.Parts {
		out, changed, err := qcdt.StripModel(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fn, err)
		}
		if changed {
			t.Parts[fn] = out
			patched = append(patched, fn)
		}
	}
	sort.Strings(patched)
	return patched, nil
}

// targetIdentity reads the target's own secboot identity from a stock signed
// partition (xbl/abl). Returns nil if none is parseable.
func targetIdentity(t *bfforge.Target) *secboot.Identity {
	for _, fn := range []string{"xbl.elf", "abl.elf", "tz.mbn"} {
		if b, ok := t.Parts[fn]; ok {
			if id, err := secboot.FromELF(b); err == nil {
				return id
			}
		}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s != "" {
			return s
		}
	}
	return ""
}

func mark(ok bool) string {
	if ok {
		return "yes"
	}
	return "no "
}

func yesno(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ---- container: unpack / pack ----

func newUnpackCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "unpack <container>",
		Short: "explode a SINGLE_N_LONELY container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			blob, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			recs, err := bfforge.Parse(blob)
			if err != nil {
				return err
			}
			var manifest []manifestEntry
			for _, r := range recs {
				if r.Name == bfforge.Trailer {
					continue
				}
				if err := write(filepath.Join(out, r.Name), r.Data); err != nil {
					return err
				}
				manifest = append(manifest, manifestEntry{Name: r.Name, Size: len(r.Data)})
			}
			mj, _ := json.MarshalIndent(manifest, "", "  ")
			if err := write(filepath.Join(out, "manifest.json"), mj); err != nil {
				return err
			}
			for _, m := range manifest {
				fmt.Printf("  %10d  %s\n", m.Size, m.Name)
			}
			fmt.Printf("%d records -> %s\n", len(manifest), out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.MarkFlagRequired("out")
	return c
}

func newPackCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "pack <dir>",
		Short: "rebuild a container from an unpacked dir",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			mj, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if err != nil {
				return err
			}
			var manifest []manifestEntry
			if err := json.Unmarshal(mj, &manifest); err != nil {
				return err
			}
			var recs []bfforge.Record
			for _, m := range manifest {
				b, err := os.ReadFile(filepath.Join(dir, m.Name))
				if err != nil {
					return err
				}
				recs = append(recs, bfforge.Record{Name: m.Name, Data: b})
			}
			blob, err := bfforge.Build(bfforge.WithTrailer(recs))
			if err != nil {
				return err
			}
			if err := write(out, blob); err != nil {
				return err
			}
			fmt.Printf("packed %d records -> %s (%d bytes)\n", len(recs), out, len(blob))
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output container")
	c.MarkFlagRequired("out")
	return c
}

// ---- pipeline: ingest / harvest / forge ----

func newIngestCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "ingest <donor>",
		Short: "lift programmer.elf + qboot from a donor blankflash",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := bfforge.Ingest(args[0])
			if err != nil {
				return err
			}
			if err := write(filepath.Join(out, "programmer.elf"), d.Programmer); err != nil {
				return err
			}
			for n, b := range d.Recipes {
				if err := write(filepath.Join(out, n), b); err != nil {
					return err
				}
			}
			for n, b := range d.Qboot {
				if err := write(filepath.Join(out, n), b); err != nil {
					return err
				}
			}
			fmt.Printf("donor: cpu.name=%s storage=%s programmer.elf=%dB qboot=%v\n",
				d.CPUName, d.Storage, len(d.Programmer), sortedKeys(d.Qboot))
			fmt.Printf("-> %s\n", out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.MarkFlagRequired("out")
	return c
}

func newHarvestCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "harvest",
		Short: "extract target partitions + gpt from stock",
		Args:  cobra.NoArgs,
	}
	tf := addTargetFlags(c)
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.MarkFlagRequired("out")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		t, err := tf.load()
		if err != nil {
			return err
		}
		for fn, b := range t.Parts {
			if err := write(filepath.Join(out, "parts", fn), b); err != nil {
				return err
			}
		}
		if t.GPT != nil {
			if err := write(filepath.Join(out, "gpt.bin"), t.GPT); err != nil {
				return err
			}
		}
		partSizes := map[string]int{}
		for k, val := range t.Parts {
			partSizes[k] = len(val)
		}
		meta, _ := json.MarshalIndent(map[string]any{
			"storage": t.Storage, "flash_map": t.FlashMap, "source": t.Source, "parts": partSizes,
		}, "", "  ")
		if err := write(filepath.Join(out, "meta.json"), meta); err != nil {
			return err
		}
		fmt.Printf("target: storage=%s parts=%d gpt=%s\n", t.Storage, len(t.Parts), yesno(t.GPT != nil))
		for _, label := range sortedKeys(t.FlashMap) {
			fn := t.FlashMap[label]
			miss := ""
			if _, ok := t.Parts[fn]; !ok {
				miss = "  (MISSING)"
			}
			fmt.Printf("  %-12s %s%s\n", label, fn, miss)
		}
		fmt.Printf("-> %s\n", out)
		return nil
	}
	return c
}

func newForgeCmd() *cobra.Command {
	var donorPath, storage, provisionFrom, out string
	var stripModel bool
	c := &cobra.Command{
		Use:   "forge",
		Short: "assemble a target blankflash (one-shot, no library)",
		Args:  cobra.NoArgs,
	}
	tf := addTargetFlags(c)
	c.Flags().StringVar(&donorPath, "donor", "", "donor blankflash (zip/dir/singleimage.bin)")
	c.Flags().StringVar(&storage, "storage", "", "override target storage type (emmc/ufs)")
	c.Flags().StringVar(&provisionFrom, "provision-from", "", "XML file with a target-specific provisioning block")
	c.Flags().BoolVar(&stripModel, "strip-model", false, "strip the QCDT model field so a sibling-model boot chain matches (cross-model donation)")
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.MarkFlagRequired("donor")
	c.MarkFlagRequired("out")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		drv, ok := vendor.Detect(donorPath)
		if !ok {
			return fmt.Errorf("unrecognized donor package (no vendor driver matched): %s", donorPath)
		}
		d, err := drv.IngestDonor(donorPath)
		if err != nil {
			return err
		}
		t, err := drv.HarvestStock(tf.source())
		if err != nil {
			return err
		}
		if stripModel {
			patched, err := stripModels(t)
			if err != nil {
				return err
			}
			fmt.Printf("  stripped QCDT model field from: %v\n", patched)
		}
		provision, err := readProvision(provisionFrom)
		if err != nil {
			return err
		}
		res, err := drv.Assemble(d, t, vendor.AssembleOptions{Slot: tf.slot, Storage: storage, Provision: provision})
		if err != nil {
			return err
		}
		if err := writeForgeOutput(out, res); err != nil {
			return err
		}
		recs, _ := bfforge.Parse(res.Singleimage)
		fmt.Printf("forged singleimage.bin: %d bytes, %d records\n", len(res.Singleimage), len(bfforge.Index(recs)))
		fmt.Printf("  donor loader: %s  cpu.name=%s\n", d.Source, d.CPUName)
		fmt.Printf("  target: %s  storage=%s\n", t.Source, firstNonEmpty(t.Storage, storage))
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "  ! %s\n", w)
		}
		fmt.Printf("-> %s  (run blank-flash.bat / blank-flash.sh with the device in EDL 9008)\n", out)
		return nil
	}
	return c
}

// ---- inspect ----

func printIdentity(indent, label string, id *secboot.Identity) {
	fmt.Printf("%s%-16s root=CA %-4s OEM_ID=%s HW_ID=%s (JTAG=%s) SW_ID=%d key=RSA-%d\n",
		indent, label, id.Root, id.OEMID, id.HWID, id.JTAGID, id.SWID, id.KeyBits)
}

// inspectBytes reports the secboot identity of an ELF, or of every signed ELF
// record inside a SINGLE_N_LONELY container.
func inspectBytes(name string, b []byte) (int, error) {
	if secboot.IsELF(b) {
		id, err := secboot.FromELF(b)
		if err != nil {
			return 0, err
		}
		printIdentity("  ", name, id)
		return 1, nil
	}
	if bfforge.IsContainer(b) {
		recs, err := bfforge.Parse(b)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, r := range recs {
			if !secboot.IsELF(r.Data) {
				continue
			}
			if id, err := secboot.FromELF(r.Data); err == nil {
				printIdentity("  ", r.Name, id)
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
		Short: "dump the Qualcomm secboot identity (root / OEM_ID / HW_ID / SW_ID) of signed images",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			// MediaTek package: derive the chip from the scatter (no Qualcomm secboot).
			if drv, ok := vendor.Detect(path); ok && drv.Platform() == vendor.PlatformMediaTek {
				info, err := mtk.FromPackage(path)
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
				d, err := bfforge.Ingest(path)
				if err != nil {
					return err
				}
				fmt.Printf("%s (loader from donor):\n", path)
				id, err := secboot.FromELF(d.Programmer)
				if err != nil {
					return err
				}
				printIdentity("  ", "programmer.elf", id)
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fmt.Printf("%s:\n", path)
			n, err := inspectBytes(filepath.Base(path), b)
			if err != nil {
				// Last resort: treat as a donor blankflash (zip) and inspect its loader.
				if d, ierr := bfforge.Ingest(path); ierr == nil {
					if id, ferr := secboot.FromELF(d.Programmer); ferr == nil {
						printIdentity("  ", "programmer.elf", id)
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

// ---- catalog ----

func newCatalogCmd() *cobra.Command {
	c := &cobra.Command{Use: "catalog", Short: "browse the vendor/SoC/device catalog"}
	c.AddCommand(newCatalogListCmd(), newCatalogFamilyCmd(), newCatalogStubCmd())
	return c
}

var (
	reCodename = regexp.MustCompile(`(?i)blankflash[_-]`)
	reModel    = regexp.MustCompile(`(?i)XT\d{3,4}[A-Z]?`)
)

// codenameFromSource parses a device codename from a donor filename, e.g.
// "…/blankflash_GUAMP_RETBR_11_RPX31.Q2-58-17-7.zip" -> "guamp".
func codenameFromSource(src string) string {
	base := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
	if loc := reCodename.FindStringIndex(base); loc != nil {
		base = base[loc[1]:]
	}
	if i := strings.IndexAny(base, "_-. "); i >= 0 {
		base = base[:i]
	}
	return strings.ToLower(base)
}

func modelFromSource(src string) string {
	return strings.ToUpper(reModel.FindString(filepath.Base(src)))
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
					code := codenameFromSource(b.Meta.Source)
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
					if m := modelFromSource(b.Meta.Source); m != "" && len(d.Models) == 0 {
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
					mark(lib.HasLoaderForCPU(d.Vendor, d.CPUName)), mark(lib.HasStock(d.Vendor, d.Codename)))
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

// ---- library ----

func newLibraryCmd() *cobra.Command {
	c := &cobra.Command{Use: "library", Short: "manage the local loader + stock store"}
	c.AddCommand(newLibraryAddLoaderCmd(), newLibraryAddStockCmd(), newLibraryListCmd(), newLibrarySyncCmd())
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
			dir, ok := upstream.VendorDir[vendorID]
			if !ok {
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
				donor := &bfforge.Donor{Programmer: blob, Source: "bkerler/Loaders/" + dir + "/" + e.Name}
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
			fmt.Printf("stored loader %s@%s (cpu.name=%q storage=%s SW_ID=%d, %dB, sha256=%s)%s\n",
				fam, ref.Build, d.CPUName, d.Storage, swid, len(d.Programmer), ref.Meta.SHA256[:12], note)
			return nil
		},
	}
	c.Flags().StringVar(&vendorHint, "vendor", "", "vendor id, to disambiguate a shared cpu_name")
	return c
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
		dir, err := library.Open(libraryDir()).AddStock(d.Vendor, d.Codename, t)
		if err != nil {
			return err
		}
		fmt.Printf("stored stock for %s/%s: parts=%d gpt=%s storage=%s\n",
			d.Vendor, d.Codename, len(t.Parts), yesno(t.GPT != nil), t.Storage)
		fmt.Printf("-> %s\n", dir)
		return nil
	}
	return c
}

func newLibraryListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "loaders (by family) and stock (by device) on hand",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lib := library.Open(libraryDir())
			fmt.Println("loaders (by family; builds low SW_ID first = derive default):")
			for _, f := range lib.Loaders() {
				fmt.Printf("  %s\n", f)
				for _, b := range lib.Builds(f) {
					fmt.Printf("    SW_ID=%-4d %-26s OEM=%s HW=%s root=CA %s sha=%s\n",
						b.Meta.SWID, b.Build, b.Meta.OEMID, b.Meta.HWID, b.Meta.Root, b.Meta.SHA256[:12])
				}
			}
			fmt.Println("stock (by device):")
			for _, s := range lib.Stock() {
				fmt.Printf("  %s/%s\n", s.Vendor, s.Codename)
			}
			return nil
		},
	}
}

// ---- derive ----

func newDeriveCmd() *cobra.Command {
	var storage, provisionFrom, out, loaderBuild string
	var stripModel bool
	c := &cobra.Command{
		Use:   "derive <codename>",
		Short: "extrapolate a blankflash from a stored family loader + stock",
		Args:  cobra.ExactArgs(1),
	}
	tf := addTargetFlags(c)
	c.Flags().StringVar(&loaderBuild, "loader", "", "loader build id to use (default: newest)")
	c.Flags().BoolVar(&stripModel, "strip-model", false, "strip the QCDT model field so a sibling-model boot chain matches (cross-model donation)")
	c.Flags().StringVar(&storage, "storage", "", "override target storage type (emmc/ufs)")
	c.Flags().StringVar(&provisionFrom, "provision-from", "", "XML file with a target-specific provisioning block")
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.MarkFlagRequired("out")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		c2, err := catalog.Load(catalogDir())
		if err != nil {
			return err
		}
		dev, ok := c2.Device(args[0])
		if !ok {
			return fmt.Errorf("unknown codename %q; extrapolation is limited to catalog devices", args[0])
		}
		drv, ok := vendor.For(dev.Vendor)
		if !ok {
			return fmt.Errorf("no vendor driver for %q", dev.Vendor)
		}
		lib := library.Open(libraryDir())
		// Resolve the device's cpu_name to candidate JTAG-keyed loaders (lowest
		// SW_ID first). One cpu_name can span several silicon revisions, so this
		// may draw from more than one JTAG family.
		cands := lib.LoadersForCPU(dev.Vendor, dev.CPUName)
		if len(cands) == 0 {
			sibs, _ := c2.Siblings(args[0])
			codes := make([]string, len(sibs))
			for i, s := range sibs {
				codes[i] = s.Codename
			}
			return fmt.Errorf("no loader in library for cpu_name %q (%s); ingest one from a sibling first "+
				"(library add-loader), donors: %v", dev.CPUName, dev.CPUFamily(), codes)
		}
		lref := &cands[0]
		if loaderBuild != "" {
			lref = nil
			for i := range cands {
				if cands[i].Build == loaderBuild {
					lref = &cands[i]
					break
				}
			}
			if lref == nil {
				return fmt.Errorf("no loader build %q among candidates for %q", loaderBuild, dev.CPUName)
			}
		}
		fam := lref.Family
		donor, lref, err := lib.FindLoader(fam, lref.Build)
		if err != nil {
			return err
		}

		var target *bfforge.Target
		if tf.parts != "" || tf.bootloader != "" {
			target, err = drv.HarvestStock(tf.source())
		} else if lib.HasStock(dev.Vendor, dev.Codename) {
			target, err = lib.FindStock(dev.Vendor, dev.Codename)
		} else {
			return fmt.Errorf("no stock for %s in library and no --target-... given; "+
				"add it with library add-stock or pass the target's own images", dev.Codename)
		}
		if err != nil {
			return err
		}
		if stripModel {
			patched, err := stripModels(target)
			if err != nil {
				return err
			}
			fmt.Printf("  stripped QCDT model field from: %v\n", patched)
		}

		provisionData, err := readProvision(provisionFrom)
		if err != nil {
			return err
		}
		// Identity check: compare the chosen loader against the target's own stock
		// signing identity (read from its xbl/abl). OEM mismatch is fatal (won't
		// authenticate); HW/root divergence is advisory (loader-stage acceptance is
		// coarser, provable only on-device).
		if tgID := targetIdentity(target); tgID != nil {
			if ldID, err := secboot.FromELF(donor.Programmer); err == nil {
				oemOK, reasons := secboot.Compatible(ldID, tgID)
				fmt.Printf("  identity: loader OEM=%s HW=%s root=CA %s SW_ID=%d  vs target OEM=%s HW=%s root=CA %s\n",
					ldID.OEMID, ldID.HWID, ldID.Root, ldID.SWID, tgID.OEMID, tgID.HWID, tgID.Root)
				for _, r := range reasons {
					fmt.Fprintf(os.Stderr, "  ! %s\n", r)
				}
				if !oemOK {
					return fmt.Errorf("refusing to forge: loader OEM_ID %s != target OEM_ID %s (will not authenticate)", ldID.OEMID, tgID.OEMID)
				}
			}
		}

		res, err := drv.Assemble(donor, target, vendor.AssembleOptions{Slot: tf.slot, Storage: storage, Provision: provisionData})
		if err != nil {
			return err
		}
		if err := writeForgeOutput(out, res); err != nil {
			return err
		}
		recs, _ := bfforge.Parse(res.Singleimage)
		fmt.Printf("derived %s (%s) blankflash: %d bytes, %d records\n",
			dev.Codename, dev.Name, len(res.Singleimage), len(bfforge.Index(recs)))
		fmt.Printf("  family: %s  loader: %s@%s SW_ID=%d (from %s)\n", fam, fam, lref.Build, lref.Meta.SWID, lref.Meta.Source)
		fmt.Printf("  target: %s  storage=%s\n", target.Source, firstNonEmpty(target.Storage, storage))
		if len(cands) > 1 && loaderBuild == "" {
			ladder := make([]string, len(cands))
			for i, b := range cands {
				ladder[i] = fmt.Sprintf("%s(SW_ID=%d)", b.Build, b.Meta.SWID)
			}
			fmt.Printf("  using lowest SW_ID; if it stalls at Sahara (rejected, harmless), step up: --loader <build>\n")
			fmt.Printf("  ladder: %s\n", strings.Join(ladder, " -> "))
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "  ! %s\n", w)
		}
		fmt.Printf("-> %s  (run blank-flash.bat / blank-flash.sh with the device in EDL 9008)\n", out)
		return nil
	}
	return c
}
