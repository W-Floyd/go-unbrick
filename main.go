// Command unbrick: unpack/pack the SINGLE_N_LONELY container, and the
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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/catalog"
	"go-unbrick/internal/efi"
	"go-unbrick/internal/imgdiff"
	"go-unbrick/internal/library"
	"go-unbrick/internal/mediatek"
	"go-unbrick/internal/qcdt"
	"go-unbrick/internal/secboot"
	"go-unbrick/internal/upstream"
	"go-unbrick/internal/vendor"
)

// v holds global config, resolved from flags, env (UNBRICK_*), and an optional
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
		Use:           "unbrick",
		Short:         "Build a device blankflash from a same-SoC sibling's signed loader",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("catalog", "catalog", "catalog directory (env UNBRICK_CATALOG)")
	root.PersistentFlags().String("library", "library", "library directory (env UNBRICK_LIBRARY)")

	// Config plumbing: flags < env < config file resolve through viper.
	v.SetEnvPrefix("UNBRICK")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	_ = v.BindPFlag("catalog", root.PersistentFlags().Lookup("catalog"))
	_ = v.BindPFlag("library", root.PersistentFlags().Lookup("library"))
	cobra.OnInitialize(func() {
		v.SetConfigName(".unbrick")
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
		newStockCmd(), newEFICmd(), newDiffCmd(),
	)
	return root
}

// ---- diff ----

// newDiffCmd compares two signed images in terms that survive re-signing. The
// raw byte count is reported too, because seeing it next to the verdict is the
// point: it is routinely an order of magnitude larger than the real change.
func newDiffCmd() *cobra.Command {
	var verbose bool
	c := &cobra.Command{
		Use:   "diff <a> <b>",
		Short: "compare two signed images, separating re-signing from real change",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			b, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			r, err := imgdiff.Compare(a, b)
			if err != nil {
				return err
			}
			rawPct := 0.0
			if r.SizeA > 0 {
				rawPct = 100 * float64(r.RawDiffering) / float64(r.SizeA)
			}
			fmt.Printf("%s vs %s\n", filepath.Base(args[0]), filepath.Base(args[1]))
			fmt.Printf("  verdict: %s\n", r.Verdict)
			if r.Note != "" {
				fmt.Printf("  %s\n", r.Note)
			}
			fmt.Printf("  raw byte diff: %d of %d (%.1f%%) -- not a measure of change\n",
				r.RawDiffering, r.SizeA, rawPct)
			for _, s := range r.Segments {
				kind := "payload"
				if s.Hash {
					kind = "hash/sig"
				}
				if s.Differing == 0 {
					fmt.Printf("  seg %d %-8s paddr=0x%-9x %7d bytes  identical\n", s.Index, kind, s.Paddr, s.Size)
					continue
				}
				note := ""
				switch {
				case s.Hash:
					note = "  (re-signed; expected)"
				case len(s.Reports) > 0:
					note = "  (" + s.Reports[0].Summary() + ")"
				case s.Opaque():
					note = "  (opaque: compressed or key material)"
				case s.NamesEqual && !s.NamesOrdered:
					note = fmt.Sprintf("  (same %d names, reordered)", len(s.NamesA))
				}
				fmt.Printf("  seg %d %-8s paddr=0x%-9x %7d bytes  %d differing%s\n",
					s.Index, kind, s.Paddr, s.Size, s.Differing, note)
				if !verbose {
					continue
				}
				for i, run := range s.Runs {
					if i >= 6 {
						fmt.Printf("      ... %d more runs\n", len(s.Runs)-6)
						break
					}
					tag := "structured"
					if run.Opaque {
						tag = "opaque"
					}
					fmt.Printf("      +%-8d %7d bytes  entropy %.2f  %s\n", run.Start, run.Len, run.Entropy, tag)
				}
				if s.NamesEqual {
					order := "same order"
					if !s.NamesOrdered {
						order = "reordered"
					}
					fmt.Printf("      name table: %d names, identical set, %s\n", len(s.NamesA), order)
				}
				for _, rep := range s.Reports {
					printReport("      ", rep)
				}
			}
			for _, rep := range r.Reports {
				fmt.Printf("  %s, compared independently of layout: %s\n", rep.Kind, rep.Summary())
				for _, line := range rep.Detail {
					fmt.Printf("      %s\n", line)
				}
			}
			if r.OutsideDiffering > 0 {
				fmt.Printf("  outside segments: %d differing\n", r.OutsideDiffering)
				if r.StampA != "" || r.StampB != "" {
					fmt.Printf("      %s\n      %s\n", r.StampA, r.StampB)
				}
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "show each differing run with its entropy")
	return c
}

// printReport renders an analyzer's finding. The command prints what an
// analyzer produced without knowing which formats exist; teaching the tool a
// new one means registering an analyzer, not editing this.
func printReport(indent string, r imgdiff.Report) {
	fmt.Printf("%s%s: %s\n", indent, r.Kind, r.Summary())
	for _, line := range r.Detail {
		fmt.Printf("%s  %s\n", indent, line)
	}
}

// ---- stock package ----

func newStockCmd() *cobra.Command {
	c := &cobra.Command{Use: "stock", Short: "work with an OEM stock firmware package"}
	c.AddCommand(newStockExtractCmd())
	return c
}

func newStockExtractCmd() *cobra.Command {
	var out string
	var super bool
	c := &cobra.Command{
		Use:   "extract <stock.zip>",
		Short: "write every partition image in a stock package to a directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			drv, _, ok := vendor.DetectStock(path)
			if !ok {
				return fmt.Errorf("unrecognized stock package (no vendor driver matched): %s", path)
			}
			ex, ok := drv.(vendor.StockExploder)
			if !ok {
				return fmt.Errorf("%s packages cannot be exploded yet: %w", drv.ID(), vendor.ErrUnsupported)
			}
			names, err := ex.ExplodeStock(path, out, vendor.ExplodeOptions{Super: super})
			if err != nil {
				// Partial output is still useful; only a total failure is fatal.
				if len(names) == 0 {
					return err
				}
				fmt.Fprintf(os.Stderr, "  ! %v\n", err)
			}
			for _, n := range names {
				if fi, err := os.Stat(filepath.Join(out, n)); err == nil {
					fmt.Printf("  %12d  %s\n", fi.Size(), n)
				}
			}
			fmt.Printf("%d images (%s) -> %s\n", len(names), drv.ID(), out)
			if !super {
				fmt.Println("  (super image skipped; --super to join it)")
			}
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output directory")
	c.Flags().BoolVar(&super, "super", false, "also join and write the multi-gigabyte super image")
	c.MarkFlagRequired("out")
	return c
}

// ---- efi ----

// efiInputs resolves any supported input to named images to scan: a stock
// package explodes to its partitions, a SINGLE_N_LONELY container to its
// records, and anything else (a bare abl.elf/xbl.elf, a raw dump) is itself.
func efiInputs(path string) (map[string][]byte, error) {
	if _, sp, ok := vendor.DetectStock(path); ok {
		t, err := sp.HarvestStockPackage(path)
		if err != nil {
			return nil, err
		}
		return t.Parts, nil
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		out := map[string][]byte{}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(path, e.Name())); err == nil {
				out[e.Name()] = b
			}
		}
		return out, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if blankflash.IsContainer(b) {
		recs, err := blankflash.Parse(b)
		if err != nil {
			return nil, err
		}
		out := map[string][]byte{}
		for _, r := range recs {
			if r.Name != blankflash.Trailer {
				out[r.Name] = r.Data
			}
		}
		return out, nil
	}
	return map[string][]byte{filepath.Base(path): b}, nil
}

func newEFICmd() *cobra.Command {
	var out, guids string
	c := &cobra.Command{
		Use:   "efi <stock.zip | abl.elf | container | dir>",
		Short: "list or extract the UEFI modules in a boot chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imgs, err := efiInputs(args[0])
			if err != nil {
				return err
			}
			var names map[string]string
			if guids != "" {
				f, err := os.Open(guids)
				if err != nil {
					return err
				}
				defer f.Close()
				if names, err = efi.LoadGUIDNames(f); err != nil {
					return err
				}
			}
			total := 0
			for _, img := range sortedKeys(imgs) {
				vols := efi.Volumes(imgs[img])
				if len(vols) == 0 {
					continue
				}
				mods, err := efi.Extract(imgs[img])
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ! %s: %v\n", img, err)
					continue
				}
				efi.ApplyNames(mods, names)
				fmt.Printf("%s: %d volume(s), %d modules\n", img, len(vols), len(mods))
				for _, m := range mods {
					if out == "" {
						fmt.Printf("  %s  type=0x%02x %-32s %d bytes\n", m.GUID, m.Type, m.Name, len(m.Data))
						continue
					}
					dst := filepath.Join(out, strings.TrimSuffix(img, filepath.Ext(img)), m.Filename())
					if err := write(dst, m.Data); err != nil {
						return err
					}
				}
				total += len(mods)
			}
			if total == 0 {
				fmt.Println("no UEFI firmware volumes found")
				return nil
			}
			if out != "" {
				fmt.Printf("%d modules -> %s\n", total, out)
			}
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "extract modules to this directory (default: list only)")
	c.Flags().StringVar(&guids, "guids", "", "CSV of guid,name to name modules that carry no UI section")
	return c
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

func (t *targetFlags) load() (*blankflash.Target, error) {
	var gpt []byte
	if t.gpt != "" {
		var err error
		if gpt, err = os.ReadFile(t.gpt); err != nil {
			return nil, err
		}
	}
	switch {
	case t.parts != "":
		return blankflash.FromDumps(t.parts, t.slot, gpt)
	case t.bootloader != "":
		img, err := os.ReadFile(t.bootloader)
		if err != nil {
			return nil, err
		}
		return blankflash.FromBootloaderImg(img, gpt)
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
func writeForgeOutput(outDir string, res *blankflash.ForgeResult) error {
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
func stripModels(t *blankflash.Target) ([]string, error) {
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
func targetIdentity(t *blankflash.Target) *secboot.Identity {
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
			recs, err := blankflash.Parse(blob)
			if err != nil {
				return err
			}
			var manifest []manifestEntry
			for _, r := range recs {
				if r.Name == blankflash.Trailer {
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
			var recs []blankflash.Record
			for _, m := range manifest {
				b, err := os.ReadFile(filepath.Join(dir, m.Name))
				if err != nil {
					return err
				}
				recs = append(recs, blankflash.Record{Name: m.Name, Data: b})
			}
			blob, err := blankflash.Build(blankflash.WithTrailer(recs))
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
			d, err := blankflash.Ingest(args[0])
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
		recs, _ := blankflash.Parse(res.Singleimage)
		fmt.Printf("forged singleimage.bin: %d bytes, %d records\n", len(res.Singleimage), len(blankflash.Index(recs)))
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
	if blankflash.IsContainer(b) {
		recs, err := blankflash.Parse(b)
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
				info, err := mediatek.FromPackage(path)
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
				d, err := blankflash.Ingest(path)
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
				if d, ierr := blankflash.Ingest(path); ierr == nil {
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
	c.AddCommand(newCatalogListCmd(), newCatalogFamilyCmd(), newCatalogStubCmd(), newCatalogBackfillCmd())
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
					// The loader's family JTAG_ID is this device's own silicon (the
					// source names the device), so pin it exactly.
					if isRealJTAG(fam.JTAGID) && !slices.Contains(d.JTAGIDs, fam.JTAGID) {
						d.JTAGIDs = append(d.JTAGIDs, fam.JTAGID)
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
					add(fam.Vendor, codenameFromSource(b.Meta.Source), fam.JTAGID)
					add(fam.Vendor, modelFromSource(b.Meta.Source), fam.JTAGID)
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
					for j := range byIdent[key{d.Vendor, strings.ToUpper(reModel.FindString(m))}] {
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

// ---- library ----

func newLibraryCmd() *cobra.Command {
	c := &cobra.Command{Use: "library", Short: "manage the local loader + stock store"}
	c.AddCommand(newLibraryAddLoaderCmd(), newLibraryAddStockCmd(), newLibraryAddStockZipCmd(),
		newLibraryHarvestDonorsCmd(), newLibraryListCmd(), newLibrarySyncCmd())
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
			fmt.Printf("stored loader %s@%s (cpu.name=%q storage=%s SW_ID=%d, %dB, sha256=%s)%s\n",
				fam, ref.Build, d.CPUName, d.Storage, swid, len(d.Programmer), ref.Meta.SHA256[:12], note)
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
	fmt.Printf("stored stock %s/%s@%s: parts=%d gpt=%s storage=%s\n",
		ref.Vendor, ref.Codename, ref.Build, len(t.Parts), yesno(t.GPT != nil), t.Storage)
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
	return &cobra.Command{
		Use:   "list",
		Short: "loaders (by family) and stock (by device) on hand",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lib, err := stockLibrary()
			if err != nil {
				return err
			}
			fmt.Println("loaders (by family; builds low SW_ID first = derive default):")
			for _, f := range lib.Loaders() {
				fmt.Printf("  %s\n", f)
				for _, b := range lib.Builds(f) {
					fmt.Printf("    SW_ID=%-4d %-26s OEM=%s HW=%s root=CA %s sha=%s\n",
						b.Meta.SWID, b.Build, b.Meta.OEMID, b.Meta.HWID, b.Meta.Root, b.Meta.SHA256[:12])
				}
			}
			fmt.Println("stock (by device; builds oldest first, newest = derive default):")
			lastDev := ""
			for _, s := range lib.Stock() {
				if dev := s.Vendor + "/" + s.Codename; dev != lastDev {
					fmt.Printf("  %s\n", dev)
					lastDev = dev
				}
				fmt.Printf("    %-22s %s\n", s.Build, s.Meta.Source)
			}
			return nil
		},
	}
}

// ---- derive ----

func newDeriveCmd() *cobra.Command {
	var storage, provisionFrom, out, loaderBuild, stockBuild string
	var stripModel bool
	c := &cobra.Command{
		Use:   "derive <codename>",
		Short: "extrapolate a blankflash from a stored family loader + stock",
		Args:  cobra.ExactArgs(1),
	}
	tf := addTargetFlags(c)
	c.Flags().StringVar(&loaderBuild, "loader", "", "loader build id to use (default: newest)")
	c.Flags().StringVar(&stockBuild, "stock", "", "stock build id to use (default: newest)")
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
		lib, err := stockLibrary()
		if err != nil {
			return err
		}
		// Resolve candidate loaders (lowest SW_ID first). A recorded jtag_id is
		// the fact the PBL enforces, so it keys exactly; the cpu_name bridge is
		// the fallback and is lossy (one cpu_name spans several JTAG families).
		via := fmt.Sprintf("cpu_name %q", dev.CPUName)
		if len(dev.JTAGIDs) > 0 {
			via = fmt.Sprintf("jtag_id %v", dev.JTAGIDs)
		}
		cands := lib.CandidateLoaders(dev)
		if len(cands) == 0 {
			sibs, _ := c2.Siblings(args[0])
			codes := make([]string, len(sibs))
			for i, s := range sibs {
				codes[i] = s.Codename
			}
			return fmt.Errorf("no loader in library via %s (%s); ingest one from a sibling first "+
				"(library add-loader), donors: %v", via, dev.CPUFamily(), codes)
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
				return fmt.Errorf("no loader build %q among candidates for %s (%s)", loaderBuild, args[0], via)
			}
		}
		fam := lref.Family
		donor, lref, err := lib.FindLoader(fam, lref.Build)
		if err != nil {
			return err
		}

		var target *blankflash.Target
		var sref *library.StockRef
		if tf.parts != "" || tf.bootloader != "" {
			target, err = drv.HarvestStock(tf.source())
		} else if lib.HasStock(dev.Vendor, dev.Codename) {
			target, sref, err = lib.FindStock(dev.Vendor, dev.Codename, stockBuild)
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
		recs, _ := blankflash.Parse(res.Singleimage)
		fmt.Printf("derived %s (%s) blankflash: %d bytes, %d records\n",
			dev.Codename, dev.Name, len(res.Singleimage), len(blankflash.Index(recs)))
		fmt.Printf("  family: %s  loader: %s@%s SW_ID=%d (from %s)\n", fam, fam, lref.Build, lref.Meta.SWID, lref.Meta.Source)
		fmt.Printf("  target: %s  storage=%s\n", target.Source, firstNonEmpty(target.Storage, storage))
		if sref != nil {
			if others := lib.StockBuilds(dev.Vendor, dev.Codename); len(others) > 1 && stockBuild == "" {
				ids := make([]string, len(others))
				for i, s := range others {
					ids[i] = s.Build
				}
				fmt.Printf("  using newest of %d stock builds (%s); select another: --stock <build>\n",
					len(others), strings.Join(ids, ", "))
			}
		}
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
