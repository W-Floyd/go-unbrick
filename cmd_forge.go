package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/qcdt"
	"go-unbrick/internal/secboot"
	"go-unbrick/internal/vendor"
)

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
	if len(res.Singleimage) > 0 {
		if err := write(filepath.Join(outDir, "singleimage.bin"), res.Singleimage); err != nil {
			return err
		}
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
// partition (xbl/abl/tz). Returns nil if none is parseable.
func targetIdentity(t *blankflash.Target) *secboot.Identity {
	for _, fn := range []string{"xbl.elf", "abl.elf", "tz.mbn"} {
		if b, ok := t.Parts[fn]; ok {
			if id, err := secboot.FromELF(b); err == nil {
				return id
			}
		}
	}
	for fn, b := range t.Parts {
		lower := strings.ToLower(fn)
		if strings.Contains(lower, "xbl") || strings.Contains(lower, "abl") || strings.Contains(lower, "tz") {
			if id, err := secboot.FromELF(b); err == nil {
				return id
			}
		}
	}
	return nil
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

		// Pre-flight secboot identity and anti-rollback validation
		if tgID := targetIdentity(t); tgID != nil && len(d.Programmer) > 0 {
			if ldID, err := secboot.FromELF(d.Programmer); err == nil {
				oemOK, reasons := secboot.Compatible(ldID, tgID)
				swStr := fmt.Sprintf("SW_ID=%d", ldID.SWID)
				if swName := activeCatalog().SWIDName(ldID.SWID); swName != "" {
					swStr = fmt.Sprintf("SW_ID=%d (%s)", ldID.SWID, swName)
				}
				fmt.Printf("  identity: loader OEM=%s HW=%s root=CA %s %s  vs target OEM=%s HW=%s root=CA %s\n",
					ldID.OEMID, ldID.HWID, ldID.Root, swStr, tgID.OEMID, tgID.HWID, tgID.Root)
				for _, r := range reasons {
					fmt.Fprintf(os.Stderr, "  ! %s\n", r)
				}
				if !oemOK {
					return fmt.Errorf("refusing to forge: loader OEM_ID %s != target OEM_ID %s (will not authenticate)", ldID.OEMID, tgID.OEMID)
				}
				rb := secboot.ValidateRollback(ldID, tgID)
				for _, r := range rb.Reasons {
					fmt.Fprintf(os.Stderr, "  ! [anti-rollback] %s\n", r)
				}
			}
		}

		res, err := drv.Assemble(d, t, vendor.AssembleOptions{Slot: tf.slot, Storage: storage, Provision: provision})
		if err != nil {
			return err
		}
		if err := writeForgeOutput(out, res); err != nil {
			return err
		}
		if len(res.Singleimage) > 0 {
			recs, _ := blankflash.Parse(res.Singleimage)
			fmt.Printf("forged singleimage.bin: %d bytes, %d records\n", len(res.Singleimage), len(blankflash.Index(recs)))
		} else {
			fmt.Printf("forged QFIL recovery bundle: %d files\n", len(res.Aux))
		}
		fmt.Printf("  donor loader: %s  cpu.name=%s\n", d.Source, d.CPUName)
		fmt.Printf("  target: %s  storage=%s\n", t.Source, firstNonEmpty(t.Storage, storage))
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "  ! %s\n", w)
		}
		runScript := "blank-flash.bat / blank-flash.sh"
		if len(res.Singleimage) == 0 {
			runScript = "flash.bat / flash.sh"
		}
		fmt.Printf("-> %s  (run %s with the device in EDL 9008)\n", out, runScript)
		return nil
	}
	return c
}
