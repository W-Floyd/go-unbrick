package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/edl"
	"github.com/W-Floyd/go-unbrick/internal/library"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// loaderFromLibrary is the --loader value that picks a stored loader by the
// chip's own fused identity.
const loaderFromLibrary = "library"

func newEDLReconCmd() *cobra.Command {
	var f deviceReconFlags
	var o edl.OpenOptions
	c := &cobra.Command{
		Use:   "recon",
		Short: "identify a device in EDL (9008) mode, and derive from it",
		Long: `Reconnaissance over EDL against a device in Qualcomm 9008 mode.

Without a loader, speaks only Sahara: the PBL reports its fused chip identity
(MSM/JTAG id, OEM id, the hash of the signing root) and no programmer is
uploaded. Every stored loader for that chip is then judged against the fuses,
so the report says which one the PBL will accept before any is sent.

With --loader, the programmer is uploaded and Firehose lists the live GPT and,
with --read-partitions, reads the identity and boot-chain partitions through
the same recognizers a firmware package goes through. --loader=library picks
the stored loader whose signing root matches the fuses. A running programmer
stays until the device is power-cycled.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEDLRecon(cmd.Context(), o, f)
		},
	}
	f.register(c)
	c.Flags().StringVar(&o.Loader, "loader", "", "Firehose programmer to upload, or \"library\" to pick a stored one matching the fuses")
	c.Flags().StringVar(&o.Memory, "memory", "", "storage type for Firehose: ufs or emmc (default: the loader decides)")
	c.Flags().IntVar(&o.WaitSeconds, "wait", 10, "seconds to wait for a device in 9008 mode")
	return c
}

func runEDLRecon(ctx context.Context, o edl.OpenOptions, f deviceReconFlags) error {
	r, err := ensureEDL(ctx)
	if err != nil {
		return err
	}
	lib := library.Open(libraryDir())
	var session bytes.Buffer

	if o.Loader == loaderFromLibrary {
		stop := spin("reading chip identity over Sahara…")
		chip, err := r.SaharaInfo(ctx, o.WaitSeconds, &session)
		stop()
		if err != nil {
			return err
		}
		switch {
		case chip.Mode == "firehose" || chip.Mode == "quiet":
			// A programmer from an earlier session is still running; use it.
			o.Loader = ""
		case chip.Mode != "sahara" || chip.HWID == "":
			return fmt.Errorf("--loader=library needs the chip identity, but the device answered in %s mode; power-cycle into EDL", chip.Mode)
		default:
			best := bestLoader(judgeLibrary(lib, chip))
			if best == nil {
				return fmt.Errorf("no stored loader for JTAG %s / OEM_ID %s that the fuses accept", chip.JTAGID(), chip.OEMID())
			}
			o.Loader, o.Chip = best.path, chip
		}
	}

	label := "reading chip identity over Sahara…"
	if o.Loader != "" {
		label = "uploading loader and reading the GPT…"
	}
	stop := spin("%s", label)
	tr, err := edl.Open(ctx, r, o, &session)
	stop()
	if err != nil {
		if tail := lastLines(session.String(), 8); tail != "" {
			fmt.Fprintln(os.Stderr, tail)
		}
		return err
	}
	return runTransportRecon(tr, f, func() {
		printEDLSections(tr, activeCatalog(), lib, f, session.String())
	})
}

// judgedLoader is one candidate programmer and what the fuses make of it.
type judgedLoader struct {
	label   string
	path    string
	swid    uint64
	verdict edl.Verdict
	restr   secboot.Restriction
}

// judgeLibrary judges every stored loader filed under the chip's JTAG family,
// for whichever vendor signs with the chip's OEM_ID.
func judgeLibrary(lib *library.Library, chip *edl.ChipInfo) []judgedLoader {
	jtag := chip.JTAGID()
	if jtag == "" {
		return nil
	}
	var vendors []string
	if d, ok := vendor.ForOEMID(chip.OEMID()); ok {
		vendors = append(vendors, d.ID())
	} else {
		for _, fam := range lib.Loaders() {
			if fam.JTAGID == jtag {
				vendors = append(vendors, fam.Vendor)
			}
		}
	}
	var out []judgedLoader
	for _, v := range vendors {
		for _, ref := range lib.LoadersForJTAGs(v, []string{jtag}) {
			j := judgedLoader{label: ref.Family.String() + "@" + ref.Build, path: lib.LoaderPath(ref), swid: ref.Meta.SWID}
			data, err := os.ReadFile(j.path)
			if err != nil {
				j.verdict = edl.Verdict{Reasons: []string{err.Error()}}
			} else if id, err := secboot.FromELF(data); err != nil {
				j.verdict = edl.Verdict{Reasons: []string{"unsigned or unparseable: " + err.Error()}}
			} else {
				j.verdict = edl.Judge(chip, id)
				j.restr = secboot.ScanRestriction(data)
			}
			out = append(out, j)
		}
	}
	return out
}

// bestLoader prefers a root-hash-proven loader, then any not ruled out; the
// input is already lowest-SW_ID first, which is the safe order against
// anti-rollback.
func bestLoader(js []judgedLoader) *judgedLoader {
	for i := range js {
		if js[i].verdict.Accept && js[i].verdict.Proven {
			return &js[i]
		}
	}
	for i := range js {
		if js[i].verdict.Accept {
			return &js[i]
		}
	}
	return nil
}

func printEDLSections(tr *edl.Transport, cat *catalog.Catalog, lib *library.Library, f deviceReconFlags, session string) {
	chip := tr.S.Chip
	serial := ""
	if chip != nil {
		serial = chip.Serial
	}
	fmt.Printf("EDL Device: %s\n", firstNonEmpty(mask(f.redact, serial), "(serial unavailable)"))

	hdr := "  Chip (Sahara, from fuses):"
	if tr.ChipCached {
		hdr = "  Chip (cached from a prior EDL session):"
	}
	fmt.Println(cHdr(hdr))
	if chip == nil {
		printField("Identity", cWarn("unavailable — a programmer was already running and no cached identity; power-cycle into EDL for Sahara"))
	} else {
		if tr.ChipCached {
			printField("Source", cWarn("cached — loader still running, identity confirmed by storage serial"))
		}
		printField("Sahara", fmt.Sprintf("protocol v%d", chip.SaharaVersion))
		printField("Serial", mask(f.redact, chip.Serial))
		if j := chip.JTAGID(); j != "" {
			desc := j
			if soc, ok := cat.SoCByJTAG(j); ok {
				desc += " (" + soc + ")"
			}
			printField("MSM / JTAG ID", desc)
		}
		if o := chip.OEMID(); o != "" {
			desc := o
			if d, ok := vendor.ForOEMID(o); ok {
				desc += " (" + d.ID() + ")"
			}
			printField("OEM ID", desc)
		}
		if m := chip.ModelID(); m != "" && m != "0000" {
			printField("Model ID", m)
		}
		switch {
		case chip.PKHash == "":
			printField("Secure Boot", cWarn("OEM_PK_HASH not reported (Sahara v3 restriction)"))
		case chip.Fused():
			printField("Secure Boot", cGood("fused")+" — loaders must chain to this root")
			printField("OEM PK Hash", chip.PKHash)
		default:
			printField("Secure Boot", cWarn("unfused — any loader is accepted"))
		}
		if devs := devicesByJTAG(cat, chip.JTAGID()); len(devs) > 0 {
			printField("Catalog Devices", strings.Join(devs, ", "))
		}
	}

	fmt.Println("\n" + cHdr("  Loaders:"))
	switch {
	case tr.Loader != "":
		v := cWarn("no Firehose session")
		if tr.Firehose() {
			v = cGood("accepted, Firehose running")
		}
		printField("Using", tr.Loader+" — "+v)
	case tr.Firehose():
		printField("Using", "the programmer an earlier session left running")
	}
	if chip != nil {
		js := judgeLibrary(lib, chip)
		if len(js) == 0 {
			printField("Library", cWarn(fmt.Sprintf("no stored loader for JTAG %s", chip.JTAGID())))
		}
		for _, j := range js {
			line := j.label + " — " + verdictText(j.verdict)
			if n := restrictionNote(j.restr); n != "" {
				line += "; " + n
			}
			printField(fmt.Sprintf("SW_ID %d", j.swid), line)
			if j.verdict.Accept && !tr.Firehose() {
				fmt.Printf("    %-20s %s\n", "", "--loader="+j.path)
			}
		}
	}

	if tr.Firehose() {
		fmt.Println("\n" + cHdr("  Storage & Partitions:"))
		if tr.GPT != nil {
			printField("LUNs", fmt.Sprintf("%d", len(tr.GPT.LunSize)))
		}
		printField("Active Slot", tr.Slot())
		printPartitionSections(tr, f.readCap)
	}
	if f.raw {
		fmt.Println("\n" + cHdr("  Raw edlclient output:"))
		fmt.Println(mask(f.redact, session))
	}
}

// restrictionNote is what the loader's own marker strings say about its read
// policy — a warning that a full backup may be refused, not a proof of which
// partitions (the allowlist is runtime, resolved only by probing the device).
func restrictionNote(r secboot.Restriction) string {
	if r.RangeGated {
		return cWarn("may restrict reads (boot-chain only on tested units; identity/calibration refused)")
	}
	if r.HandlerGated || r.PeekPokeOff {
		return cWarn("may gate some Firehose verbs")
	}
	return ""
}

func verdictText(v edl.Verdict) string {
	why := strings.Join(v.Reasons, "; ")
	switch {
	case !v.Accept:
		return cWarn("refused: " + why)
	case v.Proven && why == "":
		return cGood("root matches fuses")
	case v.Proven:
		return cGood("accepted") + " (" + why + ")"
	default:
		return "not ruled out (" + why + ")"
	}
}

func devicesByJTAG(cat *catalog.Catalog, jtag string) []string {
	if cat == nil || jtag == "" {
		return nil
	}
	var out []string
	for _, d := range cat.AllDevices() {
		for _, j := range d.JTAGIDs {
			if strings.EqualFold(j, jtag) {
				out = append(out, d.Codename)
				break
			}
		}
	}
	return out
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
