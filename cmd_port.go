package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/adb"
	"github.com/W-Floyd/go-unbrick/internal/arsc"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/fdt"
	"github.com/W-Floyd/go-unbrick/internal/port"
	_ "github.com/W-Floyd/go-unbrick/internal/port/nura" // registers the Nura emitter
	"github.com/W-Floyd/go-unbrick/internal/qfil"
)

func newPortCmd() *cobra.Command {
	var out, sizeMM, distro, kernelTree, serial string
	var live, checkDTS bool
	var referenceDTS, referencePanel, socDTSI []string
	c := &cobra.Command{
		Use:   "port <stock package>",
		Short: "draft a Linux port (device packaging and hardware report) from a stock package",
		Long: `Reads a stock Android package for what a port needs to know: the boot image
layout, the partition table, the board's device-tree overlays (variants,
displays, touch, audio, charging, camera parts), the screen's shape and the
vendor build.prop, and writes a hardware report, a gmobile display file, and
the chosen distribution's packaging (--distro). A field the package cannot
settle is a TODO in the draft, not a guess.

Reading the vendor build.prop opens the dynamic-partition super image, which
for a package that ships it as sparse chunks takes about half a minute.

  unbrick port XT2413-2_FOGONA_….xml.zip --distro nura -o port/`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			em, ok := port.Lookup(distro)
			if !ok {
				return fmt.Errorf("no emitter for distribution %q (have: %s)", distro, strings.Join(port.IDs(), ", "))
			}
			prog := newPortProgress()
			defer prog.done()
			carve.Progress = prog.detail
			pkg, unknown, blob, err := readPackage(args[0], prog.say)
			if err != nil {
				return err
			}
			if live {
				prog.say("asking the device over adb")
				dev, err := adb.Open(adb.Options{Serial: serial, Elevate: "auto"})
				if err != nil {
					return fmt.Errorf("--live: %w", err)
				}
				pkg.Live = port.NewLive(dev.R.Sections, dev.R.CmdlineRaw)
			}
			prog.say("writing the bundle")
			if sizeMM != "" {
				w, h, ok := strings.Cut(sizeMM, "x")
				pkg.SizeMM[0], _ = strconv.Atoi(w)
				pkg.SizeMM[1], _ = strconv.Atoi(h)
				if !ok || pkg.SizeMM[0] <= 0 || pkg.SizeMM[1] <= 0 {
					return fmt.Errorf("--size-mm wants WIDTHxHEIGHT in millimetres, e.g. 68x151")
				}
			}
			if len(socDTSI) > 0 && kernelTree == "" {
				return fmt.Errorf("--soc-dtsi adds to what --kernel-tree matches: name the kernel tree it applies to")
			}
			if kernelTree != "" {
				var compats []string
				for _, pt := range pkg.DT.Parts {
					compats = append(compats, pt.Compatible)
				}
				if pkg.Mainline, err = port.ScanKernelTree(kernelTree, compats); err != nil {
					return fmt.Errorf("--kernel-tree: %w", err)
				}
				pkg.KernelTree = kernelTree
				if pkg.KernelConfig != nil {
					d := port.CompareConfig(pkg.KernelConfig, port.KconfigSymbols(kernelTree))
					pkg.ConfigDiff = &d
					var items []string
					for _, c := range pkg.ConfigChoices() {
						items = append(items, c.Items...)
					}
					if len(items) > 0 {
						pkg.ChoiceDrivers = port.FindDriversByName(kernelTree, items)
					}
				}
				ms, err := port.FindSoCDTSI(kernelTree, pkg.DT.UnitAddrs)
				extra, xerr := port.FindExtraSoCDTSI(kernelTree, socDTSI, pkg.DT.UnitAddrs)
				if xerr != nil {
					return fmt.Errorf("--soc-dtsi: %w", xerr)
				}
				if err == nil {
					ms = port.PreferNamed(kernelTree, port.MergeSoCMatches(ms, extra), pkg.DT.SoC)
					pkg.SoC = ms
					if len(ms) > 0 {
						if dtsi, err := os.ReadFile(port.SoCFile(kernelTree, ms[0].File)); err == nil {
							pkg.BusLabels = port.BusLabels(pkg.DT, string(dtsi))
							pkg.SoCRegions = port.ParseDTSRegions(string(dtsi))
						}
						pkg.SoCGap = port.ComputeSoCGap(kernelTree, pkg)
						pkg.SoCLabels = port.SoCLabels(kernelTree, ms[0].File)
						pkg.SoCAddrLabels = port.SoCLabelsByAddr(kernelTree, ms[0].File)
						pkg.SoCFacts = port.ReadSoCDTSI(kernelTree, ms[0].File)
						var unstocked []string
						for _, l := range pkg.SoCFacts.Needs {
							if _, ok := pkg.DT.FixedClocks[l]; !ok {
								unstocked = append(unstocked, l)
							}
						}
						pkg.ClockDefs = port.SiblingClockDefs(kernelTree, ms[1:], unstocked)
					}
				}
			}
			bundle, err := em.Emit(pkg, port.Options{Catalog: activeCatalog(), Blob: blob})
			if err != nil {
				// What the package says about the hardware is worth having even
				// when its packaging cannot be drafted (no name to give it).
				bundle = &port.Bundle{Files: map[string][]byte{}}
				bundle.Notes = append(bundle.Notes, fmt.Sprintf("%v; writing the hardware report without %s packaging", err, em.Title()))
			}
			files := bundle.Files
			dts, dtsNotes := port.PeripheralDTS(pkg)
			files["dts/"+port.BoardName(pkg)+"-peripherals.dtsi"] = []byte(dts)
			files["dts/"+port.BoardName(pkg)+".dts"] = []byte(port.BoardDTS(pkg))
			bundle.Notes = append(bundle.Notes, dtsNotes...)
			if pkg.KernelTree != "" {
				bundle.Report = append(bundle.Report, port.SoCReport(pkg.KernelTree, pkg.SoC, pkg.DT.SoC), port.SoCGapSection(pkg.SoCGap))
			}
			bundle.Report = append(bundle.Report, port.MemorySection(pkg))
			drivers := port.PanelDrivers(pkg)
			for _, d := range drivers {
				files["panels/"+port.PanelFileName(d.Name)] = []byte(d.CSource())
			}
			var refPanel strings.Builder
			for _, f := range referencePanel {
				b, err := os.ReadFile(f)
				if err != nil {
					return fmt.Errorf("--reference-panel: %w", err)
				}
				refPanel.Write(b)
				refPanel.WriteString("\n")
			}
			bundle.Report = append(bundle.Report, port.LiveSection(pkg), port.CameraSection(pkg.Cameras), port.AudioSection(pkg), port.ConfigChoicesSection(pkg))
			ucm, ucmNotes := port.UCM(pkg)
			for name, b := range ucm {
				files[name] = b
			}
			bundle.Notes = append(bundle.Notes, ucmNotes...)
			if pkg.KernelConfig != nil {
				files["kernel/stock.config"] = []byte(port.ConfigText(pkg.KernelConfig))
			}
			if d := pkg.ConfigDiff; d != nil {
				files["kernel/stock.fragment"] = []byte(d.Fragment)
				files["kernel/stock-missing.txt"] = []byte(strings.Join(d.Missing, "\n") + "\n")
				bundle.Report = append(bundle.Report, port.ConfigDiffSection(d, pkg.KernelTree))
			}
			bundle.Report = append(bundle.Report, port.PanelSection(drivers, refPanel.String()))
			if len(referenceDTS) > 0 {
				var ref strings.Builder
				for _, f := range referenceDTS {
					b, err := os.ReadFile(f)
					if err != nil {
						return fmt.Errorf("--reference-dts: %w", err)
					}
					ref.Write(b)
					ref.WriteString("\n")
				}
				bundle.Report = append(bundle.Report, port.CompareDTS(pkg, ref.String()))
			}
			files["HARDWARE.md"] = []byte(port.Report(pkg, unknown, bundle.Report...))
			gmFile, gm, notes, haveGM := pkg.Gmobile()
			if haveGM {
				files["gmobile/"+gmFile] = []byte(gm.JSON())
			}
			prog.done() // clear the bar before anything is printed under it
			for _, n := range append(notes, bundle.Notes...) {
				fmt.Fprintln(os.Stderr, "port:", n)
			}

			files["BUNDLE.md"] = []byte(port.Manifest(files))
			names := make([]string, 0, len(files))
			for n := range files {
				names = append(names, n)
			}
			sort.Strings(names)
			if out == "" {
				for _, n := range names {
					fmt.Printf("\n# ---- %s ----\n\n%s", n, files[n])
				}
				return nil
			}
			for _, n := range names {
				dst := filepath.Join(out, n)
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(dst, files[n], 0o644); err != nil {
					return err
				}
			}
			fmt.Printf("wrote %d files (%s) -> %s\n", len(files), em.Title(), out)
			if checkDTS {
				if len(pkg.SoC) == 0 {
					return fmt.Errorf("--check-dts needs --kernel-tree with a SoC dtsi that matches the package")
				}
				res, err := port.CheckDTS(pkg.KernelTree, filepath.Join(out, "dts", port.BoardName(pkg)+".dts"), pkg.SoC[0].File)
				if err != nil {
					return fmt.Errorf("--check-dts: %w", err)
				}
				for _, l := range res.Summary() {
					fmt.Fprintln(os.Stderr, l)
				}
			}
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write the files here instead of printing them")
	c.Flags().StringVar(&distro, "distro", "nura", "distribution to draft packaging for ("+strings.Join(port.IDs(), ", ")+")")
	c.Flags().StringSliceVar(&referencePanel, "reference-panel", nil, "an existing hand-written panel driver: compare the drafted panels' command bytes and modes against it")
	c.Flags().StringSliceVar(&referenceDTS, "reference-dts", nil, "an existing hand-written board dts (repeat or comma-separate for several): compare the generated peripherals against it, by bus and address")
	c.Flags().StringSliceVar(&socDTSI, "soc-dtsi", nil, "SoC dtsi support from outside --kernel-tree (a patch series or fork checkout: a file, or a directory searched for .dtsi); matched against the stock device tree and ranked with the tree's, and used wherever the tree's dtsi is")
	c.Flags().BoolVar(&checkDTS, "check-dts", false, "after writing with -o, compile the board dts against --kernel-tree with the C preprocessor and dtc, and report what the board adds over the bare SoC dtsi (needs clang or gcc, and dtc)")
	c.Flags().BoolVar(&live, "live", false, "ask an attached device over adb which of the board's variant parts are fitted, and draft only those")
	c.Flags().StringVar(&serial, "serial", "", "adb serial for --live when more than one device is attached")
	c.Flags().StringVar(&kernelTree, "kernel-tree", "", "target kernel source tree: report which parts it supports and the firmware its drivers name")
	c.Flags().StringVar(&sizeMM, "size-mm", "", "visible panel size WIDTHxHEIGHT in mm for the gmobile file; overrides the diagonal in a vendor panel file's name and the device tree's size")
	return addFullDownload(c)
}

var kernelBanner = regexp.MustCompile(`Linux version (\d+\.\d+\.\d+)`)

// portStages is how many steps reading and writing a bundle has, for the bar.
const portStages = 7

// portProgress tells the person running the command what a slow stage is doing:
// reading a stock package takes tens of seconds, and a silent terminal looks
// like a hang. On a terminal it is the shared step bar (one step per stage, the
// super image's unpacking as detail on its step); off one it prints a line per
// stage with the time since the start, since the bar draws nothing there and a
// log wants them.
type portProgress struct {
	start time.Time
	bar   *barSink // nil off a terminal
	stage string
	n     int
}

func newPortProgress() *portProgress {
	p := &portProgress{start: time.Now(), bar: newBar()}
	p.bar.Begin(portStages)
	return p
}

// say starts the next stage.
func (p *portProgress) say(format string, args ...any) {
	p.stage = fmt.Sprintf(format, args...)
	if p.bar == nil {
		fmt.Fprintf(os.Stderr, "port: [%3.0fs] %s\n", time.Since(p.start).Seconds(), p.stage)
		return
	}
	if p.n > 0 {
		p.bar.Advance()
	}
	p.n++
	p.bar.Describe(p.stage)
}

// detail reports progress inside the current stage.
func (p *portProgress) detail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if p.bar == nil {
		fmt.Fprintf(os.Stderr, "port: [%3.0fs] %s\n", time.Since(p.start).Seconds(), msg)
		return
	}
	p.bar.Describe(p.stage + " — " + strings.TrimSpace(msg))
}

// done finishes the bar and clears it, so what is printed next is not drawn over.
func (p *portProgress) done() {
	if p.bar != nil && p.n > 0 {
		p.bar.Advance()
	}
	p.bar.Clear()
	p.n = 0
}

// readPackage reads everything a port draws on from a stock package.
// blob reads a file out of the package by its "partition:path" location.
func readPackage(input string, say func(string, ...any)) (pkg port.Package, unknown []string, blob func(string) ([]byte, error), err error) {
	say("opening the package")
	top, err := carveRoot(input)
	if err != nil {
		return port.Package{}, nil, nil, err
	}
	root := packageRoot(top)
	bytesOf := func(p string) ([]byte, error) {
		n, err := root.Walk(p)
		if err != nil {
			return nil, err
		}
		return n.Bytes()
	}
	// The base device trees are in vendor_boot on a device that ships one, else
	// in the boot image (header v2).
	say("reading the boot images and device trees")
	bootImg := "vendor_boot.img"
	vb, err := bytesOf(bootImg)
	if err != nil {
		bootImg = "boot.img"
		if vb, err = bytesOf(bootImg); err != nil {
			return pkg, nil, nil, fmt.Errorf("the package has neither vendor_boot.img nor boot.img (looked in %s)", root.Path())
		}
	}
	if pkg.Boot, err = port.ParseBoot(vb); err != nil {
		return pkg, nil, nil, err
	}
	super := superImage(root)
	root = root.withSuper(super)

	var base, overlays []*fdt.Node
	if n, err := root.Walk(bootImg + "/dtb"); err == nil {
		// A raw DTB (or several), or an Android dtbo table of them (MediaTek's
		// boot image holds one, whose entries are the trees).
		blobs := [][]byte{}
		if kind, kids, _ := n.Children(); kind == "dtbo" {
			for _, k := range kids {
				if b, err := k.Bytes(); err == nil {
					blobs = append(blobs, b)
				}
			}
		} else if b, err := n.Bytes(); err == nil {
			blobs = fdt.Split(b)
		}
		for _, d := range blobs {
			if n, err := fdt.Parse(d); err == nil {
				base = append(base, n)
			}
		}
	}
	if t, err := root.Walk("dtbo.img"); err == nil {
		_, kids, _ := t.Children()
		for _, k := range kids {
			if b, err := k.Bytes(); err == nil {
				if n, err := fdt.Parse(b); err == nil {
					overlays = append(overlays, n)
				}
			}
		}
	}
	say("reading the kernel modules")
	pkg.Modules = readModules(root, super, bootImg)
	pkg.DT, unknown = port.ReadDT(base, overlays, pkg.Modules, activeCatalog())

	gptFile := "gpt.bin"
	if _, err := root.Walk(gptFile); err != nil {
		gptFile = "gpt_main0.bin" // Qualcomm's per-LUN tables; LUN 0 holds the A/B partitions
	}
	if g, err := bytesOf(gptFile); err == nil {
		if t, err := qfil.ParseGPT(g); err == nil {
			pkg.SectorSize = t.SectorSize
			for _, p := range t.Partitions {
				pkg.Partitions = append(pkg.Partitions, p.Name)
			}
		}
	}
	if b, err := bytesOf("boot.img/kernel"); err == nil {
		b = port.KernelImage(b)
		if m := kernelBanner.FindSubmatch(b); m != nil {
			pkg.Kernel = string(m[1])
		}
		pkg.KernelConfig = port.KernelConfig(b)
	}
	if fs, err := bytesOf("vendor_boot.img/vendor_ramdisk_0/first_stage_ramdisk/fstab.qcom"); err == nil {
		pkg.Fstab = port.ParseFstab(string(fs))
	}
	if b, err := bytesOf(super + "/vendor_a/build.prop"); err == nil {
		pkg.Props = port.ParseProps(string(b))
	} else {
		fmt.Fprintf(os.Stderr, "vendor build.prop not read (%v); name and codename will be TODOs\n", err)
	}
	say("reading the display resources")
	density, _ := strconv.Atoi(pkg.Props["ro.sf.lcd_density"])
	pkg.Display = readAndroidDisplay(root, super, density)
	say("listing the firmware partitions")
	var nodes map[string]*carve.Node
	pkg.Slot, pkg.PartFiles, pkg.FileIndex, nodes = readPartFiles(root, super, pkg.Partitions)
	if v, err := root.Walk(super + "/vendor_a"); err == nil {
		_, kids, _ := v.Children()
		for _, k := range kids {
			pkg.VendorFiles = append(pkg.VendorFiles, strings.Trim(k.Name, "/"))
		}
		pkg.Cameras = port.CameraModules(pkg.VendorFiles)
		pkg.Audio = port.ReadAudio(append([]string(nil), pkg.VendorFiles...), func(name string) ([]byte, error) {
			return bytesOf(super + "/vendor_a/" + name)
		})
	}
	slot := pkg.Slot
	blob = func(location string) ([]byte, error) {
		part, p, ok := strings.Cut(location, ":")
		n := nodes[strings.TrimSuffix(part, slot)]
		if !ok || n == nil {
			return nil, fmt.Errorf("no partition for %q", location)
		}
		fsn, err := n.Walk(p)
		if err != nil {
			// A sparse image wraps its filesystem in one "unsparsed" child.
			if fsn, err = n.Walk("unsparsed/" + p); err != nil {
				return nil, err
			}
		}
		return fsn.Bytes()
	}
	return pkg, unknown, blob, nil
}

// pkgRoot is the directory a package's images are in. A flashing package wraps
// them in a folder (and an image/ below it); an archive lists such members by
// full path with no directory nodes, so the folder is a prefix on every lookup.
type pkgRoot struct {
	*carve.Node
	prefix string
	// super and logical say where a logical partition's data is when the
	// flasher stores each as its own file next to a super image that holds only
	// the table (Lenovo's super_1.img names the partitions; super_2…N are their
	// filesystems): "<super>/<partition>" is routed to that file.
	super   string
	logical map[string]*carve.Node
}

func (r pkgRoot) Walk(p string) (*carve.Node, error) {
	if rest, ok := strings.CutPrefix(p, r.super+"/"); ok && r.super != "" {
		part, sub, _ := strings.Cut(rest, "/")
		if n, ok := r.logical[part]; ok {
			if sub == "" {
				return n, nil
			}
			return n.Walk(sub)
		}
	}
	return r.Node.Walk(r.prefix + p)
}

// withSuper records the super image's name and, for a table-only one, the
// files its partitions live in, matched by size.
func (r pkgRoot) withSuper(super string) pkgRoot {
	r.super = super
	t, err := r.Walk(super)
	if err != nil {
		return r
	}
	_, parts, _ := t.Children()
	names, files := r.files()
	r.logical = map[string]*carve.Node{}
	for _, part := range parts {
		if kind, _, err := part.Children(); err == nil && kind != "" {
			continue // readable in place
		}
		for i, f := range files {
			if n := strings.TrimSuffix(names[i], "/"); n != super && strings.HasPrefix(n, "super_") && f.Size == part.Size {
				r.logical[strings.Trim(part.Name, "/")] = f
				break
			}
		}
	}
	return r
}

// files are the entries directly in the folder, by name within it.
func (r pkgRoot) files() (names []string, nodes []*carve.Node) {
	_, kids, err := r.Node.Children()
	if err != nil {
		return nil, nil
	}
	for _, k := range kids {
		if rel, ok := strings.CutPrefix(k.Name, r.prefix); ok && !strings.Contains(strings.TrimSuffix(rel, "/"), "/") {
			names, nodes = append(names, rel), append(nodes, k)
		}
	}
	return names, nodes
}

// packageRoot finds the folder holding the boot images: the archive's root, or
// the folder of the first boot, vendor_boot or dtbo image it lists.
func packageRoot(top *carve.Node) pkgRoot {
	_, kids, _ := top.Children()
	best := ""
	found := false
	for _, k := range kids {
		name := strings.TrimSuffix(k.Name, "/")
		dir, file := path.Split(name)
		switch file {
		case "dtbo.img", "boot.img", "vendor_boot.img":
			if !found || len(dir) < len(best) {
				best, found = dir, true
			}
		}
	}
	return pkgRoot{Node: top, prefix: best}
}

// superImage names the dynamic-partition image in the package's root: super.img,
// or super_1.img, the first piece of one a flasher split into several files.
// One shipped as a sparse image holds the super below an "unsparsed" child.
func superImage(root pkgRoot) string {
	for _, name := range []string{"super.img", "super_1.img"} {
		if _, err := root.Walk(name); err == nil {
			if _, err := root.Walk(name + "/unsparsed"); err == nil {
				return name + "/unsparsed"
			}
			return name
		}
	}
	return "super.img"
}

// readModules reads every kernel module the package ships: the boot image's
// ramdisk's, and those on the dlkm partitions of super.
func readModules(root pkgRoot, super, bootImg string) []port.Module {
	var mods []port.Module
	for _, from := range []string{bootImg + "/vendor_ramdisk_0", super + "/vendor_dlkm_a", super + "/system_dlkm_a"} {
		n, err := root.Walk(from)
		if err != nil {
			continue
		}
		_, kids, _ := n.Children()
		for _, k := range kids {
			if !strings.HasSuffix(k.Name, ".ko") {
				continue
			}
			if b, err := k.Bytes(); err == nil {
				mods = append(mods, port.ReadModule(k.Name, b))
			}
		}
	}
	return mods
}

var (
	flashStep   = regexp.MustCompile(`<step [^>]*filename="([^"]+)"[^>]*operation="flash"[^>]*partition="([^"]+)"`)
	recipeFlash = regexp.MustCompile(`<flash\s+partition="([^"]+)"\s+filename="([^"]+)"`)
)

// readPartFiles finds the content of each firmware-bearing partition
// (port.FirmwarePartitions) that the package carries, and lists its files. A
// partition is found by the package's own flash steps (including a radio
// container's recipe), by the catalog's file-name aliases, or as a logical
// partition of super. The A/B slot is the GPT's: "_a" when its partitions
// carry that suffix.
func readPartFiles(root pkgRoot, super string, gpt []string) (slot string, parts []port.PartFiles, index map[string][]string, nodes map[string]*carve.Node) {
	for _, n := range gpt {
		if strings.HasSuffix(n, "_a") {
			slot = "_a"
			break
		}
	}
	nodes = map[string]*carve.Node{}
	add := func(part string, n *carve.Node) {
		if _, dup := nodes[part]; !dup {
			nodes[part] = n
		}
	}
	if n, err := root.Walk("flashfile.xml"); err == nil {
		if b, err := n.Bytes(); err == nil {
			for _, m := range flashStep.FindAllStringSubmatch(string(b), -1) {
				file, part := m[1], m[2]
				if fn, err := root.Walk(file); err == nil {
					add(part, fn)
					// A container's own recipe names the partitions inside it.
					_, kids, _ := fn.Children()
					for _, k := range kids {
						if !strings.HasSuffix(k.Name, ".xml") {
							continue
						}
						if rb, err := k.Bytes(); err == nil {
							for _, r := range recipeFlash.FindAllStringSubmatch(string(rb), -1) {
								if inner, err := fn.Walk(r[2]); err == nil {
									add(r[1], inner)
								}
							}
						}
					}
				}
			}
		}
	}
	cat := activeCatalog()
	names, kids := root.files()
	for i, k := range kids {
		if part := cat.CanonicalPartition(strings.Trim(names[i], "/")); part != "" {
			add(part, k)
		}
	}
	for _, base := range port.FirmwarePartitions {
		if _, ok := nodes[base]; ok {
			continue
		}
		if n, err := root.Walk(super + "/" + base + slot); err == nil {
			nodes[base] = n
		}
	}

	index = map[string][]string{}
	for _, base := range port.FirmwarePartitions {
		n, ok := nodes[base]
		if !ok {
			continue
		}
		files := nodeFiles(n)
		parts = append(parts, port.PartFiles{Name: base, Files: files})
		for _, f := range files {
			b := path.Base(f)
			index[b] = append(index[b], base+slot+":"+f)
		}
	}
	return slot, parts, index, nodes
}

// nodeFiles lists a partition image's files, looking through the wrappers a
// package puts around one (a sparse image's single "unsparsed" child).
func nodeFiles(n *carve.Node) []string {
	for depth := 0; depth < 4; depth++ {
		kind, kids, err := n.Children()
		if err != nil || kind == "" {
			return nil
		}
		if kind == "sparse" && len(kids) == 1 {
			n = kids[0]
			continue
		}
		var out []string
		for _, k := range kids {
			name := strings.Trim(k.Name, "/")
			if name != "" && !strings.HasSuffix(name, ".joined") {
				out = append(out, name)
			}
		}
		return out
	}
	return nil
}

// overlayDirs are the partitions that carry runtime resource overlays, lowest
// precedence first; within one, overlays apply in name order.
var overlayDirs = []string{"system_ext_a", "vendor_a", "product_a"}

// readAndroidDisplay reads the framework's display resources and every
// overlay's over them. Nil when the framework table cannot be read, since
// then even the defaults are unknown.
func readAndroidDisplay(root pkgRoot, super string, density int) *port.AndroidDisplay {
	tableOf := func(p string) *arsc.Table {
		n, err := root.Walk(p)
		if err != nil {
			return nil
		}
		b, err := n.Bytes()
		if err != nil {
			return nil
		}
		t, err := arsc.OpenAPK(b)
		if err != nil {
			return nil
		}
		return t
	}
	base := tableOf(super + "/system_a/system/framework/framework-res.apk")
	if base == nil {
		return nil
	}
	overlays := map[string]*arsc.Table{}
	var order []string
	for _, part := range overlayDirs {
		n, err := root.Walk(super + "/" + part)
		if err != nil {
			continue
		}
		_, kids, _ := n.Children()
		for _, k := range kids {
			name := strings.Trim(k.Name, "/")
			dir, file := path.Split(name)
			// Only the overlays installed directly; the cutout-emulation ones in
			// subdirectories are alternatives the user can pick, not the default.
			if dir != "overlay/" || !strings.HasSuffix(file, ".apk") {
				continue
			}
			if t := tableOf(super + "/" + part + "/" + name); t != nil {
				overlays[file] = t
				order = append(order, file)
			}
		}
	}
	d := port.ReadAndroidDisplay(density, base, overlays, order)
	return &d
}
