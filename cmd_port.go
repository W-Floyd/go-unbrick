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

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/arsc"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/fdt"
	"github.com/W-Floyd/go-unbrick/internal/port"
	_ "github.com/W-Floyd/go-unbrick/internal/port/nura" // registers the Nura emitter
	"github.com/W-Floyd/go-unbrick/internal/qfil"
)

func newPortCmd() *cobra.Command {
	var out, sizeMM, distro, kernelTree string
	var referenceDTS, referencePanel []string
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
			pkg, unknown, err := readPackage(args[0])
			if err != nil {
				return err
			}
			if sizeMM != "" {
				w, h, ok := strings.Cut(sizeMM, "x")
				pkg.SizeMM[0], _ = strconv.Atoi(w)
				pkg.SizeMM[1], _ = strconv.Atoi(h)
				if !ok || pkg.SizeMM[0] <= 0 || pkg.SizeMM[1] <= 0 {
					return fmt.Errorf("--size-mm wants WIDTHxHEIGHT in millimetres, e.g. 68x151")
				}
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
				if ms, err := port.FindSoCDTSI(kernelTree, pkg.DT.UnitAddrs); err == nil {
					pkg.SoC = ms
					if len(ms) > 0 {
						if dtsi, err := os.ReadFile(filepath.Join(kernelTree, ms[0].File)); err == nil {
							pkg.BusLabels = port.BusLabels(pkg.DT, string(dtsi))
							pkg.SoCRegions = port.ParseDTSRegions(string(dtsi))
						}
					}
				}
			}
			bundle, err := em.Emit(pkg, port.Options{Catalog: activeCatalog()})
			if err != nil {
				return err
			}
			files := bundle.Files
			dts, dtsNotes := port.PeripheralDTS(pkg)
			files["dts/"+port.BoardName(pkg)+"-peripherals.dtsi"] = []byte(dts)
			files["dts/"+port.BoardName(pkg)+".dts"] = []byte(port.BoardDTS(pkg))
			bundle.Notes = append(bundle.Notes, dtsNotes...)
			if pkg.KernelTree != "" {
				bundle.Report = append(bundle.Report, port.SoCReport(pkg.KernelTree, pkg.SoC))
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
			for _, n := range append(notes, bundle.Notes...) {
				fmt.Fprintln(os.Stderr, "port:", n)
			}

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
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write the files here instead of printing them")
	c.Flags().StringVar(&distro, "distro", "nura", "distribution to draft packaging for ("+strings.Join(port.IDs(), ", ")+")")
	c.Flags().StringSliceVar(&referencePanel, "reference-panel", nil, "an existing hand-written panel driver: compare the drafted panels' command bytes and modes against it")
	c.Flags().StringSliceVar(&referenceDTS, "reference-dts", nil, "an existing hand-written board dts (repeat or comma-separate for several): compare the generated peripherals against it, by bus and address")
	c.Flags().StringVar(&kernelTree, "kernel-tree", "", "target kernel source tree: report which parts it supports and the firmware its drivers name")
	c.Flags().StringVar(&sizeMM, "size-mm", "", "visible panel size WIDTHxHEIGHT in mm for the gmobile file; overrides the diagonal in a vendor panel file's name and the device tree's size")
	return c
}

var kernelBanner = regexp.MustCompile(`Linux version (\d+\.\d+\.\d+)`)

// readPackage reads everything a port draws on from a stock package.
func readPackage(input string) (port.Package, []string, error) {
	root, err := carveRoot(input)
	if err != nil {
		return port.Package{}, nil, err
	}
	bytesOf := func(p string) ([]byte, error) {
		n, err := root.Walk(p)
		if err != nil {
			return nil, err
		}
		return n.Bytes()
	}
	var pkg port.Package

	vb, err := bytesOf("vendor_boot.img")
	if err != nil {
		return pkg, nil, err
	}
	if pkg.Boot, err = port.ParseVendorBoot(vb); err != nil {
		return pkg, nil, err
	}

	var base, overlays []*fdt.Node
	if dtb, err := bytesOf("vendor_boot.img/dtb"); err == nil {
		for _, d := range fdt.Split(dtb) {
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
	pkg.Modules = readModules(root)
	var unknown []string
	pkg.DT, unknown = port.ReadDT(base, overlays, pkg.Modules, activeCatalog())

	if g, err := bytesOf("gpt.bin"); err == nil {
		if t, err := qfil.ParseGPT(g); err == nil {
			pkg.SectorSize = t.SectorSize
			for _, p := range t.Partitions {
				pkg.Partitions = append(pkg.Partitions, p.Name)
			}
		}
	}
	if b, err := bytesOf("boot.img/kernel"); err == nil {
		if m := kernelBanner.FindSubmatch(b); m != nil {
			pkg.Kernel = string(m[1])
		}
	}
	if fs, err := bytesOf("vendor_boot.img/vendor_ramdisk_0/first_stage_ramdisk/fstab.qcom"); err == nil {
		pkg.Fstab = port.ParseFstab(string(fs))
	}
	if b, err := bytesOf("super.img/vendor_a/build.prop"); err == nil {
		pkg.Props = port.ParseProps(string(b))
	} else {
		fmt.Fprintf(os.Stderr, "vendor build.prop not read (%v); name and codename will be TODOs\n", err)
	}
	density, _ := strconv.Atoi(pkg.Props["ro.sf.lcd_density"])
	pkg.Display = readAndroidDisplay(root, density)
	pkg.Slot, pkg.PartFiles, pkg.FileIndex = readPartFiles(root, pkg.Partitions)
	if v, err := root.Walk("super.img/vendor_a"); err == nil {
		_, kids, _ := v.Children()
		for _, k := range kids {
			pkg.VendorFiles = append(pkg.VendorFiles, strings.Trim(k.Name, "/"))
		}
	}
	return pkg, unknown, nil
}

// readModules reads every kernel module the package ships: the vendor_boot
// ramdisk's, and those on the dlkm partitions of super.
func readModules(root *carve.Node) []port.Module {
	var mods []port.Module
	for _, from := range []string{"vendor_boot.img/vendor_ramdisk_0", "super.img/vendor_dlkm_a", "super.img/system_dlkm_a"} {
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
func readPartFiles(root *carve.Node, gpt []string) (slot string, parts []port.PartFiles, index map[string][]string) {
	for _, n := range gpt {
		if strings.HasSuffix(n, "_a") {
			slot = "_a"
			break
		}
	}
	nodes := map[string]*carve.Node{}
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
	if kids, err := rootKids(root); err == nil {
		for _, k := range kids {
			if part := cat.CanonicalPartition(strings.Trim(k.Name, "/")); part != "" {
				add(part, k)
			}
		}
	}
	for _, base := range port.FirmwarePartitions {
		if _, ok := nodes[base]; ok {
			continue
		}
		if n, err := root.Walk("super.img/" + base + slot); err == nil {
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
	return slot, parts, index
}

func rootKids(root *carve.Node) ([]*carve.Node, error) {
	_, kids, err := root.Children()
	return kids, err
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
func readAndroidDisplay(root *carve.Node, density int) *port.AndroidDisplay {
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
	base := tableOf("super.img/system_a/system/framework/framework-res.apk")
	if base == nil {
		return nil
	}
	overlays := map[string]*arsc.Table{}
	var order []string
	for _, part := range overlayDirs {
		n, err := root.Walk("super.img/" + part)
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
			if t := tableOf("super.img/" + part + "/" + name); t != nil {
				overlays[file] = t
				order = append(order, file)
			}
		}
	}
	d := port.ReadAndroidDisplay(density, base, overlays, order)
	return &d
}
