package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/arsc"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/fdt"
	"github.com/W-Floyd/go-unbrick/internal/nura"
	"github.com/W-Floyd/go-unbrick/internal/qfil"
)

func newNuraCmd() *cobra.Command {
	var out, sizeMM string
	c := &cobra.Command{
		Use:   "nura <stock package>",
		Short: "draft a Nura port (deviceinfo and hardware report) from a stock package",
		Long: `Reads a stock Android package for what a port needs to know: the boot image
layout, the partition table, the board's device-tree overlays (variants,
displays, touch, audio, charging, camera parts) and the vendor build.prop, and
writes a deviceinfo draft plus a hardware report. A field the package cannot
settle is a TODO in the draft, not a guess.

Reading the vendor build.prop opens the dynamic-partition super image, which
for a package that ships it as sparse chunks takes about half a minute.

  unbrick nura XT2413-2_FOGONA_….xml.zip -o port/`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkg, unknown, err := readNuraPackage(args[0])
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
			info, report := nura.Render(nura.Deviceinfo(pkg)), nura.Report(pkg, unknown)
			files := map[string]string{"deviceinfo": info, "HARDWARE.md": report}
			gmFile, gm, notes, haveGM := pkg.Gmobile()
			if haveGM {
				files[gmFile] = gm.JSON()
			}
			for _, n := range notes {
				fmt.Fprintln(os.Stderr, "gmobile:", n)
			}
			if out == "" {
				fmt.Print(info, "\n", report)
				if haveGM {
					fmt.Printf("\n# %s (gmobile)\n\n%s", gmFile, gm.JSON())
				}
				return nil
			}
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(out, name), []byte(body), 0o644); err != nil {
					return err
				}
			}
			fmt.Printf("wrote %d files -> %s\n", len(files), out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write deviceinfo and HARDWARE.md here instead of printing")
	c.Flags().StringVar(&sizeMM, "size-mm", "", "visible panel size WIDTHxHEIGHT in mm for the gmobile file; overrides the diagonal in a vendor panel file's name and the device tree's size")
	return c
}

var kernelBanner = regexp.MustCompile(`Linux version (\d+\.\d+\.\d+)`)

func readNuraPackage(input string) (nura.Package, []string, error) {
	root, err := carveRoot(input)
	if err != nil {
		return nura.Package{}, nil, err
	}
	bytesOf := func(p string) ([]byte, error) {
		n, err := root.Walk(p)
		if err != nil {
			return nil, err
		}
		return n.Bytes()
	}
	var pkg nura.Package

	vb, err := bytesOf("vendor_boot.img")
	if err != nil {
		return pkg, nil, err
	}
	if pkg.Boot, err = nura.ParseVendorBoot(vb); err != nil {
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
	var unknown []string
	pkg.DT, unknown = nura.ReadDT(base, overlays, activeCatalog())

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
	if rd, err := root.Walk("vendor_boot.img/vendor_ramdisk_0"); err == nil {
		_, kids, _ := rd.Children()
		for _, k := range kids {
			if strings.HasSuffix(k.Name, ".ko") {
				pkg.Modules = append(pkg.Modules, filepath.Base(k.Name))
			}
		}
		if fs, err := bytesOf("vendor_boot.img/vendor_ramdisk_0/first_stage_ramdisk/fstab.qcom"); err == nil {
			pkg.Fstab = nura.ParseFstab(string(fs))
		}
	}
	if b, err := bytesOf("super.img/vendor_a/build.prop"); err == nil {
		pkg.Props = nura.ParseProps(string(b))
	} else {
		fmt.Fprintf(os.Stderr, "vendor build.prop not read (%v); name and codename will be TODOs\n", err)
	}
	density, _ := strconv.Atoi(pkg.Props["ro.sf.lcd_density"])
	pkg.Display = readAndroidDisplay(root, density)
	if v, err := root.Walk("super.img/vendor_a"); err == nil {
		_, kids, _ := v.Children()
		for _, k := range kids {
			pkg.VendorFiles = append(pkg.VendorFiles, strings.Trim(k.Name, "/"))
		}
	}
	return pkg, unknown, nil
}

// overlayDirs are the partitions that carry runtime resource overlays, lowest
// precedence first; within one, overlays apply in name order.
var overlayDirs = []string{"system_ext_a", "vendor_a", "product_a"}

// readAndroidDisplay reads the framework's display resources and every
// overlay's over them. Nil when the framework table cannot be read, since
// then even the defaults are unknown.
func readAndroidDisplay(root *carve.Node, density int) *nura.AndroidDisplay {
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
	d := nura.ReadAndroidDisplay(density, base, overlays, order)
	return &d
}
