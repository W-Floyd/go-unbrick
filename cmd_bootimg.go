package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/bootimg"
)

// ---- Android boot image / ramdisk dissection ----

func newBootimgCmd() *cobra.Command {
	c := &cobra.Command{Use: "bootimg", Short: "dissect an Android boot/recovery/vendor_boot image and its ramdisk"}
	c.AddCommand(newBootimgListCmd(), newBootimgExtractCmd(), newBootimgFindCmd())
	return c
}

// parseBootimg reads and parses an image file, the shared front half of every
// subcommand.
func parseBootimg(path string) (*bootimg.Image, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bootimg.Parse(b)
}

// ramdiskEntries decompresses every ramdisk in the image and returns all cpio
// entries, tagged with which ramdisk they came from when there is more than one.
func ramdiskEntries(im *bootimg.Image) ([]bootimg.CpioEntry, error) {
	rds := im.Ramdisks()
	if len(rds) == 0 {
		return nil, fmt.Errorf("image has no ramdisk (a GKI boot.img carries only a kernel)")
	}
	var all []bootimg.CpioEntry
	for _, rd := range rds {
		plain, _, err := bootimg.DecompressRamdisk(rd.Data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rd.Name, err)
		}
		entries, err := bootimg.ParseCpioConcat(plain)
		if err != nil {
			return all, fmt.Errorf("%s: %w", rd.Name, err)
		}
		all = append(all, entries...)
	}
	return all, nil
}

func newBootimgListCmd() *cobra.Command {
	var files bool
	c := &cobra.Command{
		Use:   "list <boot.img>",
		Short: "show the image's sections, and optionally its ramdisk file tree",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			im, err := parseBootimg(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("%s  %s header v%d", filepath.Base(args[0]), im.Magic, im.HeaderVersion)
			if im.OSVersion != "" {
				fmt.Printf("  os %s", im.OSVersion)
			}
			fmt.Println()
			for _, s := range im.Sections {
				codec := ""
				if c := bootimg.DetectCodec(s.Data); c != "" {
					codec = "  " + string(c)
				}
				fmt.Printf("  %-24s %10d bytes%s\n", s.Name, len(s.Data), codec)
			}
			if !files {
				return nil
			}
			entries, err := ramdiskEntries(im)
			if err != nil {
				return err
			}
			fmt.Printf("\n  ramdisk: %d entries\n", len(entries))
			for _, e := range entries {
				fmt.Printf("    %s %s\n", modeString(e), entryLabel(e))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&files, "files", false, "also list every file in the ramdisk")
	return c
}

func newBootimgFindCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "find <boot.img> <name>",
		Short: "locate a file in the ramdisk by path or basename (e.g. fastbootd)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			im, err := parseBootimg(args[0])
			if err != nil {
				return err
			}
			entries, err := ramdiskEntries(im)
			if err != nil {
				return err
			}
			e, ok := bootimg.Find(entries, args[1])
			if !ok {
				return fmt.Errorf("%q not found in ramdisk", args[1])
			}
			fmt.Printf("%s  %s  %d bytes\n", entryLabel(e), modeString(e), e.Size)
			return nil
		},
	}
	return c
}

func newBootimgExtractCmd() *cobra.Command {
	var out, only string
	c := &cobra.Command{
		Use:   "extract <boot.img>",
		Short: "write ramdisk files to a directory (all, or one --only <name>)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			im, err := parseBootimg(args[0])
			if err != nil {
				return err
			}
			entries, err := ramdiskEntries(im)
			if err != nil {
				return err
			}
			if out == "" {
				out = strings.TrimSuffix(filepath.Base(args[0]), filepath.Ext(args[0])) + "_ramdisk"
			}

			// --only pulls a single file to <out>/<basename>, the common case
			// (grab fastbootd and nothing else).
			if only != "" {
				e, ok := bootimg.Find(entries, only)
				if !ok {
					return fmt.Errorf("%q not found in ramdisk", only)
				}
				if !e.IsReg {
					return fmt.Errorf("%q is not a regular file (%s)", only, modeString(e))
				}
				if err := os.MkdirAll(out, 0o755); err != nil {
					return err
				}
				dst := filepath.Join(out, pathBase(e.Name))
				if err := os.WriteFile(dst, e.Data, 0o755); err != nil {
					return err
				}
				fmt.Printf("wrote %s (%d bytes)\n", dst, e.Size)
				return nil
			}

			n := 0
			for _, e := range entries {
				if !e.IsReg {
					continue // dirs/symlinks/nodes are not reconstructed
				}
				dst := filepath.Join(out, filepath.FromSlash(e.Name))
				if !withinDir(out, dst) {
					return fmt.Errorf("refusing path escaping %s: %q", out, e.Name)
				}
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(dst, e.Data, 0o755); err != nil {
					return err
				}
				n++
			}
			fmt.Printf("wrote %d regular files to %s/\n", n, out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output directory (default <image>_ramdisk)")
	c.Flags().StringVar(&only, "only", "", "extract just this file, by path or basename")
	return c
}

// withinDir guards against a ramdisk entry whose path (via .. or an absolute
// form) would land outside the output directory.
func withinDir(dir, target string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func modeString(e bootimg.CpioEntry) string {
	switch {
	case e.IsDir:
		return "d"
	case e.IsLink:
		return "l"
	case e.IsReg:
		return "-"
	default:
		return "?"
	}
}

func entryLabel(e bootimg.CpioEntry) string {
	if e.IsLink {
		return e.Name + " -> " + e.LinkTo
	}
	return e.Name
}
