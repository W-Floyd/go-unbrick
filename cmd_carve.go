package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// carveOnce registers the vendors' container formats after the neutral ones.
var carveOnce sync.Once

func carveRoot(input string) (*carve.Node, error) {
	carveOnce.Do(func() { carve.Register(vendor.CarveExpanders()...) })
	return carve.Open(input)
}

// carvePath opens input and walks to p inside it.
func carvePath(input, p string) (*carve.Node, error) {
	root, err := carveRoot(input)
	if err != nil {
		return nil, err
	}
	return root.Walk(p)
}

func newLsCmd() *cobra.Command {
	var recursive bool
	var depth int
	c := &cobra.Command{
		Use:   "ls <file | url> [path]",
		Short: "list what is inside anything: archive members, payload partitions, filesystem files, boot sections, …",
		Long: `ls lists the children of a path inside an input, through any nesting:
an archive's members, an OTA payload's partitions, super's logical partitions,
a FAT/ext4/erofs image's files, a boot image's sections and ramdisk. Each
segment of path names a child; a container's children follow its name.

  unbrick ls ota.zip payload.bin/modem
  unbrick ls fastboot.tgz images/boot.img/ramdisk`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := ""
			if len(args) == 2 {
				p = args[1]
			}
			n, err := carvePath(args[0], p)
			if err != nil {
				return err
			}
			if !recursive {
				depth = 1
			}
			return listNode(n, "", depth)
		},
	}
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "descend into nested containers")
	c.Flags().IntVar(&depth, "depth", 4, "with -r, how many container levels to descend")
	return c
}

// listNode prints n's children, and theirs down to depth container levels.
func listNode(n *carve.Node, indent string, depth int) error {
	kind, kids, err := n.Children()
	if err != nil {
		return err
	}
	if kind == "" {
		return fmt.Errorf("%s is not a container (%s)", n.Name, typeLabel(n.Name, n.Head()))
	}
	if indent == "" {
		fmt.Printf("%s  [%s] — %d entries\n", n.Name, kind, len(kids))
	}
	for _, k := range kids {
		size := "?"
		if k.Size >= 0 {
			size = humanBytes(k.Size)
		}
		label := typeLabel(k.Name, k.Head())
		if k.Size == 0 {
			label = "empty"
		}
		name := k.Name
		sub, isContainer := carve.Format(k)
		if isContainer {
			name += "/"
			label = sub.Kind
		}
		fmt.Printf("%s  %-40s %10s  [%s]\n", indent, name, size, label)
		if isContainer && depth > 1 {
			if err := listNode(k, indent+"  ", depth-1); err != nil {
				fmt.Printf("%s    (%v)\n", indent, err)
			}
		}
	}
	return nil
}

func newTreeCmd() *cobra.Command {
	var depth int
	var types bool
	c := &cobra.Command{
		Use:   "tree <file | url> [path]",
		Short: "draw what is inside anything as a tree, through nested containers",
		Long: `tree draws a path inside an input the way tree(1) draws a directory: member
and file names split into their directories, and each nested container
(payload, filesystem, boot image, ramdisk, …) opened beneath its name, down to
--depth container levels. Opening a container reads its index (a filesystem's
directory, a payload's manifest); --types also reads every entry's head to
name its format, which over a URL means fetching it.

  unbrick tree ota.zip payload.bin/vendor_boot
  unbrick tree --depth 2 fastboot.tgz`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := ""
			if len(args) == 2 {
				p = args[1]
			}
			n, err := carvePath(args[0], p)
			if err != nil {
				return err
			}
			kind, kids, err := n.Children()
			if err != nil {
				return err
			}
			if kind == "" {
				return fmt.Errorf("%s is not a container (%s)", n.Name, typeLabel(n.Name, n.Head()))
			}
			t := &treePrinter{types: types}
			fmt.Printf("%s  [%s]\n", n.Name, kind)
			t.print(kids, "", depth-1)
			fmt.Printf("\n%d containers, %d files\n", t.containers, t.files)
			return nil
		},
	}
	c.Flags().IntVar(&depth, "depth", 3, "how many container levels to open, the first included")
	c.Flags().BoolVarP(&types, "types", "t", false, "name each file's format (reads every head)")
	return c
}

// treeDir is one directory level of a container's children, rebuilt from the
// slashes in their names.
type treeDir struct {
	dirs  map[string]*treeDir
	files []*carve.Node
	base  map[*carve.Node]string // a file's name within this directory
}

func newTreeDir() *treeDir {
	return &treeDir{dirs: map[string]*treeDir{}, base: map[*carve.Node]string{}}
}

func buildTreeDir(kids []*carve.Node) *treeDir {
	root := newTreeDir()
	for _, k := range kids {
		parts := strings.Split(strings.Trim(k.Name, "/"), "/")
		d := root
		for _, p := range parts[:len(parts)-1] {
			if d.dirs[p] == nil {
				d.dirs[p] = newTreeDir()
			}
			d = d.dirs[p]
		}
		d.files = append(d.files, k)
		d.base[k] = parts[len(parts)-1]
	}
	return root
}

type treePrinter struct {
	types             bool
	containers, files int
}

// print draws kids under prefix, opening containers while depth > 0.
func (t *treePrinter) print(kids []*carve.Node, prefix string, depth int) {
	t.printDir(buildTreeDir(kids), prefix, depth)
}

func (t *treePrinter) printDir(d *treeDir, prefix string, depth int) {
	type item struct {
		name string
		dir  *treeDir
		file *carve.Node
	}
	var items []item
	for name, sub := range d.dirs {
		items = append(items, item{name: name + "/", dir: sub})
	}
	for _, f := range d.files {
		items = append(items, item{name: d.base[f], file: f})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	for i, it := range items {
		branch, next := "├── ", "│   "
		if i == len(items)-1 {
			branch, next = "└── ", "    "
		}
		if it.dir != nil {
			fmt.Printf("%s%s%s\n", prefix, branch, it.name)
			t.printDir(it.dir, prefix+next, depth)
			continue
		}
		t.printFile(it.file, it.name, prefix, branch, next, depth)
	}
}

func (t *treePrinter) printFile(f *carve.Node, name, prefix, branch, next string, depth int) {
	size := ""
	if f.Size >= 0 {
		size = "  " + humanBytes(f.Size)
	}
	// Telling a container from a file reads its head, so it is done only
	// where the tree would open it, or where --types reads heads anyway.
	var kids []*carve.Node
	kind := ""
	if depth > 0 || t.types {
		if e, ok := carve.Format(f); ok {
			kind = e.Kind
		}
	}
	label := ""
	switch {
	case kind != "":
		label = "  [" + kind + "]"
	case t.types:
		label = "  [" + typeLabel(name, f.Head()) + "]"
	}
	if kind != "" && depth > 0 {
		_, ks, err := f.Children()
		if err != nil {
			label += fmt.Sprintf("  (%v)", err)
		}
		kids = ks
		t.containers++
	} else {
		t.files++
	}
	fmt.Printf("%s%s%s%s%s\n", prefix, branch, name, size, label)
	if len(kids) > 0 {
		t.print(kids, prefix+next, depth-1)
	}
}

func newExtractCmd() *cobra.Command {
	var out string
	var recursive, force bool
	c := &cobra.Command{
		Use:   "extract <file | url> <path>",
		Short: "write out anything inside an input, by the path `ls` shows",
		Long: `extract writes the node at path inside an input to a file (-o, default its
base name here; "-" for stdout). With -r, a container's children are written
under a directory instead, named by their paths; nested containers stay whole.

  unbrick extract ota.zip payload.bin/modem/image/adsp.mdt.joined -o adsp.elf
  unbrick extract -r ota.zip payload.bin/boot/ramdisk -o ramdisk/`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := carvePath(args[0], args[1])
			if err != nil {
				return err
			}
			if !recursive {
				if out == "" {
					out = path.Base(n.Name)
				}
				return writeNode(n, out, force)
			}
			if out == "" {
				out = path.Base(n.Name) + ".d"
			}
			_, kids, err := n.Children()
			if err != nil {
				return err
			}
			if kids == nil {
				return fmt.Errorf("%s is not a container", n.Name)
			}
			for _, k := range kids {
				dst, err := within(out, k.Name)
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					return err
				}
				if err := writeNode(k, dst, force); err != nil {
					return err
				}
			}
			fmt.Printf("%d entries written under %s\n", len(kids), out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "output", "o", "", `where to write ("-" for stdout; with -r, a directory)`)
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "write a container's children under a directory")
	c.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing files")
	return c
}

// within joins a member name under dir, refusing one that would land outside
// it: names come from the input, and an archive can say "../../x".
func within(dir, name string) (string, error) {
	rel := filepath.FromSlash(strings.TrimLeft(name, "/"))
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("refusing to write %q outside %s", name, dir)
	}
	return filepath.Join(dir, rel), nil
}

// writeNode streams n to dst, or to stdout for "-".
func writeNode(n *carve.Node, dst string, force bool) error {
	r, err := n.Reader()
	if err != nil {
		return err
	}
	defer r.Close()
	if dst == "-" {
		_, err := io.Copy(os.Stdout, r)
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(dst, flags, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
