package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// carveOnce registers the vendors' container formats after the neutral ones.
var carveOnce sync.Once

func carveRoot(input string) (*carve.Node, error) {
	carveOnce.Do(func() {
		carve.Register(vendor.CarveExpanders()...)
		carve.ZipPasswords = vendor.ZipPasswords
		carve.Register(encryptedExpander())
	})
	if secretsLoaded() == 0 {
		dir := carveSecrets
		if dir == "" && !infile.IsRemote(input) {
			dir = findSecrets(filepath.Dir(input))
		}
		if dir != "" {
			if err := loadSecrets(dir); err != nil {
				return nil, fmt.Errorf("--secrets: %w", err)
			}
		}
	}
	if !infile.IsRemote(input) {
		if fi, err := os.Stat(input); err == nil && fi.IsDir() {
			return carveDir(input)
		}
	}
	return carve.Open(input)
}

// carveDir is a directory on disk as a container, its files and subdirectories
// the children; files are opened where they are looked into, not here.
func carveDir(dir string) (*carve.Node, error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var kids []*carve.Node
	for _, e := range es {
		full := filepath.Join(dir, e.Name())
		fi, err := os.Stat(full) // follows links; a dangling one is left out
		if err != nil {
			continue
		}
		if fi.IsDir() {
			k, err := carveDir(full)
			if err != nil {
				return nil, err
			}
			kids = append(kids, k)
			continue
		}
		k, err := carve.Open(full)
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	return carve.Dir(filepath.Base(filepath.Clean(dir)), kids), nil
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
	return addSecrets(addFullDownload(c))
}

// listNode prints n's children, and theirs down to depth container levels.
func listNode(n *carve.Node, indent string, depth int) error {
	kind, kids, err := n.Children()
	if err != nil {
		return err
	}
	if kind == "" {
		return fmt.Errorf("%s is not a container (%s)", n.Name, cachedTypeLabel(n.Name, n.Head()))
	}
	if indent == "" {
		fmt.Printf("%s  [%s] — %d entries\n", n.Name, kind, len(kids))
	}
	for _, k := range kids {
		size := "?"
		if k.Size >= 0 {
			size = humanBytes(k.Size)
		}
		label := "directory"
		name := k.Name
		isContainer := k.IsDirNode()
		if isContainer {
			name += "/"
		} else {
			label = cachedTypeLabel(k.Name, k.Head())
			if k.Size == 0 {
				label = "empty"
			}
			var sub carve.Expander
			if sub, isContainer = carve.Format(k); isContainer {
				name += "/"
				label = sub.Kind
			}
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
	var skip []string
	var match, grep string
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
				return fmt.Errorf("%s is not a container (%s)", n.Name, cachedTypeLabel(n.Name, n.Head()))
			}
			skip, err = checkSkips(skip)
			if err != nil {
				return err
			}
			t := &treePrinter{types: types, skip: skip}
			if match != "" {
				if t.match, err = regexp.Compile(match); err != nil {
					return fmt.Errorf("--match: %w", err)
				}
			}
			if grep != "" {
				if t.grep, err = regexp.Compile(grep); err != nil {
					return fmt.Errorf("--grep: %w", err)
				}
				t.sem = make(chan struct{}, grepWorkers())
			}
			fmt.Printf("%s  [%s]\n", n.Name, kind)
			t.print(kids, "", "", depth-1)
			fmt.Printf("\n%d containers, %d files", t.containers, t.files)
			if t.left > 0 {
				fmt.Printf(", %d skipped", t.left)
			}
			fmt.Println()
			return nil
		},
	}
	c.Flags().IntVar(&depth, "depth", 3, "how many container levels to open, the first included")
	c.Flags().BoolVarP(&types, "types", "t", false, "name each file's format (reads every head)")
	addSkipFlag(c, &skip, "files and directories")
	c.Flags().StringVarP(&match, "match", "m", "", "draw only entries whose full path (from the tree's root, through nested containers, e.g. enc_system/enc_system.ext4/etc/iv.dat) matches this regular expression, with the directories above them; containers are opened to look, down to --depth")
	c.Flags().StringVarP(&grep, "grep", "g", "", "draw only entries whose content matches this regular expression (a byte-level search, so a hit sitting in otherwise-binary data is found too, not just printable strings), with the directories above them; containers are opened to look, down to --depth. With --match too, both must hold for the same leaf")
	return addSecrets(addFullDownload(c))
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
	skip              []string       // regular expressions on an entry's full path: left out, files and directories alike
	match             *regexp.Regexp // when set, only entries whose full path is or holds a match are drawn
	grep              *regexp.Regexp // when set, only entries whose content is or holds a match are drawn (binary data included, not just printable strings); with match too, both must hold for the same leaf
	grepMax           int64          // bytes of a file --grep reads before giving up on it; 0 = ContentMatch's default
	containers, files int
	left              int // entries a skip left out

	// sem bounds how many --grep content reads run at once (nil: unbounded,
	// e.g. grep == nil, so there is none to bound); contentCache remembers
	// each leaf's answer, computed once by precomputeContentMatches rather
	// than inline by matches. See precomputeContentMatches for why this is
	// only ever acquired for a leaf's own read, never while already holding
	// one: recursing into a container cannot deadlock the pool this way.
	sem          chan struct{}
	contentCache sync.Map // *carve.Node -> bool
}

// skipped says whether the entry at path (a directory with a trailing slash) is left out.
func (t *treePrinter) skipped(path string) bool {
	return analysis.SkipPath(t.skip, path) || analysis.SkipPath(t.skip, strings.TrimSuffix(path, "/"))
}

// print draws kids under prefix, opening containers while depth > 0.
func (t *treePrinter) print(kids []*carve.Node, prefix, at string, depth int) {
	t.printDir(buildTreeDir(kids), prefix, at, depth)
}

type treeItem struct {
	name string // with a trailing slash for a directory
	dir  *treeDir
	file *carve.Node
}

// items is d's entries in order, less those a skip leaves out (counted when count).
func (t *treePrinter) items(d *treeDir, at string, count bool) []treeItem {
	var items []treeItem
	for name, sub := range d.dirs {
		items = append(items, treeItem{name: name + "/", dir: sub})
	}
	for _, f := range d.files {
		items = append(items, treeItem{name: d.base[f], file: f})
	}
	if len(t.skip) > 0 {
		kept := items[:0]
		for _, it := range items {
			if t.skipped(at + it.name) {
				if count {
					t.left++
				}
				continue
			}
			kept = append(kept, it)
		}
		items = kept
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	return items
}

// opens is what the tree shows under f: a directory's entries, or a container's
// while depth allows opening it. Nil for a file.
func (t *treePrinter) opens(f *carve.Node, depth int) []*carve.Node {
	if f.IsDirNode() {
		_, ks, _ := f.Children()
		return ks
	}
	if depth > 0 {
		if _, ok := carve.Format(f); ok {
			_, ks, _ := f.Children()
			return ks
		}
	}
	return nil
}

// grepWorkers bounds how many --grep content reads run at once, across
// tree/extract: the CPUs, capped, the same default --exhaustive-key-learn
// uses for the same reason (KeySweepOptions.Workers).
func grepWorkers() int { return min(runtime.NumCPU(), 8) }

// hits reports whether d, at path at, holds an entry whose path matches
// --match or whose content matches --grep. Every item's own content check (if
// any) runs concurrently first, bounded by t.sem -- the only expensive, and
// mutually independent, step in deciding this -- before the existing
// sequential match logic below, which now just reads each leaf's answer
// instead of computing it inline.
func (t *treePrinter) hits(d *treeDir, at string, depth int) bool {
	items := t.items(d, at, false)
	t.precomputeContentMatches(items, at)
	for _, it := range items {
		if t.matches(it, at, depth) {
			return true
		}
	}
	return false
}

// precomputeContentMatches evaluates --grep against every leaf in items that
// can be read at random, concurrently, storing each result in t.contentCache
// for matches to consult. Only ever acquires t.sem for this, a leaf's own
// read -- never while already holding one -- so recursing into a container
// (which calls hits, which calls this again, for the next level down) cannot
// deadlock the pool: a nested call's own sem acquisitions happen only after
// this one's goroutines have already returned theirs.
func (t *treePrinter) precomputeContentMatches(items []treeItem, at string) {
	if t.grep == nil {
		return
	}
	var wg sync.WaitGroup
	for _, it := range items {
		if it.dir != nil || it.file.IsDirNode() || !it.file.RandomAccess() {
			continue // nothing of its own to check here, or can't be read concurrently
		}
		if _, ok := t.contentCache.Load(it.file); ok {
			continue
		}
		f := it.file
		t.sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-t.sem }()
			t.contentCache.Store(f, t.matchesContent(f))
		}()
	}
	wg.Wait()
}

// contentMatchCached is matchesContent, from precomputeContentMatches's cache
// when it got there first; computed inline otherwise (a sequential-only
// source precomputeContentMatches skipped, or a cache miss some other way).
func (t *treePrinter) contentMatchCached(f *carve.Node) bool {
	if v, ok := t.contentCache.Load(f); ok {
		return v.(bool)
	}
	return t.matchesContent(f)
}

// matches reports whether an entry is, or holds, a match: its full path for
// --match, its content for --grep, both for the same leaf when both are given.
// A directory has no content, so only --match (never --grep) can make a
// directory count on its own name; either can still be satisfied by something
// found inside it.
func (t *treePrinter) matches(it treeItem, at string, depth int) bool {
	p := at + strings.TrimSuffix(it.name, "/")
	if it.dir != nil {
		dirNamed := t.match != nil && t.match.MatchString(p)
		return dirNamed || t.hits(it.dir, p+"/", depth)
	}
	if it.file.IsDirNode() { // a directory on disk riding in treeItem.file (see items): same rule, no content to grep
		dirNamed := t.match != nil && t.match.MatchString(p)
		_, ks, _ := it.file.Children()
		return dirNamed || t.hits(buildTreeDir(ks), p+"/", depth)
	}
	pathOK := t.match == nil || t.match.MatchString(p)
	if pathOK {
		switch {
		case t.grep == nil:
			return true
		case t.contentMatchCached(it.file):
			return true
		}
	}
	if ks := t.opens(it.file, depth); ks != nil {
		d := depth
		if !it.file.IsDirNode() {
			d--
		}
		return t.hits(buildTreeDir(ks), p+"/", d)
	}
	return false
}

// matchesContent reports whether f's bytes satisfy --grep, treating a read
// failure (an opaque/undecryptable member) as no match rather than an error the
// tree draws nothing for.
func (t *treePrinter) matchesContent(f *carve.Node) bool {
	ok, err := analysis.ContentMatch(f, t.grep, t.grepMax)
	return err == nil && ok
}

func (t *treePrinter) printDir(d *treeDir, prefix, at string, depth int) {
	items := t.items(d, at, true)
	if t.match != nil || t.grep != nil {
		kept := items[:0]
		for _, it := range items {
			if t.matches(it, at, depth) {
				kept = append(kept, it)
			}
		}
		items = kept
	}
	for i, it := range items {
		branch, next := "├── ", "│   "
		if i == len(items)-1 {
			branch, next = "└── ", "    "
		}
		if it.dir != nil {
			fmt.Printf("%s%s%s\n", prefix, branch, it.name)
			t.printDir(it.dir, prefix+next, at+it.name, depth)
			continue
		}
		t.printFile(it.file, it.name, prefix, branch, next, at+it.name, depth)
	}
}

func (t *treePrinter) printFile(f *carve.Node, name, prefix, branch, next, at string, depth int) {
	if f.IsDirNode() { // a directory on disk, not a container level: depth is not spent
		_, ks, _ := f.Children()
		fmt.Printf("%s%s%s/\n", prefix, branch, name)
		t.print(ks, prefix+next, at+"/", depth)
		return
	}
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
		label = "  [" + cachedTypeLabel(name, f.Head()) + "]"
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
		t.print(kids, prefix+next, at+"/", depth-1)
	}
}

func newExtractCmd() *cobra.Command {
	var out, match, grep string
	var skip []string
	var depth int
	var recursive, force bool
	c := &cobra.Command{
		Use:   "extract <file | url> <path>",
		Short: "write out anything inside an input, by the path `ls` shows",
		Long: `extract writes the node at path inside an input to a file (-o, default its
base name here; "-" for stdout). With -r, a container's children are written
under a directory instead, named by their paths; nested containers stay whole.

  unbrick extract ota.zip payload.bin/modem/image/adsp.mdt.joined -o adsp.elf
  unbrick extract -r ota.zip payload.bin/boot/ramdisk -o ramdisk/`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := ""
			if len(args) == 2 {
				p = args[1]
			}
			skip, err := checkSkips(skip)
			if err != nil {
				return err
			}
			var re, grepRe *regexp.Regexp
			if match != "" {
				var err error
				if re, err = regexp.Compile(match); err != nil {
					return fmt.Errorf("--match: %w", err)
				}
				if !recursive {
					return fmt.Errorf("--match needs -r")
				}
			}
			if grep != "" {
				var err error
				if grepRe, err = regexp.Compile(grep); err != nil {
					return fmt.Errorf("--grep: %w", err)
				}
				if !recursive {
					return fmt.Errorf("--grep needs -r")
				}
			}
			n, err := carvePath(args[0], p)
			if err != nil {
				return err
			}
			if !recursive {
				if len(args) < 2 {
					return fmt.Errorf("extract needs a path (or -r to write a container's children)")
				}
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
			written, err := extractKids(kids, "", out, re, grepRe, skip, depth-1, force)
			if err != nil {
				return err
			}
			fmt.Printf("%d entries written under %s\n", written, out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "output", "o", "", `where to write ("-" for stdout; with -r, a directory)`)
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "write a container's children under a directory")
	c.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing files")
	c.Flags().StringVarP(&match, "match", "m", "", "with -r, write only entries whose full path (from the extracted node, through nested containers) matches this regular expression; containers are opened to look, down to --depth, and a matching one is written whole")
	c.Flags().StringVarP(&grep, "grep", "g", "", "with -r, write only entries whose content matches this regular expression (a byte-level search, binary data included); containers are opened to look, down to --depth. With --match too, both must hold for the same entry")
	c.Flags().IntVar(&depth, "depth", 3, "with --match/--grep, how many container levels to open, the first included")
	addSkipFlag(c, &skip, "with -r")
	return addSecrets(addFullDownload(c))
}

// extractKids writes kids under out, named by their paths from the extracted
// node (at is the path of kids). A directory is always descended. With re
// and/or grep, only entries whose path and/or content match are written (both
// must hold for the same entry when both are given), and containers are
// opened, while depth > 0, to look for them.
func extractKids(kids []*carve.Node, at, out string, re, grep *regexp.Regexp, skip []string, depth int, force bool) (int, error) {
	// --grep's content read is the only expensive, and mutually independent,
	// part of deciding what to write at this level: evaluate every leaf's
	// match concurrently first, then do the (fast, sequential) writing and
	// recursion below using those answers instead of computing them inline.
	matched := parallelGrepMatch(kids, at, re, grep)
	written := 0
	for i, k := range kids {
		p := at + k.Name
		if analysis.SkipPath(skip, p) {
			continue
		}
		switch {
		case k.IsDirNode():
			_, ks, err := k.Children()
			if err != nil {
				return written, err
			}
			n, err := extractKids(ks, p+"/", out, re, grep, skip, depth, force)
			written += n
			if err != nil {
				return written, err
			}
		case matched[i]:
			dst, err := within(out, p)
			if err != nil {
				return written, err
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return written, err
			}
			if err := writeNode(k, dst, force); err != nil {
				return written, err
			}
			written++
		case depth > 0:
			if _, ok := carve.Format(k); !ok {
				continue
			}
			_, ks, err := k.Children()
			if err != nil {
				continue // not readable as a container: nothing to find in it
			}
			n, err := extractKids(ks, p+"/", out, re, grep, skip, depth-1, force)
			written += n
			if err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// parallelGrepMatch evaluates, for every non-directory kid, whether its path
// matches re (if given) and its content matches grep (if given) -- extractKids'
// own per-leaf rule, computed concurrently (bounded by grepWorkers) since
// contentOK's read is independent per kid. A kid that can't be read at random
// (sequential-only) is checked inline instead of backgrounded.
func parallelGrepMatch(kids []*carve.Node, at string, re, grep *regexp.Regexp) []bool {
	matched := make([]bool, len(kids))
	check := func(k *carve.Node, p string) bool { return (re == nil || re.MatchString(p)) && contentOK(k, grep) }
	sem := make(chan struct{}, grepWorkers())
	var wg sync.WaitGroup
	for i, k := range kids {
		if k.IsDirNode() {
			continue
		}
		p := at + k.Name
		if !k.RandomAccess() {
			matched[i] = check(k, p)
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, k *carve.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			matched[i] = check(k, p)
		}(i, k)
	}
	wg.Wait()
	return matched
}

// contentOK reports whether k's bytes satisfy grep ("" i.e. nil: always true).
// A read failure (an opaque/undecryptable member) counts as no match rather
// than aborting the whole extraction.
func contentOK(k *carve.Node, grep *regexp.Regexp) bool {
	if grep == nil {
		return true
	}
	ok, err := analysis.ContentMatch(k, grep, 0)
	return err == nil && ok
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
