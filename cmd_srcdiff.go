package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/gitsrc"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/srcdiff"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/upstreamsrc"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// maxSrcdiffRead bounds a file read whole to count its changed lines.
const maxSrcdiffRead = 4 << 20

func newSrcdiffCmd() *cobra.Command {
	var upstream, upstreamPath string
	var showDiff bool
	var limit int
	cmd := &cobra.Command{
		Use:   "srcdiff <file | dir> <path> --upstream <url[#ref]>",
		Short: "compare a vendor source tree against the upstream it came from",
		Long: `srcdiff compares the tree at <path> inside an input (a source release's archive, or a
directory) with an upstream git repository at a branch, tag or commit, by git blob
id: a file is unchanged when it hashes to what upstream has, so only differing files
are read from upstream. What remains is the vendor's own change.

The tree is aligned to wherever it sits in upstream (--upstream-path overrides). Where
the release carries *_notice.txt files that declare the files they modified, the
changes found are checked against them: declared and changed, changed but undeclared
(a change the vendor did not list), and declared but unchanged.

  unbrick srcdiff OSA_2025.zip ccNC_42dot/kenlm-src --upstream https://github.com/kpu/kenlm#5bf7b46

Reads from upstream only; git is needed, and the fetch is partial (commits, trees,
and the blobs that differ).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if upstream == "" {
				return fmt.Errorf("--upstream is required")
			}
			return runSrcdiff(args[0], strings.Trim(args[1], "/"), upstream, upstreamPath, showDiff, limit)
		},
	}
	cmd.Flags().StringVar(&upstream, "upstream", "", "upstream git repository, as url or url#ref (branch, tag, or commit id)")
	cmd.Flags().StringVar(&upstreamPath, "upstream-path", "", "directory in upstream the tree corresponds to (default: found by matching paths)")
	cmd.Flags().BoolVar(&showDiff, "diff", false, "print the changed lines of each modified file")
	cmd.Flags().IntVar(&limit, "limit", 40, "files to list per category")
	return cmd
}

// treeFiles lists the files of the tree at root inside input, relative to root.
func treeFiles(input, root string) ([]srcdiff.File, map[string]srcfile.Entry, func(), error) {
	if infile.IsDir(input) {
		return nil, nil, nil, fmt.Errorf("srcdiff of a directory input is not supported yet; pass an archive")
	}
	entries, closer, err := srcfile.Entries(input)
	if err != nil {
		return nil, nil, nil, err
	}
	if closer == nil {
		return nil, nil, nil, fmt.Errorf("%s is not an archive", infile.Base(input))
	}
	prefix := ""
	if root != "" && root != "." {
		prefix = root + "/"
	}
	var files []srcdiff.File
	byRel := map[string]srcfile.Entry{}
	for _, e := range entries {
		rel, ok := strings.CutPrefix(e.Name, prefix)
		if !ok || rel == "" {
			continue
		}
		e := e
		byRel[rel] = e
		files = append(files, srcdiff.File{Path: rel, Size: int64(e.Size), Open: e.Open})
	}
	return files, byRel, func() { closer.Close() }, nil
}

func readAllCapped(f srcdiff.File) ([]byte, error) {
	if f.Size > maxSrcdiffRead {
		return nil, fmt.Errorf("too large")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// declaredPaths is the files the notices that go with the tree at root declare as
// modified. A notice goes with a tree when its name begins with the tree's top
// directory or contains the tree's own directory name, ignoring punctuation.
func declaredPaths(input, root string) (paths, imports []string) {
	norm := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	top, _, _ := strings.Cut(root, "/")
	topN, baseN := norm(top), norm(path.Base(root))
	entries, closer, err := srcfile.Entries(input)
	if err != nil || closer == nil {
		return nil, nil
	}
	defer closer.Close()
	for _, e := range entries {
		if !vendor.IsNoticeName(e.Name) {
			continue
		}
		n := norm(strings.TrimSuffix(e.Name, ".txt"))
		if !(topN != "" && strings.HasPrefix(n, topN)) && !(baseN != "" && strings.Contains(n, baseN)) {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		notice := vendor.ParseNotice(data)
		paths = append(paths, notice.Paths...)
		if notice.Import {
			imports = append(imports, strings.TrimSuffix(e.Name, ".txt"))
		}
	}
	return paths, imports
}

// isDeclared says a changed file is one a notice names: the same path, or one a
// suffix of the other (a notice may name it from a different root).
func isDeclared(p string, declared []string) bool {
	for _, d := range declared {
		if p == d || strings.HasSuffix(p, "/"+d) || strings.HasSuffix(d, "/"+p) {
			return true
		}
	}
	return false
}

func runSrcdiff(input, root, upstream, upstreamPath string, showDiff bool, limit int) error {
	files, byRel, closeIn, err := treeFiles(input, root)
	if err != nil {
		return err
	}
	defer closeIn()
	if len(files) == 0 {
		return fmt.Errorf("%s: no files under %q", infile.Base(input), root)
	}
	src, ok := gitsrc.Parse(upstream)
	if !ok {
		return fmt.Errorf("--upstream %q is not a git URL", upstream)
	}
	cache, err := gitsrc.DefaultCache()
	if err != nil {
		return err
	}
	snap, err := upstreamsrc.Open(src.URL, src.Ref, cache, os.Stderr)
	if err != nil {
		return err
	}
	prefix := upstreamPath
	if prefix != "" {
		prefix = strings.Trim(prefix, "/") + "/"
	} else {
		paths := make([]string, len(files))
		for i, f := range files {
			paths[i] = f.Path
		}
		prefix = srcdiff.Align(paths, snap.Files)
	}
	kept := files[:0]
	for _, f := range files {
		if !snap.Symlinks[prefix+f.Path] {
			kept = append(kept, f)
		}
	}
	files = kept
	eol := func(f srcdiff.File, upSHA string) bool {
		a, err := readAllCapped(f)
		if err != nil {
			return false
		}
		b, err := snap.Blob(upSHA)
		if err != nil {
			return false
		}
		return bytes.Equal(bytes.ReplaceAll(a, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
	}
	res, err := srcdiff.Compare(files, snap.Files, prefix, eol)
	if err != nil {
		return err
	}
	declared, imports := declaredPaths(input, root)
	// A notice that lists the whole tree (an initial import) declares every file, so
	// what it declares cannot be told from what it changed.
	if len(imports) > 0 {
		declared = nil
	}

	label := root
	if label == "" {
		label = infile.Base(input)
	}
	fmt.Printf("%s vs %s @ %s (%s)\n", label, snap.URL, orHead(snap.Ref), snap.Commit[:12])
	fmt.Printf("  aligned to upstream %q\n", prefix)
	eolOnly := 0
	for _, m := range res.Modified {
		if m.EOLOnly {
			eolOnly++
		}
	}
	fmt.Printf("  %d identical, %d modified", len(res.Identical), len(res.Modified))
	if eolOnly > 0 {
		fmt.Printf(" (%d line endings only)", eolOnly)
	}
	fmt.Printf(", %d vendor-only, %d upstream-only (not shipped)\n", len(res.VendorOnly), len(res.UpstreamOnly))

	var undeclared []string
	if len(res.Modified) > 0 {
		fmt.Println("  modified:")
	}
	for i, m := range res.Modified {
		if i == limit {
			fmt.Printf("    ... %d more\n", len(res.Modified)-limit)
			break
		}
		line, body := "    "+m.Path, ""
		if m.EOLOnly {
			line += "  line endings only"
		} else {
			if st, b, ok := lineStats(byRel[m.Path], m, snap, showDiff); ok {
				line += fmt.Sprintf("  +%d -%d", st.Added, st.Removed)
				body = b
			} else {
				line += "  binary or too large to count"
			}
			if len(declared) > 0 {
				if isDeclared(m.Path, declared) {
					line += "  declared"
				} else {
					line += "  NOT declared"
					undeclared = append(undeclared, m.Path)
				}
			}
		}
		fmt.Println(line)
		fmt.Print(body)
	}
	listCapped("vendor-only", res.VendorOnly, limit)
	if len(imports) > 0 {
		fmt.Printf("  %s lists the whole tree (an initial import): declared and undeclared changes cannot be told apart\n", strings.Join(imports, ", "))
	}
	if len(declared) > 0 {
		var unchanged []string
		changedAll := map[string]bool{}
		for _, m := range res.Modified {
			changedAll[m.Path] = true
		}
		for _, v := range res.VendorOnly {
			changedAll[v] = true
		}
		for _, d := range declared {
			found := false
			for p := range changedAll {
				if p == d || strings.HasSuffix(p, "/"+d) || strings.HasSuffix(d, "/"+p) {
					found = true
					break
				}
			}
			if !found {
				unchanged = append(unchanged, d)
			}
		}
		fmt.Printf("  notices declare %d file(s); %d changed but not declared\n", len(declared), len(undeclared))
		listCapped("declared but unchanged here", unchanged, limit)
	}
	return nil
}

func orHead(ref string) string {
	if ref == "" {
		return "HEAD"
	}
	return ref
}

func listCapped(title string, items []string, limit int) {
	if len(items) == 0 {
		return
	}
	fmt.Printf("  %s:\n", title)
	for i, it := range items {
		if i == limit {
			fmt.Printf("    ... %d more\n", len(items)-limit)
			return
		}
		fmt.Printf("    %s\n", it)
	}
}

// lineStats counts the lines a text file changed, and renders the hunks if asked.
func lineStats(e srcfile.Entry, m srcdiff.Modified, snap *upstreamsrc.Snapshot, hunks bool) (analysis.Stats, string, bool) {
	if e.Open == nil {
		return analysis.Stats{}, "", false
	}
	f := srcdiff.File{Size: int64(e.Size), Open: e.Open}
	local, err := readAllCapped(f)
	if err != nil {
		return analysis.Stats{}, "", false
	}
	up, err := snap.Blob(m.UpstreamSHA)
	if err != nil || len(up) > maxSrcdiffRead || !analysis.IsText(local) || !analysis.IsText(up) {
		return analysis.Stats{}, "", false
	}
	lines, st, _ := analysis.TextDiff(up, local, 2)
	var b strings.Builder
	if hunks {
		for _, l := range lines {
			fmt.Fprintf(&b, "      %c %s\n", l.Op, strings.TrimRight(l.Text, "\r\n"))
		}
	}
	return st, b.String(), true
}
