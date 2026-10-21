package main

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/gitsrc"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	work "github.com/W-Floyd/go-unbrick/internal/progress"
	"github.com/W-Floyd/go-unbrick/internal/srcdiff"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/srcident"
	"github.com/W-Floyd/go-unbrick/internal/upstreamsrc"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// maxSrcdiffRead bounds a file read whole to count its changed lines.
const maxSrcdiffRead = 4 << 20

func newSrcdiffCmd() *cobra.Command {
	var upstream, upstreamPath string
	var showDiff, auto, heavy, interactive bool
	var webAddr string
	var limit int
	cmd := &cobra.Command{
		Use:   "srcdiff <file | dir> <path> --upstream <url[#ref]> | srcdiff <file> --auto",
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
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ui := interactive || webAddr != ""
			var trees []*srcdiffTree
			var collect func(*srcdiffTree)
			if ui {
				collect = func(t *srcdiffTree) { trees = append(trees, t) }
			}
			switch {
			case auto:
				if err := runSrcdiffAuto(args[0], heavy, collect); err != nil {
					return err
				}
			case len(args) != 2 || upstream == "":
				return fmt.Errorf("give <file> <path> and --upstream, or --auto")
			default:
				root := strings.Trim(args[1], "/")
				src, isGit := gitsrc.Parse(upstream)
				if srcdiffSweep && isGit && src.Ref != "" {
					commit, note, err := sweepCommits(args[0], root, src.URL, nil, src.Ref)
					switch {
					case err != nil:
						return fmt.Errorf("sweep: %w", err)
					case commit != "":
						fmt.Println(note)
						upstream = src.URL + "#" + commit
					default:
						fmt.Println(note)
					}
				}
				if err := runSrcdiff(args[0], root, upstream, upstreamPath, showDiff, limit, ui, collect); err != nil {
					return err
				}
				if isGit && srcdiffCVEs {
					printCVEs(args[0], src.URL, src.Ref)
				}
			}
			if !ui {
				return nil
			}
			return runSrcdiffUI(trees, webAddr)
		},
	}
	cmd.Flags().BoolVar(&srcdiffSweep, "sweep", false, "look for the upstream commit between releases that the tree matches best, not only the release: a vendor usually snapshots a commit, so some edits are upstream's own changes since the tag")
	cmd.Flags().BoolVar(&srcdiffCVEs, "cves", false, "list the vulnerabilities the OSV database (api.osv.dev) knows for each upstream version; sends the repository and tag to that service. Incomplete for old versions")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "browse what differs from upstream in the interactive diff (upstream is the base, the vendor's tree the change)")
	cmd.Flags().StringVar(&webAddr, "web", "", "serve that diff as a web page on this address instead, e.g. 127.0.0.1:8765")
	cmd.Flags().BoolVar(&auto, "auto", false, "find the upstream of each project in the release (names, versions and notices; see catalog/upstreams.yaml) and compare them all, one line each")
	cmd.Flags().BoolVar(&heavy, "heavy", false, "with --auto, also compare projects whose upstream is large (the Linux kernel)")
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

// identifyUpstreams finds the projects a source release is made of, by the
// catalog's upstream rules. It reads only the version files and notices the rules
// ask for.
func identifyUpstreams(input string) ([]srcident.Candidate, error) {
	entries, closer, err := srcfile.Entries(input)
	if err != nil {
		return nil, err
	}
	if closer == nil {
		return nil, fmt.Errorf("%s is not an archive", infile.Base(input))
	}
	defer closer.Close()
	byName := make(map[string]srcfile.Entry, len(entries))
	names := make([]string, len(entries))
	for i, e := range entries {
		byName[e.Name], names[i] = e, e.Name
	}
	read := func(name string) []byte {
		e, ok := byName[name]
		if !ok || e.Size > 1<<20 {
			return nil
		}
		rc, err := e.Open()
		if err != nil {
			return nil
		}
		defer rc.Close()
		b, _ := io.ReadAll(rc)
		return b
	}
	cands := srcident.Find(names, read, activeCatalog().Upstreams())
	// A vendor's own history, left in the tree, says exactly what it began from; a
	// commit a notice already pinned stands.
	for i := range cands {
		c := &cands[i]
		if strings.HasPrefix(c.Evidence, "pinned") {
			continue
		}
		if commit, evidence, ok := pinFromGitLog(entries, c.Root); ok {
			c.Ref, c.Evidence = commit, evidence
		}
	}
	return cands, nil
}

// upstreamURL is the --upstream value a candidate stands for.
func upstreamURL(c srcident.Candidate) string {
	if c.Ref == "" {
		return c.Rule.Repo
	}
	return c.Rule.Repo + "#" + c.Ref
}

// runSrcdiffAuto compares every identified project that has a ref to fetch, one
// summary line each.
func runSrcdiffAuto(input string, heavy bool, collect func(*srcdiffTree)) error {
	done := trace("identify upstreams (+ git history scan)")
	cands, err := identifyUpstreams(input)
	done()
	if err != nil {
		return err
	}
	if len(cands) == 0 {
		fmt.Println("no known upstream projects found in this release (see catalog/upstreams.yaml)")
		return nil
	}
	for _, c := range cands {
		if c.Ref == "" && !(c.Rule.Heavy && !heavy) {
			// No version stated: the tag whose files match the tree's is the one.
			stop := showProgress(c.Root)
			done := trace("best tag " + c.Root)
			ref, note, err := bestTag(input, c)
			done()
			stop()
			switch {
			case err != nil:
				fmt.Printf("%s: %s, version not stated; tag search failed: %v\n", c.Root, c.Rule.ID, err)
				continue
			case ref == "":
				fmt.Printf("%s: %s, version not stated; %s\n", c.Root, c.Rule.ID, note)
				continue
			}
			fmt.Printf("%s: %s\n", c.Root, note)
			c.Ref, c.Evidence = ref, note
		}
		switch {
		case c.Ref == "":
			fmt.Printf("%s: %s, version not stated; skipped (--heavy)\n", c.Root, c.Rule.ID)
		case c.Rule.Heavy && !heavy:
			fmt.Printf("%s: %s %s is a large upstream; skipped (--heavy)\n", c.Root, c.Rule.ID, c.Ref)
		default:
			tag := c.Ref
			// OSV is asked by tag; a project pinned to a commit is asked by the release
			// its version names, when it has one.
			if commitID.MatchString(tag) && c.Version != "" {
				tag = c.Rule.TagFor(c.Version)
			}
			// A snapshot is usually of some commit between releases: look there, unless
			// a notice has already named the commit.
			if srcdiffSweep && !strings.HasPrefix(c.Evidence, "pinned") {
				done := trace("sweep " + c.Root)
				commit, note, err := sweepCommits(input, c.Root, c.Rule.Repo, c.Rule, c.Ref)
				done()
				switch {
				case err != nil:
					fmt.Printf("%s: sweep failed: %v\n", c.Root, err)
				case commit != "":
					fmt.Printf("%s: %s\n", c.Root, note)
					c.Ref = commit
				default:
					fmt.Printf("%s: %s\n", c.Root, note)
				}
			}
			if err := runSrcdiff(input, c.Root, upstreamURL(c), "", false, 0, true, collect); err != nil {
				fmt.Printf("%s: %s @ %s: %v\n", c.Root, c.Rule.ID, c.Ref, err)
			} else if srcdiffCVEs {
				done := trace("cves " + c.Root)
				printCVEs(input, c.Rule.OSVRepo(), tag)
				done()
			}
		}
	}
	return nil
}

func runSrcdiff(input, root, upstream, upstreamPath string, showDiff bool, limit int, summary bool, collect func(*srcdiffTree)) error {
	done := trace("compare " + root + ": list tree")
	files, byRel, closeIn, err := treeFiles(input, root)
	done()
	if err != nil {
		return err
	}
	// A collector keeps the archive open (its files are read when it is browsed)
	// and closes it itself.
	handedOff := false
	defer func() {
		if !handedOff {
			closeIn()
		}
	}()
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
	label := root
	if label == "" {
		label = infile.Base(input)
	}
	stop := showProgress(label)
	done = trace("compare " + root + ": open upstream")
	snap, err := upstreamsrc.Open(src.URL, src.Ref, cache, nil)
	done()
	stop()
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
	// Hashing every file is the long part for a big tree: counted as it goes.
	task := work.Begin("comparing "+label, int64(len(files)))
	for i := range files {
		open := files[i].Open
		files[i].Open = func() (io.ReadCloser, error) {
			task.Add(1)
			return open()
		}
	}
	stop = showProgress(label)
	done = trace(fmt.Sprintf("compare %s: hash %d files", root, len(files)))
	res, err := srcdiff.Compare(files, snap.Files, prefix, nil)
	done()
	stop()
	task.End()
	if err != nil {
		return err
	}
	stop = showProgress(label)
	done = trace(fmt.Sprintf("compare %s: line endings of %d files", root, len(res.Modified)))
	markLineEndings(&res, files, snap)
	done()
	stop()
	done = trace("compare " + root + ": read notices")
	declared, imports := declaredPaths(input, root)
	done()
	// A notice that lists the whole tree (an initial import) declares every file, so
	// what it declares cannot be told from what it changed.
	if len(imports) > 0 {
		declared = nil
	}

	if summary {
		line := fmt.Sprintf("%s vs %s @ %s: %d identical, %d modified, %d vendor-only",
			label, strings.TrimSuffix(snap.URL, ".git"), orHead(snap.Ref), len(res.Identical), len(res.Modified), len(res.VendorOnly))
		if len(declared) > 0 {
			undeclared := 0
			for _, m := range res.Modified {
				if !m.EOLOnly && !isDeclared(m.Path, declared) {
					undeclared++
				}
			}
			line += fmt.Sprintf(" (%d not declared)", undeclared)
		}
		fmt.Println(line)
		if collect != nil {
			collect(&srcdiffTree{label: label, res: res, byRel: byRel, snap: snap, prefix: prefix, ref: orHead(snap.Ref), closeIn: closeIn})
			handedOff = true
		}
		return nil
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

// printUpstreamCandidates says which known open-source projects a source release
// holds and what each would be compared against.
func printUpstreamCandidates(input string) {
	cands, err := identifyUpstreams(input)
	if err != nil || len(cands) == 0 {
		return
	}
	fmt.Println("  Upstream candidates (compare with `srcdiff --auto`):")
	for _, c := range cands {
		what := c.Rule.ID
		switch {
		case c.Version != "":
			what += " " + c.Version
		case c.Ref != "":
		default:
			what += " (version not stated)"
		}
		line := fmt.Sprintf("    %s: %s", c.Root, what)
		if c.Ref != "" {
			line += " -> " + c.Ref
		}
		fmt.Printf("%s  [%s]\n", line, c.Evidence)
	}
}

// markLineEndings sets EOLOnly on the modified files that differ from upstream only
// in their line endings (an archive built on Windows). It fetches the differing
// files' blobs in one batch and reads them without going back to origin; if the
// server will not send blobs by id, it stops there: the files are then reported as
// modified, which is true, and not found one round trip at a time, which does not
// finish when a tree has hundreds of them.
func markLineEndings(res *srcdiff.Result, files []srcdiff.File, snap *upstreamsrc.Snapshot) {
	size := make(map[string]int64, len(res.Modified))
	for _, f := range files {
		size[f.Path] = f.Size
	}
	var shas []string
	for _, m := range res.Modified {
		if size[m.Path] <= maxSrcdiffRead {
			shas = append(shas, m.UpstreamSHA)
		}
	}
	if len(shas) == 0 {
		return
	}
	done := trace(fmt.Sprintf("  prefetch %d blobs", len(shas)))
	err := snap.Prefetch("fetching changed files", shas)
	done()
	if err != nil {
		return
	}
	byPath := make(map[string]srcdiff.File, len(res.Modified))
	for _, f := range files {
		byPath[f.Path] = f
	}
	task := work.Begin("checking line endings", int64(len(res.Modified)))
	defer task.End()
	lf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	held := snap.BlobsLocal(shas) // one git process for all, not one per file
	for i := range res.Modified {
		task.Add(1)
		m := &res.Modified[i]
		up, ok := held[m.UpstreamSHA]
		if !ok {
			continue
		}
		local, err := readAllCapped(byPath[m.Path])
		if err != nil {
			continue
		}
		m.EOLOnly = bytes.Equal(lf(local), lf(up))
	}
}

// commitID is a full git commit id.
var commitID = regexp.MustCompile(`^[0-9a-f]{40}$`)
