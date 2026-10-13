package port

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// SoCGap is what porting the SoC's own blocks involves: the stock base device
// tree's peripherals the best mainline dtsi (with everything it includes) does
// not define, and for each, whether another dtsi in the tree already names its
// compatible. A block that is somewhere in the tree is a node to copy and
// adapt; one that is nowhere is real driver and binding work.
type SoCGap struct {
	Include  string // the dtsi compared against
	Files    []string
	Stock    int // register-addressed peripherals in the stock tree
	Present  int // of those, defined by Include and what it includes
	Missing  []MissingBlock
	Siblings int // missing blocks some other dtsi names the compatible of
}

// MissingBlock is a stock peripheral the include does not define.
type MissingBlock struct {
	Node    SoCNode
	Sibling []string // dtsi files that name its compatible, nearest first; empty if none
	// Generic says a compatible of the node's was too common to count, so a
	// block with no Sibling is not simply absent from the tree.
	Generic bool
	// InCode says a driver or binding in the tree names a compatible of the
	// node's (and no dtsi does): upstream can bind the block, it just has no node
	// for it. False with no Sibling and no Generic means nothing in the tree
	// names it under any form.
	InCode bool
}

var (
	includeRe = regexp.MustCompile(`#include\s+"([^"]+\.dtsi)"`)
	compatRe  = regexp.MustCompile(`compatible\s*=\s*([^;]+);`)
	quotedRe  = regexp.MustCompile(`"([^"]*)"`)
)

// ComputeSoCGap compares the stock peripherals with the best SoC dtsi. nil when
// there is no match to compare against.
func ComputeSoCGap(tree string, p Package) *SoCGap {
	if len(p.SoC) == 0 || len(p.DT.SoCNodes) == 0 {
		return nil
	}
	g := &SoCGap{Include: p.SoC[0].File, Stock: len(p.DT.SoCNodes)}

	// The include's closure: the dtsi and the .dtsi files it pulls in.
	have := map[string]bool{}
	walkDTSIClosure(SoCFile(tree, g.Include), socDirs(tree, g.Include), func(name string, b []byte) {
		g.Files = append(g.Files, name)
		for _, m := range treeAddr.FindAllSubmatch(b, -1) {
			have[strings.TrimLeft(strings.ToLower(string(m[1])), "0")] = true
		}
	})

	// Every dtsi's compatibles, ranked by how much of the stock register map
	// each shares (SoC order), for naming the nearest sibling.
	rank := map[string]int{}
	for i, m := range p.SoC {
		rank[filepath.Base(m.File)] = i
	}
	where := compatibleIndex(socDirs(tree, g.Include))
	code := treeCompatibles(tree)

	for _, n := range p.DT.SoCNodes {
		if have[n.Addr] {
			g.Present++
			continue
		}
		mb := MissingBlock{Node: n}
		files := map[string]bool{}
		for _, c := range n.Compatible {
			// A compatible nearly every dtsi names ("syscon", "arm,primecell")
			// says nothing about this block.
			if len(where[c]) >= genericCompatFiles {
				mb.Generic = true
				continue
			}
			for _, f := range where[c] {
				files[f] = true
			}
			if len(files) > 0 {
				break // the most specific compatible that any file names
			}
		}
		for f := range files {
			mb.Sibling = append(mb.Sibling, f)
		}
		sort.Slice(mb.Sibling, func(i, j int) bool {
			ri, oki := rank[mb.Sibling[i]]
			rj, okj := rank[mb.Sibling[j]]
			switch {
			case oki != okj:
				return oki
			case ri != rj:
				return ri < rj
			}
			return mb.Sibling[i] < mb.Sibling[j]
		})
		if len(mb.Sibling) > 0 {
			g.Siblings++
		} else {
			for _, c := range n.Compatible {
				if len(where[c]) < genericCompatFiles && code[c] {
					mb.InCode = true
				}
			}
		}
		g.Missing = append(g.Missing, mb)
	}
	sort.Slice(g.Missing, func(i, j int) bool { return g.Missing[i].Node.Addr < g.Missing[j].Node.Addr })
	return g
}

// compatibleIndex maps each compatible string a dtsi in dirs names to the
// files naming it.
func compatibleIndex(dirs []string) map[string][]string {
	out := map[string][]string{}
	for _, dir := range dirs {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".dtsi") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			seen := map[string]bool{}
			for _, m := range compatRe.FindAllSubmatch(b, -1) {
				for _, q := range quotedRe.FindAllSubmatch(m[1], -1) {
					if c := string(q[1]); c != "" && !seen[c] {
						seen[c] = true
						out[c] = append(out[c], e.Name())
					}
				}
			}
		}
	}
	return out
}

// SoCGapSection is the report's estimate of the SoC porting work.
func SoCGapSection(g *SoCGap) string {
	if g == nil {
		return ""
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## SoC porting work\n")
	var generic, inCode int
	for _, m := range g.Missing {
		switch {
		case len(m.Sibling) > 0:
		case m.InCode:
			inCode++
		case m.Generic:
			generic++
		}
	}
	nowhere := len(g.Missing) - g.Siblings - inCode - generic
	w("The stock base device tree has %d register-addressed peripherals. `%s` (with %s) defines %d of them; %d are missing. Of those: %d have their compatible named in another dtsi in the tree (a node to copy and adapt, nearest first); %d are named by a driver or binding but no dtsi (upstream can bind them, there is no node); %d carry only a generic compatible; and %d are named nowhere in the tree's dtsi files, drivers or bindings.\n",
		g.Stock, g.Include, quotedList(g.Files), g.Present, len(g.Missing), g.Siblings, inCode, generic, nowhere)
	w("This matches compatible strings exactly. \"Nowhere\" is mostly downstream-only blocks (camera, coresight, bandwidth monitors, debug) with no upstream support under any name; a few are done upstream by another node (the stock `qcom,gdsc` power domains come from the clock controllers, remoteproc `*-pas` nodes have SoC-specific names), so check for an equivalent before writing a driver.\n")
	if len(g.Missing) == 0 {
		return b.String()
	}
	if kinds := g.kindCounts(); len(kinds) > 0 {
		w("Most repeated: %s.\n", strings.Join(kinds, ", "))
	}
	w("A compatible named by %d or more dtsi files (`syscon`, `arm,primecell`) is too common to point at a sibling and is ignored.\n", genericCompatFiles)
	w("| address | node | compatible | in the tree |")
	w("|---|---|---|---|")
	for _, m := range g.Missing {
		compat := "—"
		if len(m.Node.Compatible) > 0 {
			compat = "`" + m.Node.Compatible[0] + "`"
		}
		where := "nowhere"
		switch {
		case len(m.Sibling) > 0:
		case m.InCode:
			where = "a driver or binding only"
		case m.Generic:
			where = "generic compatible only"
		}
		if len(m.Sibling) > 0 {
			where = strings.Join(firstN(m.Sibling, 3), ", ")
			if len(m.Sibling) > 3 {
				where += fmt.Sprintf(" (+%d)", len(m.Sibling)-3)
			}
		}
		w("| %s | %s | %s | %s |", m.Node.Addr, m.Node.Name, compat, where)
	}
	return b.String()
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func quotedList(s []string) string {
	if len(s) <= 1 {
		return "nothing else it includes"
	}
	return "`" + strings.Join(s[1:], "`, `") + "`"
}

// genericCompatFiles is how many dtsi files may name a compatible before it is
// too common to point at a sibling.
const genericCompatFiles = 15

// kindCounts is the missing blocks grouped by their first compatible, most
// common first.
func (g *SoCGap) kindCounts() []string {
	n := map[string]int{}
	for _, m := range g.Missing {
		k := m.Node.Name
		if len(m.Node.Compatible) > 0 {
			k = m.Node.Compatible[0]
		}
		n[k]++
	}
	var keys []string
	for k := range n {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if n[keys[i]] != n[keys[j]] {
			return n[keys[i]] > n[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var out []string
	for _, k := range keys {
		if n[k] < 2 || len(out) == 8 {
			break
		}
		out = append(out, fmt.Sprintf("`%s` ×%d", k, n[k]))
	}
	return out
}

// SoCFile is the path of a matched dtsi: an out-of-tree one (--soc-dtsi) is
// already absolute, a tree one is relative to the tree.
func SoCFile(tree, file string) string {
	if filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(tree, filepath.FromSlash(file))
}

// treeDTSDirs are the vendor directories of the tree's arm64 device trees, where
// a dtsi from outside the tree finds the files it includes.
func treeDTSDirs(tree string) []string {
	base := filepath.Join(tree, "arch", "arm64", "boot", "dts")
	ents, _ := os.ReadDir(base)
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, filepath.Join(base, e.Name()))
		}
	}
	return out
}

// socDirs are the directories to look for a dtsi's includes (and for siblings
// of it) in: its own, and for one outside the tree, the tree's vendor
// directories too.
func socDirs(tree, file string) []string {
	dirs := []string{filepath.Dir(SoCFile(tree, file))}
	if filepath.IsAbs(file) {
		dirs = append(dirs, treeDTSDirs(tree)...)
	}
	return dirs
}

// walkDTSIClosure calls visit on the dtsi at start and on each .dtsi it
// includes, recursively, once each; an include is looked for in dirs in order.
func walkDTSIClosure(start string, dirs []string, visit func(name string, text []byte)) {
	seen := map[string]bool{}
	var read func(path string)
	read = func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		visit(filepath.Base(path), b)
		for _, m := range includeRe.FindAllSubmatch(b, -1) {
			name := filepath.Base(string(m[1]))
			for _, d := range dirs {
				if _, err := os.Stat(filepath.Join(d, name)); err == nil {
					read(filepath.Join(d, name))
					break
				}
			}
		}
	}
	read(start)
}

var labelRe = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*):\s`)

// SoCLabels are the node labels the SoC dtsi (and what it includes) defines,
// which a board file can refer to as &label. nil when there is no dtsi to read.
func SoCLabels(tree, include string) map[string]bool {
	if include == "" {
		return nil
	}
	out := map[string]bool{}
	walkDTSIClosure(SoCFile(tree, include), socDirs(tree, include), func(_ string, b []byte) {
		for _, m := range labelRe.FindAllSubmatch(b, -1) {
			out[string(m[1])] = true
		}
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

var (
	refRe       = regexp.MustCompile(`&([A-Za-z_][A-Za-z0-9_]*)\b`)
	intCellsRe  = regexp.MustCompile(`#interrupt-cells\s*=\s*<\s*(\d+)\s*>`)
	labelNodeRe = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*):\s*[^{;]*\{`)
)

// SoCDTSIFacts is what a board file can learn from the SoC dtsi without
// compiling it: the labels the dtsi uses but does not define (the board must
// provide them), and each labelled node's #interrupt-cells, which decides how
// an interrupt may be written against it.
type SoCDTSIFacts struct {
	Needs          []string
	InterruptCells map[string]int
}

// ReadSoCDTSI reads the dtsi (with its includes) for SoCDTSIFacts.
func ReadSoCDTSI(tree, include string) SoCDTSIFacts {
	f := SoCDTSIFacts{InterruptCells: map[string]int{}}
	if include == "" {
		return f
	}
	defined, used := map[string]bool{}, map[string]bool{}
	walkDTSIClosure(SoCFile(tree, include), socDirs(tree, include), func(_ string, b []byte) {
		text := stripComments(string(b))
		for _, m := range labelRe.FindAllStringSubmatch(text, -1) {
			defined[m[1]] = true
		}
		for _, m := range refRe.FindAllStringSubmatch(text, -1) {
			used[m[1]] = true
		}
		for _, loc := range labelNodeRe.FindAllStringSubmatchIndex(text, -1) {
			label, open := text[loc[2]:loc[3]], loc[1]-1
			if cells := intCellsRe.FindStringSubmatch(directBody(text, open)); cells != nil {
				n := 0
				fmt.Sscan(cells[1], &n)
				f.InterruptCells[label] = n
			}
		}
	})
	for l := range used {
		if !defined[l] {
			f.Needs = append(f.Needs, l)
		}
	}
	sort.Strings(f.Needs)
	return f
}

// directBody is the text of the node whose "{" is at open, without its child
// nodes' bodies, so a property is only matched against the node that has it.
func directBody(text string, open int) string {
	var b strings.Builder
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return b.String()
			}
		default:
			if depth == 1 {
				b.WriteByte(text[i])
			}
		}
	}
	return b.String()
}

var commentRe = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)

func stripComments(s string) string { return commentRe.ReplaceAllString(s, "") }

var (
	quotedCompatRe   = regexp.MustCompile(`"([a-z0-9]+,[A-Za-z0-9_.+-]+)"`)
	unquotedCompatRe = regexp.MustCompile(`[^A-Za-z0-9_.+-]([a-z0-9]+,[A-Za-z0-9_.+-]+)`)
)

// treeCompatibles is every compatible string the kernel tree's drivers and
// device-tree bindings name: C sources (quoted, in their match tables), and
// binding schemas and text bindings (where YAML writes them unquoted). It says
// whether anything upstream could bind a compatible, whatever dtsi uses it.
func treeCompatibles(tree string) map[string]bool {
	var files []string
	for _, sub := range []string{"drivers", "sound", filepath.Join("Documentation", "devicetree", "bindings")} {
		filepath.WalkDir(filepath.Join(tree, sub), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			switch filepath.Ext(p) {
			case ".c", ".h", ".yaml", ".txt":
				files = append(files, p)
			}
			return nil
		})
	}
	out := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan string)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				b, err := os.ReadFile(p)
				if err != nil {
					continue
				}
				re := quotedCompatRe
				if ext := filepath.Ext(p); ext == ".yaml" || ext == ".txt" {
					re = unquotedCompatRe
				}
				var found []string
				for _, m := range re.FindAllSubmatch(b, -1) {
					found = append(found, string(m[1]))
				}
				if filepath.Ext(p) == ".yaml" || filepath.Ext(p) == ".txt" { // quoted ones too
					for _, m := range quotedCompatRe.FindAllSubmatch(b, -1) {
						found = append(found, string(m[1]))
					}
				}
				mu.Lock()
				for _, c := range found {
					out[c] = true
				}
				mu.Unlock()
			}
		}()
	}
	for _, f := range files {
		work <- f
	}
	close(work)
	wg.Wait()
	return out
}

// ClockDef is a clock node copied from a sibling dtsi.
type ClockDef struct {
	Label string
	File  string // the dtsi it came from
	Text  string // "name {\n...};" ready to place under /clocks
}

// blockAt is the text from the "{" at open through its matching "}".
func blockAt(text string, open int) string {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[open : i+1]
			}
		}
	}
	return ""
}

// SiblingClockDefs finds, for each label a board must define, a fixed-clock or
// fixed-factor-clock node by that name in the nearest sibling dtsi that has one
// (in the SoC match order). Only clocks are copied: a node of another kind
// depends on where it sits and what it refers to.
func SiblingClockDefs(tree string, ms []SoCMatch, labels []string) map[string]ClockDef {
	out := map[string]ClockDef{}
	if len(labels) == 0 {
		return out
	}
	for _, m := range ms {
		b, err := os.ReadFile(SoCFile(tree, m.File))
		if err != nil {
			continue
		}
		text := stripComments(string(b))
		for _, l := range labels {
			if _, done := out[l]; done {
				continue
			}
			re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(l) + `:\s*([^{;\s]+)\s*\{`)
			loc := re.FindStringSubmatchIndex(text)
			if loc == nil {
				continue
			}
			block := blockAt(text, loc[1]-1)
			if !strings.Contains(directBody(text, loc[1]-1), "fixed-") {
				continue
			}
			out[l] = ClockDef{Label: l, File: filepath.Base(m.File), Text: text[loc[2]:loc[3]] + " " + block}
		}
	}
	return out
}

var addrLabelRe = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*):\s*[A-Za-z0-9_,.+\-]*@([0-9a-fA-F]+)\s*\{`)

// SoCLabelsByAddr maps a node's unit address (lower case, no leading zeros) to
// the label the SoC dtsi (with its includes) gives it: the way to name a block
// the stock tree knows by address and a mainline file knows by label.
func SoCLabelsByAddr(tree, include string) map[string]string {
	if include == "" {
		return nil
	}
	out := map[string]string{}
	walkDTSIClosure(SoCFile(tree, include), socDirs(tree, include), func(_ string, b []byte) {
		for _, m := range addrLabelRe.FindAllStringSubmatch(stripComments(string(b)), -1) {
			a := strings.TrimLeft(strings.ToLower(m[2]), "0")
			if _, dup := out[a]; !dup && a != "" { // address 0 (a CPU, a pool) is no register address
				out[a] = m[1]
			}
		}
	})
	return out
}
