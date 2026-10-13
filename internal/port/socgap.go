package port

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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
	dir := filepath.Join(tree, "arch", "arm64", "boot", "dts", "qcom")
	g := &SoCGap{Include: p.SoC[0].File, Stock: len(p.DT.SoCNodes)}

	// The include's closure: the dtsi and the .dtsi files it pulls in.
	have := map[string]bool{}
	seen := map[string]bool{}
	var read func(name string)
	read = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return
		}
		g.Files = append(g.Files, name)
		for _, m := range treeAddr.FindAllSubmatch(b, -1) {
			have[strings.TrimLeft(strings.ToLower(string(m[1])), "0")] = true
		}
		for _, m := range includeRe.FindAllSubmatch(b, -1) {
			read(filepath.Base(string(m[1])))
		}
	}
	read(filepath.Base(g.Include))

	// Every dtsi's compatibles, ranked by how much of the stock register map
	// each shares (SoC order), for naming the nearest sibling.
	rank := map[string]int{}
	for i, m := range p.SoC {
		rank[filepath.Base(m.File)] = i
	}
	where := compatibleIndex(dir)

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
		}
		g.Missing = append(g.Missing, mb)
	}
	sort.Slice(g.Missing, func(i, j int) bool { return g.Missing[i].Node.Addr < g.Missing[j].Node.Addr })
	return g
}

// compatibleIndex maps each compatible string a dtsi in dir names to the
// files naming it.
func compatibleIndex(dir string) map[string][]string {
	out := map[string][]string{}
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
	generic := 0
	for _, m := range g.Missing {
		if len(m.Sibling) == 0 && m.Generic {
			generic++
		}
	}
	none := len(g.Missing) - g.Siblings - generic
	w("The stock base device tree has %d register-addressed peripherals. `%s` (with %s) defines %d of them; %d are missing. Of those, %d have their compatible named in another dtsi in the tree (a node to copy and adapt, nearest first), %d carry only a generic compatible, and %d have a compatible no dtsi names.\n",
		g.Stock, g.Include, quotedList(g.Files), g.Present, len(g.Missing), g.Siblings, generic, none)
	w("This matches compatible strings, so it overstates the work: a vendor kernel's compatible often differs from the one mainline uses for the same IP (the stock `qcom,gdsc` blocks are power domains that mainline's clock drivers provide). Read \"none\" as \"no mainline node under this name\", and check for an equivalent before writing a driver.\n")
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
		where := "none"
		if len(m.Sibling) == 0 && m.Generic {
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
