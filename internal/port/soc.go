package port

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

// minAddrDigits is how long a unit address must be to count as a register
// address: shorter ones are I2C and SPI client addresses, which every board
// reuses.
const minAddrDigits = 5

// collectAddrs records a base DTB's labels and peripheral unit addresses.
func collectAddrs(b *fdt.Node, dt *DT) {
	if s := childNamed(b, "__symbols__"); s != nil {
		for _, k := range s.Keys {
			if _, ok := dt.Symbols[k]; !ok {
				dt.Symbols[k] = strings.TrimRight(string(s.Props[k]), "\x00")
			}
		}
	}
	labelsAt := map[string][]string{} // node path -> its labels, from this tree's own __symbols__
	if s := childNamed(b, "__symbols__"); s != nil {
		for _, k := range s.Keys {
			p := strings.TrimRight(string(s.Props[k]), "\x00")
			labelsAt[p] = append(labelsAt[p], k)
		}
	}
	b.Walk(func(path string, n *fdt.Node) {
		if dn, ok := displayNode(path, n); ok {
			dt.DisplayNodes = appendSoCNode(dt.DisplayNodes, dn)
		}
		if a, ok := unitAddr(n.Name); ok {
			if !dt.UnitAddrs[a] && !strings.Contains(path, "reserved-memory") && !strings.Contains(path, "__") {
				dt.SoCNodes = append(dt.SoCNodes, SoCNode{Path: path, Name: n.Name, Addr: a, Compatible: n.Strs("compatible")})
			}
			dt.UnitAddrs[a] = true
		}
		// The board-level fixed clocks (the crystal, the sleep clock) the SoC's
		// clock controllers take as inputs: a board file must define them.
		for _, c := range n.Strs("compatible") {
			if c != "fixed-clock" {
				continue
			}
			if f := n.U32s("clock-frequency"); len(f) == 1 {
				for _, label := range labelsAt[path] {
					if _, ok := dt.FixedClocks[label]; !ok {
						dt.FixedClocks[label] = FixedClock{Label: label, Name: n.Name, Freq: f[0]}
					}
				}
			}
		}
	})
}

// FixedClock is a "fixed-clock" node of the stock base tree.
type FixedClock struct {
	Label, Name string
	Freq        uint32 // Hz
}

// SoCNode is one peripheral of the stock base device tree, found by its
// register address.
type SoCNode struct {
	Path, Name, Addr string
	Compatible       []string
}

var hexAddr = regexp.MustCompile(`^[0-9a-f]+$`)

// unitAddr is the register address in a node name "serial@4a84000".
func unitAddr(name string) (string, bool) {
	i := strings.LastIndex(name, "@")
	if i < 0 {
		return "", false
	}
	a := strings.ToLower(name[i+1:])
	if len(a) < minAddrDigits || !hexAddr.MatchString(a) {
		return "", false
	}
	return strings.TrimLeft(a, "0"), true
}

// busKind is "i2c", "i3c" or "spi" for a stock bus label that names one.
func busKind(label string) string {
	l := strings.ToLower(label)
	for _, k := range []string{"i2c", "i3c", "spi"} {
		if strings.Contains(l, k) {
			return k
		}
	}
	return ""
}

// SoCMatch is how well a SoC dtsi in a kernel tree fits the stock peripherals.
type SoCMatch struct {
	File   string  // relative to the tree
	Shared int     // addresses both name
	Stock  int     // addresses the stock base DTB has
	Tree   int     // addresses the dtsi has
	Score  float64 // Shared / (Stock + Tree - Shared)
}

var treeAddr = regexp.MustCompile(`@([0-9a-fA-F]{5,})\s*\{`)

// FindSoCDTSI ranks the SoC device-tree includes in a kernel tree's
// arch/arm64/boot/dts (every vendor directory) by how much of the stock base
// DTB's register map they share. No table of SoC names or vendors is involved:
// a SoC is its register map, and the closest dtsi is the one to include (the
// runner-up is usually the family fallback compatible). Matches with nothing in
// common are dropped.
func FindSoCDTSI(root string, stock map[string]bool) ([]SoCMatch, error) {
	base := filepath.Join(root, "arch", "arm64", "boot", "dts")
	vendors, err := os.ReadDir(base)
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: base, Err: err}
	}
	var out []SoCMatch
	for _, v := range vendors {
		if !v.IsDir() {
			continue
		}
		out = append(out, matchDir(filepath.Join(base, v.Name()), "arch/arm64/boot/dts/"+v.Name(), stock)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].File < out[j].File
	})
	return out, nil
}

// matchDir scores each dtsi directly in dir; rel is dir within the tree.
func matchDir(dir, rel string, stock map[string]bool) []SoCMatch {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []SoCMatch
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".dtsi") {
			continue
		}
		// A tree file is scored on its own text: one that includes another is a
		// board's file (mt8183-kukui-*.dtsi) and would tie with the SoC's it
		// includes. Only a file from outside the tree is scored with its
		// includes, since that is how a series adds a SoC to a mainline one.
		if m, ok := scoreDTSI(filepath.Join(dir, e.Name()), rel+"/"+e.Name(), stock, nil); ok {
			out = append(out, m)
		}
	}
	return out
}

// scoreDTSI is how much of the stock register map a dtsi shares, under the name
// file; ok is false when it shares none.
func scoreDTSI(path, file string, stock map[string]bool, dirs []string) (SoCMatch, bool) {
	// The SoC is the file and what it includes: a file that adds a SoC to a
	// mainline one is scored on both.
	tree := map[string]bool{}
	walkDTSIClosure(path, dirs, func(_ string, b []byte) {
		for _, m := range treeAddr.FindAllSubmatch(b, -1) {
			tree[strings.TrimLeft(strings.ToLower(string(m[1])), "0")] = true
		}
	})
	if len(tree) == 0 {
		return SoCMatch{}, false
	}
	shared := 0
	for a := range stock {
		if tree[a] {
			shared++
		}
	}
	if shared == 0 {
		return SoCMatch{}, false
	}
	return SoCMatch{File: file, Shared: shared, Stock: len(stock), Tree: len(tree),
		Score: float64(shared) / float64(len(stock)+len(tree)-shared)}, true
}

// FindExtraSoCDTSI scores dtsi files from outside the kernel tree the same way:
// each path is a file, or a directory searched for .dtsi files (a checkout of a
// patch series, a vendor or distribution kernel fork). Their File is the
// absolute path, which the rest of the port reads as "not in the tree".
func FindExtraSoCDTSI(tree string, paths []string, stock map[string]bool) ([]SoCMatch, error) {
	var out []SoCMatch
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(abs)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			if m, ok := scoreDTSI(abs, abs, stock, socDirs(tree, abs)); ok {
				out = append(out, m)
			}
			continue
		}
		filepath.WalkDir(abs, func(f string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() && (e.Name() == ".git" || e.Name() == "Documentation") {
				return filepath.SkipDir
			}
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".dtsi") {
				if m, ok := scoreDTSI(f, f, stock, socDirs(tree, f)); ok {
					out = append(out, m)
				}
			}
			return nil
		})
	}
	return out, nil
}

// MergeSoCMatches puts matches from several sources in one ranking, best first.
func MergeSoCMatches(lists ...[]SoCMatch) []SoCMatch {
	var out []SoCMatch
	for _, l := range lists {
		out = append(out, l...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].File < out[j].File
	})
	return out
}

// BusLabels maps each stock serial-engine bus label to the label a mainline
// dtsi gives the node at the same register address: the stock overlay's
// "qupv3_se1_i2c" sits at 4a84000, which the dtsi calls "i2c1". Labels the
// stock tree or the dtsi cannot place are left out.
func BusLabels(dt DT, dtsi string) map[string]string {
	out := map[string]string{}
	label := regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+):\s*(i2c|spi|i3c)@([0-9a-fA-F]+)\s*\{`)
	// A serial engine is one block that is an I2C or a SPI controller, so the
	// dtsi has both (i2c1 and spi1) at one address: the kind picks between them.
	byKindAddr := map[string]string{}
	for _, m := range label.FindAllStringSubmatch(dtsi, -1) {
		byKindAddr[m[2]+":"+strings.TrimLeft(strings.ToLower(m[3]), "0")] = m[1]
	}
	for stock, path := range dt.Symbols {
		kind := busKind(stock)
		if kind == "" {
			continue
		}
		leaf := path[strings.LastIndex(path, "/")+1:]
		if a, ok := unitAddr(leaf); ok {
			if l, ok := byKindAddr[kind+":"+a]; ok {
				out[stock] = l
			}
		}
	}
	return out
}

// SoCReport is the report section for the ranked dtsi matches.
func SoCReport(tree string, ms []SoCMatch, soc string) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## SoC device tree (%s)\n", tree)
	if len(ms) == 0 {
		w("No SoC dtsi in the tree shares a register address with the stock base device tree. If the SoC has support outside the tree (a patch series, a vendor or distribution kernel fork), pass its dtsi with `--soc-dtsi`.")
		return b.String()
	}
	w("Ranked by the share of the stock base device tree's register addresses (the SoC's fingerprint). The best is the include; a close runner-up is often the SoC family a board also lists as a fallback compatible.\n")
	w("| dtsi | shared addresses | stock has | dtsi has | score |")
	w("|---|---|---|---|---|")
	for i, m := range ms {
		// The best few, and every file the person passed in by hand: those are
		// shown wherever they rank.
		if i >= 4 && !filepath.IsAbs(m.File) {
			continue
		}
		name := m.File
		if filepath.IsAbs(m.File) {
			name = "(out of tree) " + m.File
		}
		w("| %s | %d | %d | %d | %.2f |", name, m.Shared, m.Stock, m.Tree, m.Score)
	}
	best := ms[0].Score
	for _, m := range ms {
		best = max(best, m.Score)
	}
	if ms[0].Score < best {
		w("\n`%s` is ranked first although files above score higher: it names `%s`, and a smaller dtsi for the right SoC covers fewer blocks than a larger one for a sibling (related SoCs share much of their address map).", filepath.Base(ms[0].File), soc)
	}
	if model := socModel(soc); model != "" && !dtsiMentions(tree, ms[0].File, model) {
		w("\n`%s` is the closest register map available, but nothing in it names `%s`: it may be a related SoC and not this one. A recent SoC often has support in a patch series or a vendor or distribution kernel fork that is not in this tree; if you have its dtsi, pass it with `--soc-dtsi` and it is ranked with the tree's.", filepath.Base(ms[0].File), soc)
	}
	return b.String()
}

// socModel is the part of the base tree's SoC compatible after the vendor
// ("mt6768" from "mediatek,MT6768"), lower case.
func socModel(compatible string) string {
	_, m, ok := strings.Cut(compatible, ",")
	if !ok {
		return ""
	}
	return strings.ToLower(m)
}

// dtsiMentions says whether the dtsi, or a file it includes, contains the word.
func dtsiMentions(tree, file, word string) bool {
	found := false
	walkDTSIClosure(SoCFile(tree, file), socDirs(tree, file), func(_ string, b []byte) {
		if strings.Contains(strings.ToLower(string(b)), word) {
			found = true
		}
	})
	return found
}

// appendSoCNode adds n unless a node at its address is already there.
func appendSoCNode(list []SoCNode, n SoCNode) []SoCNode {
	for _, e := range list {
		if e.Addr == n.Addr {
			return list
		}
	}
	return append(list, n)
}

// regAddr is the register address a node's "reg" gives, as hex without leading
// zeros, for nodes whose names carry no unit address. A reg of four or more
// cells under #address-cells = <2> leads with a zero high word.
func regAddr(n *fdt.Node) string {
	reg := n.U32s("reg")
	if len(reg) < 2 {
		return ""
	}
	a := uint64(reg[0])
	if reg[0] == 0 && len(reg) >= 4 {
		a = uint64(reg[1])
	}
	if a == 0 {
		return ""
	}
	return fmt.Sprintf("%x", a)
}

// displayNode is a DSI controller or PHY node, found by its compatible and
// placed by its name's unit address or else its reg.
func displayNode(path string, n *fdt.Node) (SoCNode, bool) {
	for _, c := range n.Strs("compatible") {
		if strings.Contains(c, "dsi-ctrl") || strings.Contains(c, "dsi-phy") {
			addr, ok := unitAddr(n.Name)
			if !ok {
				addr = regAddr(n)
			}
			if addr == "" {
				return SoCNode{}, false
			}
			return SoCNode{Path: path, Name: n.Name, Addr: addr, Compatible: n.Strs("compatible")}, true
		}
	}
	return SoCNode{}, false
}

// minNamedShared is how many stock register addresses a dtsi must share before
// naming the SoC counts: a name in a file with next to no overlap is a
// coincidence (a board file, a different SoC that mentions this one).
const minNamedShared = 10

// PreferNamed moves the matches whose dtsi (with its includes) names the stock
// SoC to the front, keeping each group's order. A small early dtsi for the right
// SoC scores below a big one for a sibling, because the address map of related
// SoCs is largely shared; the name is the better evidence of which is the SoC.
// Nothing changes when no match names it (the usual case for a SoC the stock
// tree knows by a codename).
func PreferNamed(tree string, ms []SoCMatch, soc string) []SoCMatch {
	model := socModel(soc)
	if model == "" {
		return ms
	}
	var named, rest []SoCMatch
	for _, m := range ms {
		if m.Shared >= minNamedShared && dtsiMentions(tree, m.File, model) {
			named = append(named, m)
		} else {
			rest = append(rest, m)
		}
	}
	return append(named, rest...)
}
