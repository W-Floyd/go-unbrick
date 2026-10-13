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
	b.Walk(func(path string, n *fdt.Node) {
		if a, ok := unitAddr(n.Name); ok {
			if !dt.UnitAddrs[a] && !strings.Contains(path, "reserved-memory") && !strings.Contains(path, "__") {
				dt.SoCNodes = append(dt.SoCNodes, SoCNode{Path: path, Name: n.Name, Addr: a, Compatible: n.Strs("compatible")})
			}
			dt.UnitAddrs[a] = true
		}
	})
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
// arch/arm64/boot/dts/qcom by how much of the stock base DTB's register map
// they share. No table of SoC names is involved: a SoC is its register map,
// and the closest dtsi is the one to include (the runner-up is usually the
// family fallback compatible). Matches with nothing in common are dropped.
func FindSoCDTSI(root string, stock map[string]bool) ([]SoCMatch, error) {
	dir := filepath.Join(root, "arch", "arm64", "boot", "dts", "qcom")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: dir, Err: err}
	}
	var out []SoCMatch
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".dtsi") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		tree := map[string]bool{}
		for _, m := range treeAddr.FindAllSubmatch(b, -1) {
			tree[strings.TrimLeft(strings.ToLower(string(m[1])), "0")] = true
		}
		shared := 0
		for a := range stock {
			if tree[a] {
				shared++
			}
		}
		if shared == 0 {
			continue
		}
		out = append(out, SoCMatch{File: filepath.ToSlash(filepath.Join("arch/arm64/boot/dts/qcom", e.Name())),
			Shared: shared, Stock: len(stock), Tree: len(tree),
			Score: float64(shared) / float64(len(stock)+len(tree)-shared)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].File < out[j].File
	})
	return out, nil
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
func SoCReport(tree string, ms []SoCMatch) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## SoC device tree (%s)\n", tree)
	if len(ms) == 0 {
		w("No SoC dtsi in the tree shares a register address with the stock base device tree.")
		return b.String()
	}
	w("Ranked by the share of the stock base device tree's register addresses (the SoC's fingerprint). The best is the include; a close runner-up is often the SoC family a board also lists as a fallback compatible.\n")
	w("| dtsi | shared addresses | stock has | dtsi has | score |")
	w("|---|---|---|---|---|")
	for i, m := range ms {
		if i == 4 {
			break
		}
		w("| %s | %d | %d | %d | %.2f |", m.File, m.Shared, m.Stock, m.Tree, m.Score)
	}
	return b.String()
}
