package port

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

// Region is one reserved-memory region.
type Region struct {
	Name     string // node name without its unit address: "hyp_region"
	Addr     uint64 // 0 for a pool the kernel places (no fixed address)
	Size     uint64
	Fixed    bool // has a fixed address (a "reg")
	NoMap    bool
	Reusable bool
	Compat   string // "shared-dma-pool", "ramoops", ...
	From     string // "base" or "overlay"
}

func (r Region) key() string { return fmt.Sprintf("%x+%x", r.Addr, r.Size) }

func (r Region) String() string {
	if !r.Fixed {
		return fmt.Sprintf("%s (pool of %#x)", r.Name, r.Size)
	}
	return fmt.Sprintf("%s@%x (%#x)", r.Name, r.Addr, r.Size)
}

// readRegions collects the reserved-memory regions of the stock device trees:
// the base DTB's reserved-memory node and every overlay fragment that adds to
// it (whatever label the overlay names it by, found through its fixups).
func readRegions(base, overlays []*fdt.Node) []Region {
	var out []Region
	add := func(parent *fdt.Node, from string) {
		for _, c := range parent.Children {
			if r, ok := regionOf(c); ok {
				r.From = from
				out = append(out, r)
			}
		}
	}
	for _, b := range base {
		if rm := childNamed(b, "reserved-memory"); rm != nil {
			add(rm, "base")
		}
	}
	for _, o := range overlays {
		targets := fragmentTargets(o)
		for _, frag := range o.Children {
			if ov := childNamed(frag, "__overlay__"); ov != nil && strings.Contains(strings.ToLower(targets[frag.Name]), "reserved") {
				add(ov, "overlay")
			}
		}
	}
	return dedupeRegions(out)
}

// regionOf reads a reserved-memory child: "reg" is four cells (address and
// size, two cells each) under the usual #address-cells = <2>.
func regionOf(n *fdt.Node) (Region, bool) {
	r := Region{Name: n.Name, NoMap: hasProp(n, "no-map"), Reusable: hasProp(n, "reusable")}
	if i := strings.Index(r.Name, "@"); i >= 0 {
		r.Name = r.Name[:i]
	}
	if c := n.Strs("compatible"); len(c) > 0 {
		r.Compat = c[0]
	}
	if reg := n.U32s("reg"); len(reg) == 4 {
		r.Addr, r.Size, r.Fixed = uint64(reg[0])<<32|uint64(reg[1]), uint64(reg[2])<<32|uint64(reg[3]), true
		return r, true
	}
	if sz := n.U32s("size"); len(sz) == 2 {
		r.Size = uint64(sz[0])<<32 | uint64(sz[1])
		return r, true
	}
	return Region{}, false
}

func hasProp(n *fdt.Node, name string) bool { _, ok := n.Props[name]; return ok }

func dedupeRegions(rs []Region) []Region {
	seen := map[string]bool{}
	var out []Region
	for _, r := range rs {
		k := r.key() + "/" + r.Name
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

var (
	rmOpen   = regexp.MustCompile(`reserved-memory\s*\{`)
	regLine  = regexp.MustCompile(`reg\s*=\s*<\s*(0x[0-9a-fA-F]+|\d+)\s+(0x[0-9a-fA-F]+|\d+)\s+(0x[0-9a-fA-F]+|\d+)\s+(0x[0-9a-fA-F]+|\d+)\s*>`)
	nodeOpen = regexp.MustCompile(`^(?:[A-Za-z0-9_]+:\s*)?([A-Za-z0-9_,.+\-]+)(?:@[0-9a-fA-F]+)?\s*\{`)
)

// ParseDTSRegions reads the reserved-memory regions a device-tree source file
// defines, from every reserved-memory block in it (a dtsi and the board's own
// block both have one). Like ParseReferenceDTS it is a line reader.
func ParseDTSRegions(src string) []Region {
	src = lineComment.ReplaceAllString(blockComment.ReplaceAllString(src, ""), "")
	var out []Region
	depth, inBlock, blockDepth := 0, false, 0
	var cur *Region
	for _, line := range strings.Split(src, "\n") {
		l := strings.TrimSpace(line)
		if !inBlock && rmOpen.MatchString(l) {
			inBlock, blockDepth = true, depth
		} else if inBlock && depth == blockDepth+1 {
			if m := nodeOpen.FindStringSubmatch(l); m != nil {
				cur = &Region{Name: m[1]}
			}
		}
		if inBlock && cur != nil && depth == blockDepth+2 {
			if m := regLine.FindStringSubmatch(l); m != nil {
				v := func(s string) uint64 { x, _ := strconv.ParseUint(s, 0, 64); return x }
				cur.Addr, cur.Size, cur.Fixed = v(m[1])<<32|v(m[2]), v(m[3])<<32|v(m[4]), true
			}
			if l == "no-map;" {
				cur.NoMap = true
			}
			if m := compatLine.FindStringSubmatch(l); m != nil {
				if q := quoted.FindStringSubmatch(m[1]); q != nil {
					cur.Compat = q[1]
				}
			}
		}
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if inBlock && cur != nil && depth == blockDepth+1 {
			if cur.Fixed {
				out = append(out, *cur)
			}
			cur = nil
		}
		if inBlock && depth <= blockDepth {
			inBlock, cur = false, nil
		}
	}
	return out
}

// BoardRegions are the fixed stock regions a SoC dtsi does not already
// define: the board-level reservations the board dts must add. Regions the dtsi
// has at the same address and size are the SoC's own.
func BoardRegions(stock, soc []Region) (board, inSoC []Region) {
	have := map[string]bool{}
	for _, r := range soc {
		have[r.key()] = true
	}
	for _, r := range stock {
		if !r.Fixed {
			continue
		}
		if have[r.key()] {
			inSoC = append(inSoC, r)
		} else {
			board = append(board, r)
		}
	}
	return board, inSoC
}

// regionsText is the board dts's reserved-memory block for regions.
func regionsText(rs []Region) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\treserved-memory {")
	for _, r := range rs {
		name := strings.ReplaceAll(r.Name, "_", "-")
		w("\t\t/* stock: %s (%s) */", r.Name, r.From)
		w("\t\t%s@%x {", name, r.Addr)
		if r.Compat != "" {
			w("\t\t\tcompatible = %q;", r.Compat)
		}
		w("\t\t\treg = <0x%x 0x%x 0x%x 0x%x>;", r.Addr>>32, r.Addr&0xffffffff, r.Size>>32, r.Size&0xffffffff)
		if r.NoMap {
			w("\t\t\tno-map;")
		}
		w("\t\t};")
	}
	w("\t};")
	return b.String()
}

// MemorySection is the report section for the reserved-memory comparison.
func MemorySection(p Package) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## Reserved memory\n")
	fixed, pools := 0, []Region{}
	for _, r := range p.DT.Reserved {
		if r.Fixed {
			fixed++
		} else {
			pools = append(pools, r)
		}
	}
	w("The stock device trees reserve %d fixed regions and %d pools.", fixed, len(pools))
	if p.SoCRegions == nil {
		w("Pass `--kernel-tree` to see which of them the SoC dtsi already has.")
		return b.String()
	}
	board, inSoC := BoardRegions(p.DT.Reserved, p.SoCRegions)
	w("%d are already in the SoC dtsi at the same address and size; **%d are not**, and go in the board dts:\n", len(inSoC), len(board))
	if len(board) > 0 {
		w("| region | address | size | from |")
		w("|---|---|---|---|")
		for _, r := range board {
			w("| %s | %#x | %#x | %s |", r.Name, r.Addr, r.Size, r.From)
		}
	}
	if len(pools) > 0 {
		var names []string
		for _, r := range pools {
			names = append(names, r.String())
		}
		w("\nPools the kernel places (no fixed address; a board decides whether it needs them): %s.", strings.Join(names, ", "))
	}
	return b.String()
}
