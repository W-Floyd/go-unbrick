package port

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RefNode is a device node of a reference device tree: a child of a bus
// controller reference ("&i2c1 { sgm@47 { ... } }").
type RefNode struct {
	Bus, Name  string
	Addr       uint32
	Compatible []string
	// Pins are the interrupt, reset and enable pins the node names, by kind
	// (the first pin of a "<&tlmm N flags>" specifier).
	Pins map[PinKind]uint32
}

var (
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`//[^\n]*`)
	busOpen      = regexp.MustCompile(`^&([A-Za-z0-9_]+)\s*\{`)
	childOpen    = regexp.MustCompile(`^(?:[A-Za-z0-9_]+:\s*)?([A-Za-z0-9_,.+\-]+)@([0-9a-fA-F]+)\s*\{`)
	compatLine   = regexp.MustCompile(`^compatible\s*=\s*([^;]+);`)
	compatAny    = regexp.MustCompile(`compatible\s*=\s*([^;]+);`)
	quoted       = regexp.MustCompile(`"([^"]*)"`)
)

// ParseReferenceDTS reads the nodes a device-tree source file puts directly
// under bus controller references. It is a line reader, enough for the
// conventional layout of a board dts; it does not preprocess or follow
// includes.
func ParseReferenceDTS(src string) []RefNode {
	src = lineComment.ReplaceAllString(blockComment.ReplaceAllString(src, ""), "")
	var out []RefNode
	bus := ""
	depth := 0
	var cur *RefNode
	for _, line := range strings.Split(src, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case depth == 0:
			if m := busOpen.FindStringSubmatch(l); m != nil {
				bus = m[1]
			}
		case depth == 1 && bus != "":
			if m := childOpen.FindStringSubmatch(l); m != nil {
				a, _ := strconv.ParseUint(m[2], 16, 32)
				cur = &RefNode{Bus: bus, Name: m[1], Addr: uint32(a)}
				// A node written on one line carries its compatible there.
				if c := compatAny.FindStringSubmatch(l); c != nil {
					for _, q := range quoted.FindAllStringSubmatch(c[1], -1) {
						cur.Compatible = append(cur.Compatible, q[1])
					}
				}
			}
		case depth == 2 && cur != nil:
			if cur.Compatible == nil {
				if m := compatLine.FindStringSubmatch(l); m != nil {
					for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
						cur.Compatible = append(cur.Compatible, q[1])
					}
				}
			}
			recordPin(cur, l)
		}
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if depth == 1 && cur != nil {
			out = append(out, *cur)
			cur = nil
		}
		if depth <= 0 {
			depth, bus, cur = 0, "", nil
		}
	}
	return out
}

var (
	propLine = regexp.MustCompile(`^([A-Za-z0-9_,#+\-]+)\s*=\s*(.*);`)
	pinSpec  = regexp.MustCompile(`<&[A-Za-z0-9_]+\s+(0x[0-9a-fA-F]+|\d+)`)
	firstNum = regexp.MustCompile(`<\s*(0x[0-9a-fA-F]+|\d+)`)
)

// recordPin notes the pin a property line names, when it is an interrupt,
// reset or enable pin in the shapes ClassifyPins reads on the stock side.
func recordPin(n *RefNode, line string) {
	m := propLine.FindStringSubmatch(line)
	if m == nil {
		return
	}
	prop, val := m[1], m[2]
	var kind PinKind
	var pinStr string
	switch {
	case prop == "interrupts-extended":
		kind = PinIRQ
		if s := pinSpec.FindStringSubmatch(val); s != nil {
			pinStr = s[1]
		}
	case prop == "interrupts":
		kind = PinIRQ
		if s := firstNum.FindStringSubmatch(val); s != nil {
			pinStr = s[1]
		}
	case resetProp.MatchString(prop):
		kind = PinReset
		if s := pinSpec.FindStringSubmatch(val); s != nil {
			pinStr = s[1]
		}
	case enableProp.MatchString(prop):
		kind = PinEnable
		if s := pinSpec.FindStringSubmatch(val); s != nil {
			pinStr = s[1]
		}
	case irqProp.MatchString(prop):
		kind = PinIRQ
		if s := pinSpec.FindStringSubmatch(val); s != nil {
			pinStr = s[1]
		}
	}
	if pinStr == "" {
		return
	}
	v, err := strconv.ParseUint(pinStr, 0, 32)
	if err != nil {
		return
	}
	if n.Pins == nil {
		n.Pins = map[PinKind]uint32{}
	}
	if _, dup := n.Pins[kind]; !dup {
		n.Pins[kind] = uint32(v)
	}
}

// comparePins says how a placed part's pins line up with a reference node's.
func comparePins(pt Part, r RefNode) (summary string, agree, differ int) {
	uses, _ := ClassifyPins(pt)
	var parts []string
	for _, u := range uses {
		rp, ok := r.Pins[u.Kind]
		if !ok {
			continue
		}
		if rp == u.Pin {
			agree++
			parts = append(parts, fmt.Sprintf("%s %d ✓", u.Kind, u.Pin))
		} else {
			differ++
			parts = append(parts, fmt.Sprintf("%s stock %d, reference %d", u.Kind, u.Pin, rp))
		}
	}
	return strings.Join(parts, "; "), agree, differ
}

// CompareDTS lines the generated peripherals up against a reference device
// tree, by bus and address, and says where they agree, where the same slot has
// a different compatible, and what the reference has that the stock overlays
// do not. It is the generator's accuracy check on a device that has a
// hand-written port.
func CompareDTS(p Package, reference string) string {
	ref := ParseReferenceDTS(reference)
	type key struct {
		bus  string
		addr uint32
	}
	byKey := map[key]RefNode{}
	for _, r := range ref {
		byKey[key{r.Bus, r.Addr}] = r
	}

	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	var same, differ, missing, pinsAgree, pinsDiffer int
	used := map[key]bool{}
	var rows []string
	for _, pt := range p.DT.Parts {
		bus, ok := MainlineBus(pt.Bus)
		if !ok || pt.Source == nil {
			continue
		}
		k := key{bus, addrOf(pt)}
		r, found := byKey[k]
		status := ""
		switch {
		case !found:
			missing++
			status = "no node at this address in the reference"
		case contains(r.Compatible, pt.Compatible) || mainlineMatches(p, pt, r):
			same++
			used[k] = true
			status = "agrees"
		default:
			differ++
			used[k] = true
			status = "same slot, different part: reference has `" + strings.Join(r.Compatible, "`, `") + "`"
		}
		pins := "—"
		if found {
			if s, a, d := comparePins(pt, r); s != "" {
				pins = s
				pinsAgree += a
				pinsDiffer += d
			}
		}
		rows = append(rows, fmt.Sprintf("| %s@%x | `%s` | %s | %s |", bus, k.addr, pt.Compatible, status, pins))
	}
	sort.Strings(rows)
	w("## Generated peripherals against the reference DTS\n")
	w("Of the stock parts placed on a bus: %d agree with the reference's compatible, %d are the same slot with a different part, %d have no node at that address.", same, differ, missing)
	w("Pins, over the slots the reference also has: %d agree, %d differ.\n", pinsAgree, pinsDiffer)
	w("| bus@addr | stock compatible | against the reference | pins (interrupt, reset, enable) |")
	w("|---|---|---|---|")
	for _, r := range rows {
		w("%s", r)
	}
	var extra []string
	for _, r := range ref {
		if !used[key{r.Bus, r.Addr}] {
			extra = append(extra, fmt.Sprintf("%s@%x `%s`", r.Bus, r.Addr, strings.Join(r.Compatible, "`, `")))
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		w("\nIn the reference but not in the stock overlays (a part the stock firmware does not describe): %s.", strings.Join(extra, "; "))
	}
	return b.String()
}

// mainlineMatches is true when the reference's compatible is one the kernel
// scan offered for the stock part (a sibling or the exact driver): the
// generator pointed at it, even though the stock string differs.
func mainlineMatches(p Package, pt Part, r RefNode) bool {
	md := p.Mainline[pt.Compatible]
	if md == nil {
		return false
	}
	for _, s := range md.Similar {
		for _, c := range r.Compatible {
			if strings.HasPrefix(s, c+" ") {
				return true
			}
		}
	}
	return false
}
