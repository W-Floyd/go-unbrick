package efi

import (
	"bytes"
	"sort"
	"strconv"
)

// ModuleChange is one module whose contents differ between two images.
type ModuleChange struct {
	GUID         string
	Name         string // from either side; the first that has one
	SizeA, SizeB int
}

func (c ModuleChange) String() string {
	n := c.Name
	if n == "" {
		n = c.GUID
	}
	if c.SizeA != c.SizeB {
		return n + " (" + strconv.Itoa(c.SizeA) + " -> " + strconv.Itoa(c.SizeB) + " bytes)"
	}
	return n + " (" + strconv.Itoa(c.SizeA) + " bytes, contents differ)"
}

// Diff is a module-level comparison of two firmware images.
type Diff struct {
	OnlyA   []string // modules present in the first image only
	OnlyB   []string
	Changed []ModuleChange
	// Compared is how many modules were present in both and compared.
	Compared int
}

// Equivalent reports whether the two images hold the same modules with the same
// contents.
func (d Diff) Equivalent() bool {
	return len(d.OnlyA) == 0 && len(d.OnlyB) == 0 && len(d.Changed) == 0
}

// Compare matches modules by GUID and compares their contents. GUID is the
// identity that survives a rebuild: a module's name comes from an optional UI
// section, and its offset moves whenever anything ahead of it changes size.
func Compare(a, b []Module) Diff {
	ma, mb := byGUID(a), byGUID(b)
	var d Diff
	for _, g := range sortedKeys(ma) {
		x := ma[g]
		y, ok := mb[g]
		if !ok {
			d.OnlyA = append(d.OnlyA, label(x))
			continue
		}
		d.Compared++
		if !bytes.Equal(x.Data, y.Data) {
			name := x.Name
			if name == "" {
				name = y.Name
			}
			d.Changed = append(d.Changed, ModuleChange{
				GUID: g, Name: name,
				SizeA: len(x.Data), SizeB: len(y.Data),
			})
		}
	}
	for _, g := range sortedKeys(mb) {
		if _, ok := ma[g]; !ok {
			d.OnlyB = append(d.OnlyB, label(mb[g]))
		}
	}
	sort.Strings(d.OnlyA)
	sort.Strings(d.OnlyB)
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].String() < d.Changed[j].String() })
	return d
}

// byGUID indexes modules by GUID. A volume can carry the same GUID twice; the
// first wins, matching the order the volume lists them in.
func byGUID(mods []Module) map[string]Module {
	m := make(map[string]Module, len(mods))
	for _, x := range mods {
		if _, seen := m[x.GUID]; !seen {
			m[x.GUID] = x
		}
	}
	return m
}

func label(m Module) string {
	if m.Name == "" {
		return m.GUID
	}
	return m.GUID + " " + m.Name
}

func sortedKeys(m map[string]Module) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
