package devcfg

import (
	"bytes"
	"fmt"
	"sort"
)

// ValueChange is one property whose value or type differs between two configs.
type ValueChange struct {
	Device string
	Name   string
	A, B   uint32
	TypeA  PropType
	TypeB  PropType
}

func (v ValueChange) String() string {
	if v.TypeA != v.TypeB {
		return fmt.Sprintf("%s:%s %s=%d -> %s=%d", v.Device, v.Name, v.TypeA, v.A, v.TypeB, v.B)
	}
	return fmt.Sprintf("%s:%s %d -> %d", v.Device, v.Name, v.A, v.B)
}

// Diff compares two configurations by meaning: which devices and properties are
// present, and what their values are. Layout -- the offsets that re-sort the
// device table between builds -- is deliberately ignored.
type Diff struct {
	// NamesOnlyA and NamesOnlyB list devices, and device:property pairs, found
	// in only one of the two.
	NamesOnlyA []string
	NamesOnlyB []string
	Values     []ValueChange
	// ComparedValues is how many properties were present in both and compared,
	// so a caller can say how much of the blob the verdict covers.
	ComparedValues int
	// Reordered is true when the same devices appear at different offsets,
	// which is layout churn rather than a change in configuration.
	Reordered bool
}

// Equivalent reports whether nothing decodable distinguishes the two configs.
func (d Diff) Equivalent() bool {
	return len(d.NamesOnlyA) == 0 && len(d.NamesOnlyB) == 0 && len(d.Values) == 0
}

// Compare diffs two decoded configurations.
func Compare(a, b *Config) Diff {
	var d Diff
	da, db := index(a), index(b)

	for _, name := range sortedKeys(da) {
		bd, ok := db[name]
		if !ok {
			d.NamesOnlyA = append(d.NamesOnlyA, name)
			continue
		}
		ad := da[name]
		pa, pb := props(ad), props(bd)
		for _, pn := range sortedKeys(pa) {
			x := pa[pn]
			y, ok := pb[pn]
			if !ok {
				d.NamesOnlyA = append(d.NamesOnlyA, name+":"+pn)
				continue
			}
			if !meaningful(x, y) {
				continue
			}
			d.ComparedValues++
			if differs(a, b, x, y) {
				d.Values = append(d.Values, ValueChange{
					Device: name, Name: pn,
					A: x.Value, B: y.Value, TypeA: x.Type, TypeB: y.Type,
				})
			}
		}
		for _, pn := range sortedKeys(pb) {
			if _, ok := pa[pn]; !ok {
				d.NamesOnlyB = append(d.NamesOnlyB, name+":"+pn)
			}
		}
	}
	for _, name := range sortedKeys(db) {
		if _, ok := da[name]; !ok {
			d.NamesOnlyB = append(d.NamesOnlyB, name)
		}
	}

	// Device order in the stored table is offset-driven; if the two agree on
	// content but not on that order, the difference is layout only.
	d.Reordered = !equalOrder(a, b)

	sort.Strings(d.NamesOnlyA)
	sort.Strings(d.NamesOnlyB)
	sort.Slice(d.Values, func(i, j int) bool { return d.Values[i].String() < d.Values[j].String() })
	return d
}

// meaningful reports whether two properties can be compared at all. An
// unresolved pointer value addresses something this package cannot follow, so
// comparing the raw numbers would manufacture differences out of layout.
func meaningful(x, y Property) bool {
	if x.Type != y.Type {
		return true // a type change is a real difference
	}
	if x.Type.Pointer() {
		return x.Resolved && y.Resolved
	}
	return true
}

// differs compares two properties by content. For pointer types the stored
// value is an index into the struct table, and that index moves when the table
// is laid out differently, so the referenced bytes are what count.
func differs(a, b *Config, x, y Property) bool {
	if x.Type != y.Type {
		return true
	}
	if !x.Type.Pointer() {
		return x.Value != y.Value
	}
	return !bytes.Equal(structAt(a, x.Value), structAt(b, y.Value))
}

func structAt(c *Config, i uint32) []byte {
	if int(i) >= len(c.Structs) {
		return nil
	}
	return c.Structs[i]
}

func index(c *Config) map[string]Device {
	m := make(map[string]Device, len(c.Devices))
	for _, d := range c.Devices {
		m[d.Name] = d
	}
	return m
}

// props keys a device's properties by name. A device may repeat a name across
// entries; the first wins, matching the order the store lists them in.
func props(d Device) map[string]Property {
	m := make(map[string]Property, len(d.Props))
	for _, p := range d.Props {
		if _, seen := m[p.Name]; !seen {
			m[p.Name] = p
		}
	}
	return m
}

func equalOrder(a, b *Config) bool {
	if len(a.Devices) != len(b.Devices) {
		return false
	}
	for i := range a.Devices {
		if a.Devices[i].Name != b.Devices[i].Name {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
