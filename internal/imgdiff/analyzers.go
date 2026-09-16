package imgdiff

import (
	"go-unbrick/internal/devcfg"
	"go-unbrick/internal/efi"
)

// devCfgAnalyzer compares a Qualcomm DAL device-configuration payload property
// by property. The stored layout shifts between builds -- device offsets move
// and re-sort the table -- so a byte diff of two identical configurations runs
// to tens of thousands of bytes.
type devCfgAnalyzer struct{}

func (devCfgAnalyzer) Kind() string { return "device config" }

func (devCfgAnalyzer) Detect(c Chunk) bool { return devcfg.Is(c.Data, c.Paddr) }

func (devCfgAnalyzer) Compare(a, b Chunk) (Report, bool) {
	ca, ok := devcfg.Parse(a.Data, a.Paddr)
	if !ok {
		return Report{}, false
	}
	cb, ok := devcfg.Parse(b.Data, b.Paddr)
	if !ok {
		return Report{}, false
	}
	d := devcfg.Compare(ca, cb)
	r := Report{
		Kind:       "device config",
		Unit:       "value",
		Equivalent: d.Equivalent(),
		Compared:   d.ComparedValues,
		Differing:  len(d.Values),
	}
	for _, v := range d.Values {
		r.Detail = append(r.Detail, v.String())
	}
	for _, n := range d.NamesOnlyA {
		r.Detail = append(r.Detail, "only in first:  "+n)
	}
	for _, n := range d.NamesOnlyB {
		r.Detail = append(r.Detail, "only in second: "+n)
	}
	return r, true
}

// efiAnalyzer compares the UEFI modules inside a firmware volume. abl and xbl
// carry their volume compressed, so without this their payload reads as one
// large opaque run.
//
// Read the counts with care. Across every pair tried -- two fogona builds a
// year apart, and devon against hawao and rhode -- 87 to 88 of 94 modules
// differ, and the handful that match are the data modules (QcomChargerCfg.cfg,
// a panel .xml, BATTERY.PROVISION) rather than PE32 code. A rebuild appears to
// touch essentially every code module, so "differs" is close to a constant and
// carries little signal on its own. What the comparison does give reliably is
// the inventory: which modules each image has, named, and how their sizes
// moved.
type efiAnalyzer struct{}

func (efiAnalyzer) Kind() string { return "UEFI" }

func (efiAnalyzer) Detect(c Chunk) bool { return len(efi.Volumes(c.Data)) > 0 }

func (efiAnalyzer) Compare(a, b Chunk) (Report, bool) {
	ma, err := efi.Extract(a.Data)
	if err != nil {
		return Report{}, false
	}
	mb, err := efi.Extract(b.Data)
	if err != nil {
		return Report{}, false
	}
	// A volume we cannot walk should leave the byte-level findings standing
	// rather than claim an empty comparison.
	if len(ma) == 0 && len(mb) == 0 {
		return Report{}, false
	}
	d := efi.Compare(ma, mb)
	r := Report{
		Kind:       "UEFI",
		Unit:       "module",
		Equivalent: d.Equivalent(),
		Compared:   d.Compared,
		Differing:  len(d.Changed),
	}
	for _, m := range d.Changed {
		r.Detail = append(r.Detail, m.String())
	}
	for _, n := range d.OnlyA {
		r.Detail = append(r.Detail, "only in first:  "+n)
	}
	for _, n := range d.OnlyB {
		r.Detail = append(r.Detail, "only in second: "+n)
	}
	return r, true
}
