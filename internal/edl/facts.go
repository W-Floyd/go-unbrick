package edl

import (
	"go-unbrick/internal/facts"
)

// FactProviders returns the derivations over an EDL session. The chip identity
// is read from fuses by the PBL, so it is Attested: nothing flashed can alter
// it. The slot comes from GPT attributes, which any write can change.
func FactProviders() []facts.Provider {
	return []facts.Provider{
		fromChip(facts.JTAGID, "Sahara MSM_ID", (*ChipInfo).JTAGID),
		fromChip(facts.OEMID, "Sahara OEM_ID", (*ChipInfo).OEMID),
		fromChip(facts.RootKeyHash, "Sahara OEM_PK_HASH", func(c *ChipInfo) string { return c.PKHash }),
		facts.Rule{
			Out: facts.SoC.Name(), In: []string{SourceEDL.Name(), facts.SourceCatalog.Name()},
			Price: 1, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				s, ok := facts.Get(b, SourceEDL)
				cat, ok2 := facts.Get(b, facts.SourceCatalog)
				if !ok || !ok2 || s.Chip == nil || cat == nil {
					return false, nil
				}
				jtag := s.Chip.JTAGID()
				soc, found := cat.SoCByJTAG(jtag)
				if !found || soc == "" {
					return false, nil
				}
				facts.Set(b, facts.SoC, soc, facts.Provenance{
					Source: "catalog Sahara MSM_ID " + jtag, Authority: facts.Attested})
				return true, nil
			},
		},
		facts.Rule{
			Out: facts.Slot.Name(), In: []string{SourceEDL.Name()}, Price: 1, Level: facts.Derived,
			Fn: func(b *facts.Bag) (bool, error) {
				s, ok := facts.Get(b, SourceEDL)
				if !ok || s.Slot == "" {
					return false, nil
				}
				facts.Set(b, facts.Slot, s.Slot, facts.Provenance{
					Source: "edl getactiveslot (GPT A/B attributes)", Authority: facts.Derived})
				return true, nil
			},
		},
	}
}

func fromChip(out facts.Fact[string], source string, pick func(*ChipInfo) string) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{SourceEDL.Name()}, Price: 1, Level: facts.Attested,
		Fn: func(b *facts.Bag) (bool, error) {
			s, ok := facts.Get(b, SourceEDL)
			if !ok || s.Chip == nil {
				return false, nil
			}
			v := pick(s.Chip)
			if v == "" {
				return false, nil
			}
			facts.Set(b, out, v, facts.Provenance{Source: source, Authority: facts.Attested})
			return true, nil
		},
	}
}
