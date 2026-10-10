package vendor

import (
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	mtk "github.com/W-Floyd/go-unbrick/internal/mediatek"
)

// SourceScatter is a MediaTek package's scatter file.
var SourceScatter = facts.Key[[]byte]("source:mediatek.scatter", facts.Fmt(facts.ByteLen))

// FactRecognizers implements FactRecognizer.
func (mediatek) FactRecognizers() []facts.Recognizer {
	return []facts.Recognizer{func(b *facts.Bag, f facts.File) []string {
		l := strings.ToLower(f.Name)
		if !strings.Contains(l, "scatter") || !strings.HasSuffix(l, ".txt") {
			return nil
		}
		if _, err := mtk.ParseScatter(f.Data, f.Name); err != nil {
			return nil
		}
		facts.Set(b, SourceScatter, f.Data, facts.Provenance{Source: f.From, Authority: facts.Attested})
		return []string{SourceScatter.Name()}
	}}
}

// FactProviders implements FactDeriver: the SoC the scatter names, in the
// catalog's spelling when it has one, else as the scatter states it.
func (mediatek) FactProviders() []facts.Provider {
	return []facts.Provider{facts.Rule{
		Out: facts.SoC.Name(), In: []string{SourceScatter.Name(), facts.SourceCatalog.Name()}, Price: 2, Level: facts.Attested,
		Fn: func(b *facts.Bag) (bool, error) {
			for _, v := range b.Values(SourceScatter.Name()) {
				data, _ := v.Data.([]byte)
				info, err := mtk.ParseScatter(data, v.Source)
				if err != nil || info.Chip == "" {
					continue
				}
				chip := strings.ToUpper(info.Chip)
				soc := "MediaTek " + chip
				if cat, ok := facts.Get(b, facts.SourceCatalog); ok {
					if s := cat.ResolveVariant(strings.ToLower(chip), ""); s != "" {
						soc = s
					}
				}
				facts.Set(b, facts.SoC, soc, facts.Provenance{Source: "scatter platform", Authority: facts.Attested})
				return true, nil
			}
			return false, nil
		},
	}}
}
