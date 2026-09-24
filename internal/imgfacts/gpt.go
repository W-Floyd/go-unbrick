package imgfacts

import (
	"fmt"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/facts"
	"go-unbrick/internal/filetype"
	"go-unbrick/internal/qfil"
	"go-unbrick/internal/transport"
)

// SourceGPT is the partition names a package's own partition table declares —
// a raw GPT, or the gpt_main*.bin LUN tables inside a Motorola gpt.bin.
var SourceGPT = facts.Key[[]string]("source:gpt", facts.Fmt(func(n []string) string {
	return fmt.Sprintf("(%d partitions)", len(n))
}))

// gptNames returns the partition names of a GPT, or of every GPT inside a
// SINGLE_N_LONELY container; nil if the bytes hold neither.
func gptNames(data []byte) []string {
	var tables [][]byte
	switch filetype.Detect(data) {
	case filetype.GPT:
		tables = [][]byte{data}
	case filetype.SingleNLonely:
		recs, err := blankflash.Parse(data)
		if err != nil {
			return nil
		}
		for _, r := range recs {
			if filetype.Detect(r.Data) == filetype.GPT {
				tables = append(tables, r.Data)
			}
		}
	}
	var names []string
	for _, t := range tables {
		g, err := qfil.ParseGPT(t)
		if err != nil {
			continue
		}
		for _, p := range g.Partitions {
			names = append(names, p.Name)
		}
	}
	return names
}

func recognizeGPT(b *facts.Bag, f facts.File) []string {
	names := gptNames(f.Data)
	if len(names) == 0 {
		return nil
	}
	facts.Set(b, SourceGPT, names, facts.Provenance{Source: f.From, Authority: facts.Attested})
	return []string{SourceGPT.Name()}
}

// abFromGPT is A/B as the partition table lays it out. A package's own
// metadata can say otherwise (Motorola's info.txt reports "AB Update Enabled:
// False" beside a GPT with _a/_b slots), and this is what the graph checks it
// against.
var abFromGPT = facts.Rule{
	Out: facts.ABEnabled.Name(), In: []string{SourceGPT.Name()}, Price: 1, Level: facts.Attested,
	Fn: func(b *facts.Bag) (bool, error) {
		names, ok := facts.Get(b, SourceGPT)
		if !ok || len(names) == 0 {
			return false, nil
		}
		parts := make([]transport.Partition, len(names))
		for i, n := range names {
			parts[i] = transport.Partition{Name: n}
		}
		facts.Set(b, facts.ABEnabled, transport.ABTable(parts),
			facts.Provenance{Source: "package GPT slot layout", Authority: facts.Attested})
		return true, nil
	},
}
