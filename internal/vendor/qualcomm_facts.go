package vendor

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
)

// signedStage is one Qualcomm-signed image inside a package, by stage name.
type signedStage struct {
	Name         string
	AntiRollback int
}

// sourceSignedStage collects every signed image a package carries, one value
// each, for the rules that summarize them as a set.
var sourceSignedStage = facts.Key[signedStage]("source:qcom_signed_stage",
	facts.Fmt(func(s signedStage) string { return fmt.Sprintf("%s ARB=%d", s.Name, s.AntiRollback) }))

// representativeStages are the stages whose signature speaks for the package as
// a whole: the OEM-signed application bootloader (aboot on pre-UEFI parts). A
// package also carries images signed by others (a QTI-signed featenabler has
// Qualcomm's OEM_ID), and offering that crowd would manufacture a conflict; xbl
// is OEM-signed too but embeds QTI's XBL-Sec chain as data.
var representativeStages = map[string]bool{"abl": true, "aboot": true}

// programmerSWTypes are the sw_id types of EDL programmers (3; 26 on OnePlus).
// A programmer ships beside a package's boot chain, not in it, and a loader
// collection is nothing but programmers, so neither is a stage.
var programmerSWTypes = map[uint32]bool{3: true, 26: true}

// isProgrammer recognizes an EDL programmer by its sw_id or, where the vendor
// stamped another, by the protocol it speaks.
func isProgrammer(id *secboot.Identity, data []byte) bool {
	return programmerSWTypes[id.SWType()] || bytes.Contains(bytes.ToLower(data), []byte("firehose"))
}

// stageName is a member or partition name reduced to its stage: no directory,
// extension or slot suffix.
func stageName(name string) string {
	n := strings.ToLower(path.Base(name))
	n = strings.TrimSuffix(n, path.Ext(n))
	for _, s := range []string{"_a", "_b"} {
		n = strings.TrimSuffix(n, s)
	}
	return n
}

// FactRecognizers implements FactRecognizer: a Qualcomm-signed ELF inside a
// package. The neutral recognizers deliberately ignore signed images that are
// not the file under examination; this one knows which stage represents the
// package and records every stage's anti-rollback version.
func (qualcomm) FactRecognizers() []facts.Recognizer {
	return []facts.Recognizer{func(b *facts.Bag, f facts.File) []string {
		if f.Top || filetype.Detect(f.Data) != filetype.ELF {
			return nil
		}
		id, err := secboot.FromELF(f.Data)
		if err != nil {
			return nil
		}
		prov := facts.Provenance{Source: f.From, Authority: facts.Attested}
		stage := stageName(f.Name)
		var out []string
		if !isProgrammer(id, f.Data) {
			facts.Set(b, sourceSignedStage, signedStage{Name: stage, AntiRollback: int(id.AntiRollback())}, prov)
			out = append(out, sourceSignedStage.Name())
		}
		if representativeStages[stage] {
			facts.Set(b, imgfacts.SourceImage, f.Data, prov)
			out = append(out, imgfacts.SourceImage.Name())
		}
		return out
	}}
}

// FactProviders implements FactDeriver.
func (qualcomm) FactProviders() []facts.Provider {
	return []facts.Provider{facts.Rule{
		Out: facts.AntiRollbackTable.Name(), In: []string{sourceSignedStage.Name()}, Price: 1, Level: facts.Attested,
		Fn: func(b *facts.Bag) (bool, error) {
			// Only a boot chain has a rollback table: without its application
			// bootloader, a set of signed images is a collection, not a chain.
			table := map[string]int{}
			chain := false
			for _, s := range facts.GetAll(b, sourceSignedStage) {
				table[s.Name] = s.AntiRollback
				chain = chain || representativeStages[s.Name]
			}
			if !chain {
				return false, nil
			}
			facts.Set(b, facts.AntiRollbackTable, table, facts.Provenance{Source: "signed images' SW_ID", Authority: facts.Attested})
			return true, nil
		},
	}}
}
