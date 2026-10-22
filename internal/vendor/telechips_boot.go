package vendor

import (
	"fmt"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/telechips"
)

// Facts of a Telechips boot stage's script, and what it makes of the package's
// verified boot.
var (
	// SourceTelechipsBoot is a boot stage (BL3 with U-Boot) whose default
	// environment has a boot command.
	SourceTelechipsBoot = facts.Key[[]byte]("source:telechips.boot", facts.Fmt(facts.ByteLen))
	// TelechipsBootLoads is the partitions its boot command loads, split by whether
	// that is before its AVB verify step.
	TelechipsBootLoads = facts.Key[string]("telechips_boot_loads")
	// TelechipsUnprotectedLoads is the partitions it loads that the package's vbmeta
	// does not cover: AVB never verifies them, whenever they are loaded.
	TelechipsUnprotectedLoads = facts.Key[string]("telechips_unprotected_loads")
)

// FactRecognizers implements FactRecognizer: a Telechips boot stage with a boot
// script, wherever in a package it sits (a payload partition among them).
func (tcc) FactRecognizers() []facts.Recognizer {
	return []facts.Recognizer{func(b *facts.Bag, f facts.File) []string {
		if !telechips.IsImage(f.Data) {
			return nil
		}
		im, err := telechips.Parse(f.Data)
		if err != nil || im.Env["bootcmd"] == "" {
			return nil
		}
		facts.Set(b, SourceTelechipsBoot, f.Data, facts.Provenance{Source: f.From, Authority: facts.Attested})
		return []string{SourceTelechipsBoot.Name()}
	}}
}

// bootEnv parses the stage the fact holds.
func bootEnv(v facts.Value) (map[string]string, bool) {
	data, _ := v.Data.([]byte)
	im, err := telechips.Parse(data)
	if err != nil {
		return nil, false
	}
	return im.Env, true
}

// FactProviders implements FactDeriver.
func (tcc) FactProviders() []facts.Provider {
	return []facts.Provider{
		facts.Rule{
			Out: TelechipsBootLoads.Name(), In: []string{SourceTelechipsBoot.Name()}, Price: 2, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				for _, v := range b.Values(SourceTelechipsBoot.Name()) {
					env, ok := bootEnv(v)
					if !ok {
						continue
					}
					loads, verifies := telechips.BootLoads(env)
					if len(loads) == 0 {
						continue
					}
					var before, after []string
					for _, l := range loads {
						if l.BeforeAVB {
							before = append(before, l.Partition)
						} else {
							after = append(after, l.Partition)
						}
					}
					var parts []string
					switch {
					case !verifies:
						parts = append(parts, "no AVB verify step: "+strings.Join(after, ", "))
					default:
						if len(before) > 0 {
							parts = append(parts, "before the AVB check: "+strings.Join(before, ", "))
						}
						if len(after) > 0 {
							parts = append(parts, "after it: "+strings.Join(after, ", "))
						}
					}
					facts.Set(b, TelechipsBootLoads, strings.Join(parts, "; "), facts.Provenance{Source: v.Source + " bootcmd", Authority: facts.Attested})
					return true, nil
				}
				return false, nil
			},
		},
		// Which of those loads the vbmeta does not cover. It needs both, so a package
		// holding only one of them says nothing rather than everything.
		facts.Rule{
			Out: TelechipsUnprotectedLoads.Name(), In: []string{SourceTelechipsBoot.Name(), facts.AVBProtected.Name()}, Price: 3, Level: facts.Derived,
			Fn: func(b *facts.Bag) (bool, error) {
				protected, ok := facts.Get(b, facts.AVBProtected)
				if !ok {
					return false, nil
				}
				covered := map[string]bool{}
				for _, p := range strings.Split(protected, ", ") {
					covered[p] = true
				}
				for _, v := range b.Values(SourceTelechipsBoot.Name()) {
					env, ok := bootEnv(v)
					if !ok {
						continue
					}
					loads, _ := telechips.BootLoads(env)
					var out []string
					for _, l := range loads {
						if !covered[l.Partition] {
							out = append(out, fmt.Sprintf("%s (%s)", l.Partition, l.Command))
						}
					}
					if len(out) == 0 {
						continue
					}
					facts.Set(b, TelechipsUnprotectedLoads, strings.Join(out, ", "), facts.Provenance{Source: v.Source + " bootcmd against vbmeta", Authority: facts.Derived})
					return true, nil
				}
				return false, nil
			},
		},
	}
}
