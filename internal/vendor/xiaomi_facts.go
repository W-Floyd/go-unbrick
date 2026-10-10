package vendor

import (
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// SourceMiscTxt is a Xiaomi fastboot package's misc.txt: key=value lines
// naming the device and the build the package is.
var SourceMiscTxt = facts.Key[[]byte]("source:xiaomi.misc.txt", facts.Fmt(facts.ByteLen))

func parseMiscTxt(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			out[k] = v
		}
	}
	return out
}

// FactRecognizers implements FactRecognizer.
func (xiaomi) FactRecognizers() []facts.Recognizer {
	return []facts.Recognizer{func(b *facts.Bag, f facts.File) []string {
		if !isText(f.Data) {
			return nil
		}
		if m := parseMiscTxt(f.Data); m["device"] == "" || m["build_number"] == "" {
			return nil
		}
		facts.Set(b, SourceMiscTxt, f.Data, facts.Provenance{Source: f.From, Authority: facts.Attested})
		return []string{SourceMiscTxt.Name()}
	}}
}

// FactProviders implements FactDeriver. The build number is Xiaomi's name for
// a release ("OS2.0.209.0.VMTMIXM"); a fastboot package states it in misc.txt
// and an OTA as its fingerprint's incremental, which is what lets the two
// packages of one release be recognized as such.
func (xiaomi) FactProviders() []facts.Provider {
	misc := func(out facts.Fact[string], key string) facts.Rule {
		return parse(out, SourceMiscTxt, facts.Attested, "misc.txt "+key,
			func(_ *facts.Bag, data []byte) (string, bool) {
				v := parseMiscTxt(data)[key]
				return v, v != ""
			})
	}
	return []facts.Provider{
		misc(facts.Codename, "device"),
		misc(facts.SoftwareVersion, "build_number"),
		facts.Rule{
			Out: facts.SoftwareVersion.Name(), In: []string{facts.BuildFingerprint.Name()}, Price: 1, Level: facts.Derived,
			Fn: func(b *facts.Bag) (bool, error) {
				fp, _ := facts.Get(b, facts.BuildFingerprint)
				if v, ok := xiaomiIncremental(fp); ok {
					facts.Set(b, facts.SoftwareVersion, v, facts.Provenance{Source: "fingerprint incremental", Authority: facts.Derived})
					return true, nil
				}
				return false, nil
			},
		},
	}
}

// xiaomiIncremental returns the incremental of a Xiaomi-brand fingerprint
// (brand/product/device:release/id/incremental:type/tags).
func xiaomiIncremental(fp string) (string, bool) {
	parts := strings.Split(fp, "/")
	if len(parts) != 6 {
		return "", false
	}
	switch strings.ToLower(parts[0]) {
	case "xiaomi", "redmi", "poco":
	default:
		return "", false
	}
	inc, _, _ := strings.Cut(parts[4], ":")
	return inc, inc != ""
}
