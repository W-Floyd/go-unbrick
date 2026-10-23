package vendor

import (
	"regexp"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
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

// mi_ext is Xiaomi's own extension partition; its build.prop names the
// release.
func init() {
	imgfacts.ReadPartitionFiles("mi_ext", "etc/build.prop")
	// HyperOS builds one system target, "missi", for every device: its boot
	// ramdisk props say Xiaomi/missi/missi, not the device (madrid, tapas).
	for _, brand := range []string{"xiaomi", "redmi", "poco"} {
		imgfacts.StaleRamdiskProps(brand)
	}
}

// xiaomiSKUProp is Xiaomi's name for odm's per-SKU props (m7g_build.prop,
// m7g_ss_build.prop), where AOSP's is build_<sku>.prop.
var xiaomiSKUProp = regexp.MustCompile(`^odm/etc/([a-z0-9_]+)_build\.prop$`)

// FactRecognizers implements FactRecognizer.
func (xiaomi) FactRecognizers() []facts.Recognizer {
	return []facts.Recognizer{recognizeXiaomiSKUProps, func(b *facts.Bag, f facts.File) []string {
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

func recognizeXiaomiSKUProps(b *facts.Bag, f facts.File) []string {
	m := xiaomiSKUProp.FindStringSubmatch(f.Name)
	if m == nil {
		return nil
	}
	props := imgfacts.ParseProps(f.Data)
	if len(props) == 0 {
		return nil
	}
	facts.Set(b, imgfacts.SourcePartProps,
		imgfacts.PartProps{Partition: "odm", File: strings.TrimPrefix(f.Name, "odm/"), SKU: m[1], Props: props},
		facts.Provenance{Source: f.From, Authority: facts.Attested})
	return []string{imgfacts.SourcePartProps.Name()}
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
		// mi_ext overrides the build's incremental with the release's build
		// number, where system's is an internal stamp on a China build.
		facts.Rule{
			Out: facts.SoftwareVersion.Name(), In: []string{imgfacts.SourcePartProps.Name()}, Price: 1, Level: facts.Attested, Ver: 1,
			Fn: func(b *facts.Bag) (bool, error) {
				for _, p := range facts.GetAll(b, imgfacts.SourcePartProps) {
					if v := p.Props["ro.build.version.incremental"]; p.Partition == "mi_ext" && xiaomiBuildNumber.MatchString(v) {
						facts.Set(b, facts.SoftwareVersion, v, facts.Provenance{Source: "mi_ext build.prop", Authority: facts.Attested})
						return true, nil
					}
				}
				return false, nil
			},
		},
		facts.Rule{
			Out: facts.SoftwareVersion.Name(), In: []string{facts.BuildFingerprint.Name()}, Price: 1, Level: facts.Derived, Ver: 1,
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
	return inc, xiaomiBuildNumber.MatchString(inc)
}

// xiaomiBuildNumber is the shape of a release's build number (OS2.0.209.0.VMTMIXM,
// V14.0.3.0.TMGMIXM). Not every build's incremental is one: a China build's
// is an internal stamp (17OS4.0.261004.103610129.QCPECN.S).
var xiaomiBuildNumber = regexp.MustCompile(`^(OS|V)\d+(\.\d+){3}\.[A-Z]+$`)
