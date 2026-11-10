package arsc

import "testing"

// Both parsers read whatever carve opens, not only well-formed APKs: they must
// error, never panic.
func addSeeds(f *testing.F) {
	for _, m := range []string{"AndroidManifest.xml", "resources.arsc"} {
		for _, apk := range []string{"plain.apk", "compact.apk"} {
			f.Add(apkMember(f, apk, m))
		}
	}
}

func FuzzParse(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		if tb, err := Parse(b); err == nil {
			tb.Text()
		}
	})
}

func FuzzDecodeXML(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		DecodeXML(b, nil)
	})
}
