package imgfacts

import (
	"bytes"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// An AOSP OTA package states its own identity in the clear, in
// META-INF/com/android/metadata: the build fingerprint, the target device and
// the security-patch level. This is vendor-neutral — a Pixel, a Motorola or any
// AOSP OTA carries the same sheet — so it is recognized and derived here rather
// than behind a vendor seam. It is also the only identity a full OTA exposes
// cheaply: everything else is inside payload.bin.

// SourceOTAMetadata is an OTA package's META-INF/com/android/metadata sheet.
var SourceOTAMetadata = facts.Key[[]byte]("source:ota_metadata", facts.Fmt(facts.ByteLen))

// recognizeOTAMetadata claims the metadata sheet by content — the key=value
// lines an update package carries — not by its path, so a copy under any name is
// still recognized.
func recognizeOTAMetadata(b *facts.Bag, f facts.File) []string {
	if !isOTAMetadata(f.Data) {
		return nil
	}
	facts.Set(b, SourceOTAMetadata, f.Data, facts.Provenance{Source: f.From, Authority: facts.Attested})
	return []string{SourceOTAMetadata.Name()}
}

// isOTAMetadata reports whether the bytes are an OTA metadata sheet: small, text,
// carrying the post-build fingerprint and a device/type marker.
func isOTAMetadata(data []byte) bool {
	if len(data) == 0 || len(data) > 1<<16 || bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	s := string(data)
	return strings.Contains(s, "post-build=") &&
		(strings.Contains(s, "pre-device=") || strings.Contains(s, "ota-type="))
}

// parseOTAMetadata splits the sheet into its key=value pairs.
func parseOTAMetadata(data []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && v != "" {
			m[k] = v
		}
	}
	return m
}

// otaProviders derives the neutral build-identity facts from the sheet. Build
// date is left to build.prop (via payload.bin), whose ro.build.date is the
// authoritative string; the sheet's post-timestamp is a different representation
// and would only read as a disagreement.
func otaProviders() []facts.Provider {
	return []facts.Provider{
		otaRule(facts.Codename, "pre-device", func(m map[string]string) string { return m["pre-device"] }),
		otaRule(facts.BuildFingerprint, "post-build", func(m map[string]string) string { return m["post-build"] }),
		otaRule(facts.SecurityPatch, "post-security-patch-level", func(m map[string]string) string { return m["post-security-patch-level"] }),
	}
}

// otaRule reads one field out of the OTA metadata sheet.
func otaRule(out facts.Fact[string], field string, fn func(map[string]string) string) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{SourceOTAMetadata.Name()}, Price: 1, Level: facts.Attested,
		Fn: func(b *facts.Bag) (bool, error) {
			data, ok := facts.Get(b, SourceOTAMetadata)
			if !ok {
				return false, nil
			}
			v := fn(parseOTAMetadata(data))
			if v == "" {
				return false, nil
			}
			facts.Set(b, out, v, facts.Provenance{Source: "OTA metadata " + field, Authority: facts.Attested})
			return true, nil
		},
	}
}
