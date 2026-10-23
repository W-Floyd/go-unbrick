package imgfacts

import (
	"bytes"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/otameta"
	"github.com/W-Floyd/go-unbrick/internal/rsakey"
)

// An AOSP OTA package states its own identity in the clear, in
// META-INF/com/android/metadata: the build fingerprint, the target device and
// the security-patch level. This is vendor-neutral — a Pixel, a Motorola or any
// AOSP OTA carries the same sheet — so it is recognized and derived here rather
// than behind a vendor seam. It is also the only identity a full OTA exposes
// cheaply: everything else is inside payload.bin. Newer packages state it twice,
// as text and as metadata.pb; both are read, so each corroborates the other and
// a package that drops the text form still yields.

var (
	// SourceOTAMetadata is the text sheet, META-INF/com/android/metadata.
	SourceOTAMetadata = facts.Key[[]byte]("source:ota_metadata", facts.Fmt(facts.ByteLen))
	// SourceOTAMetadataPB is the same sheet as an OtaMetadata protobuf.
	SourceOTAMetadataPB = facts.Key[[]byte]("source:ota_metadata.pb", facts.Fmt(facts.ByteLen))
	// SourceCareMap is care_map.pb: each verified partition's build fingerprint.
	SourceCareMap = facts.Key[[]byte]("source:care_map.pb", facts.Fmt(facts.ByteLen))
	// SourceOTACert is the PEM certificate an OTA package names as its signer
	// (META-INF/com/android/otacert). It should match recovery's otacerts.zip,
	// which is what makes the two a cross-check.
	SourceOTACert = facts.Key[[]byte]("source:otacert", facts.Fmt(facts.ByteLen))
)

// recognizeOTAMetadata claims the text sheet by content — the key=value lines an
// update package carries — not by its path, so a copy under any name is still
// recognized. The protobufs have no magic, so they go by AOSP's fixed names and
// are confirmed by parsing.
func recognizeOTAMetadata(b *facts.Bag, f facts.File) []string {
	var src facts.Fact[[]byte]
	var ok bool
	switch {
	case otameta.IsTextMetadata(f.Data):
		src, ok = SourceOTAMetadata, true
	case f.Name == "metadata.pb":
		_, err := otameta.ParseMetadata(f.Data)
		src, ok = SourceOTAMetadataPB, err == nil
	case f.Name == "care_map.pb":
		_, err := otameta.ParseCareMap(f.Data)
		src, ok = SourceCareMap, err == nil
	case bytes.HasPrefix(bytes.TrimSpace(f.Data), []byte("-----BEGIN CERTIFICATE-----")) && len(f.Data) <= 1<<16:
		src, ok = SourceOTACert, len(otameta.Certs(f.Data)) > 0
	}
	if !ok {
		return nil
	}
	facts.Set(b, src, f.Data, facts.Provenance{Source: f.From, Authority: facts.Attested})
	return []string{src.Name()}
}

// pbSheet renders metadata.pb under the text sheet's keys, so one set of rules
// reads both.
func pbSheet(data []byte) map[string]string {
	m, err := otameta.ParseMetadata(data)
	if err != nil {
		return nil
	}
	out := map[string]string{
		"ota-type":                  m.Type,
		"post-security-patch-level": m.Post.SecurityPatch,
	}
	if len(m.Pre.Devices) > 0 {
		out["pre-device"] = m.Pre.Devices[0]
	}
	if len(m.Post.Builds) > 0 {
		out["post-build"] = m.Post.Builds[0]
	}
	return out
}

// otaProviders derives the neutral build-identity facts from the sheets. Build
// date is left to build.prop (via payload.bin), whose ro.build.date is the
// authoritative string; the sheet's post-timestamp is a different representation
// and would only read as a disagreement.
func otaProviders() []facts.Provider {
	var ps []facts.Provider
	for _, s := range []struct {
		src   facts.Fact[[]byte]
		label string
		parse func([]byte) map[string]string
	}{
		{SourceOTAMetadata, "OTA metadata", otameta.ParseTextMetadata},
		{SourceOTAMetadataPB, "OTA metadata.pb", pbSheet},
	} {
		field := func(out facts.Fact[string], key string) facts.Rule {
			return sheetRule(s.src, out, s.label+" "+key, func(data []byte) (string, bool) {
				v := s.parse(data)[key]
				return v, v != ""
			})
		}
		ps = append(ps,
			field(facts.Codename, "pre-device"),
			field(facts.BuildFingerprint, "post-build"),
			field(facts.SecurityPatch, "post-security-patch-level"),
			// ota-type is AB for a payload.bin update and BLOCK for the legacy
			// block-based one, which only a non-A/B device can take.
			sheetRule(s.src, facts.ABEnabled, s.label+" ota-type", func(data []byte) (bool, bool) {
				switch s.parse(data)["ota-type"] {
				case "AB":
					return true, true
				case "BLOCK":
					return false, true
				}
				return false, false
			}),
		)
	}
	return append(ps,
		sheetRule(SourceCareMap, facts.SystemFingerprint, "care_map.pb ro.system.build.fingerprint", func(data []byte) (string, bool) {
			parts, _ := otameta.ParseCareMap(data)
			for _, p := range parts {
				if p.IDProp == "ro.system.build.fingerprint" && p.Fingerprint != "" {
					return p.Fingerprint, true
				}
			}
			return "", false
		}),
		sheetRule(SourceOTACert, OTACerts, "META-INF otacert", func(data []byte) ([]rsakey.Identity, bool) {
			var der []byte
			for _, c := range otameta.Certs(data) {
				der = append(der, c.Raw...)
			}
			ids := rsakey.Scan(der).Identities()
			return ids, len(ids) > 0
		}),
	)
}

// sheetRule derives one fact from one source document.
func sheetRule[T any](src facts.Fact[[]byte], out facts.Fact[T], source string, fn func([]byte) (T, bool)) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{src.Name()}, Price: 1, Level: facts.Attested, Ver: 1,
		Fn: func(b *facts.Bag) (bool, error) {
			data, ok := facts.Get(b, src)
			if !ok {
				return false, nil
			}
			v, ok := fn(data)
			if !ok {
				return false, nil
			}
			facts.Set(b, out, v, facts.Provenance{Source: source, Authority: facts.Attested})
			return true, nil
		},
	}
}
