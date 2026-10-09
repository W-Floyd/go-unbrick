package imgfacts

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/otameta"
)

const pixelOTAMetadata = `ota-property-files=payload.bin:4437:3755445803
ota-required-cache=0
ota-type=AB
post-build=google/cubs/cubs:17/CD1A.260618.001.A7/15768489:user/release-keys
post-build-incremental=15768489
post-sdk-level=37
post-security-patch-level=2026-06-05
post-timestamp=1782930253
pre-device=cubs
`

const pixelFingerprint = "google/cubs/cubs:17/CD1A.260618.001.A7/15768489:user/release-keys"

// pixelMetadataPB is pixelOTAMetadata as metadata.pb.
func pixelMetadataPB() []byte {
	str := func(b []byte, n protowire.Number, s string) []byte {
		b = protowire.AppendTag(b, n, protowire.BytesType)
		return protowire.AppendString(b, s)
	}
	pre := str(nil, 1, "cubs")
	post := str(nil, 1, "cubs")
	post = str(post, 2, pixelFingerprint)
	post = str(post, 3, "15768489")
	post = str(post, 6, "2026-06-05")
	b := protowire.AppendTag(nil, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 1) // AB
	b = protowire.AppendTag(b, 5, protowire.BytesType)
	b = protowire.AppendBytes(b, pre)
	b = protowire.AppendTag(b, 6, protowire.BytesType)
	return protowire.AppendBytes(b, post)
}

func TestOTAMetadataDerivesIdentity(t *testing.T) {
	for _, f := range []facts.File{
		{Name: "metadata", Data: []byte(pixelOTAMetadata)},
		{Name: "metadata.pb", Data: pixelMetadataPB()},
	} {
		b := facts.NewBag()
		if got := recognizeOTAMetadata(b, f); len(got) != 1 {
			t.Fatalf("%s: recognizer returned %v, want the source fact", f.Name, got)
		}
		facts.New(otaProviders(), nil).ResolveAll(b, facts.Options{})

		for _, tc := range []struct {
			fact facts.Fact[string]
			want string
		}{
			{facts.Codename, "cubs"},
			{facts.BuildFingerprint, pixelFingerprint},
			{facts.SecurityPatch, "2026-06-05"},
		} {
			got, ok := facts.Get(b, tc.fact)
			if !ok || got != tc.want {
				t.Errorf("%s: %s = %q (ok=%v), want %q", f.Name, tc.fact.Name(), got, ok, tc.want)
			}
		}
		if ab, ok := facts.Get(b, facts.ABEnabled); !ok || !ab {
			t.Errorf("%s: ab_enabled = %v (ok=%v), want true", f.Name, ab, ok)
		}
	}
}

func TestCareMapYieldsSystemFingerprint(t *testing.T) {
	str := func(b []byte, n protowire.Number, s string) []byte {
		b = protowire.AppendTag(b, n, protowire.BytesType)
		return protowire.AppendString(b, s)
	}
	part := func(name, prop, fp string) []byte {
		p := str(nil, 1, name)
		p = str(p, 2, "2,0,100")
		p = str(p, 3, prop)
		p = str(p, 4, fp)
		return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), p)
	}
	data := append(part("vendor", "ro.vendor.build.fingerprint", "v/fp"),
		part("system", "ro.system.build.fingerprint", "s/fp")...)

	b := facts.NewBag()
	if got := recognizeOTAMetadata(b, facts.File{Name: "care_map.pb", Data: data}); len(got) != 1 {
		t.Fatalf("recognizer returned %v", got)
	}
	facts.New(otaProviders(), nil).ResolveAll(b, facts.Options{})
	if got, _ := facts.Get(b, facts.SystemFingerprint); got != "s/fp" {
		t.Errorf("system_fingerprint = %q, want s/fp", got)
	}
}

func TestOTAMetadataRejectsNonOTA(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte("just some text without the markers"),
		append([]byte("post-build=x\x00binary"), 0),    // has a NUL
		[]byte("post-security-patch-level=2026-06-05"), // no post-build
	} {
		if otameta.IsTextMetadata(data) {
			t.Errorf("IsTextMetadata(%q) = true, want false", data)
		}
	}
	// A file merely named like a protobuf member is not taken on its name.
	b := facts.NewBag()
	if got := recognizeOTAMetadata(b, facts.File{Name: "metadata.pb", Data: []byte("not a protobuf")}); got != nil {
		t.Errorf("garbage metadata.pb recognized as %v", got)
	}
}
