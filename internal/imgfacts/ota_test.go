package imgfacts

import (
	"testing"

	"go-unbrick/internal/facts"
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

func TestOTAMetadataDerivesIdentity(t *testing.T) {
	data := []byte(pixelOTAMetadata)
	if !isOTAMetadata(data) {
		t.Fatal("Pixel OTA metadata not recognized")
	}

	b := facts.NewBag()
	if got := recognizeOTAMetadata(b, facts.File{Name: "META-INF/com/android/metadata", Data: data}); len(got) != 1 {
		t.Fatalf("recognizer returned %v, want the source fact", got)
	}
	facts.New(otaProviders(), nil).ResolveAll(b, facts.Options{})

	for _, tc := range []struct {
		fact facts.Fact[string]
		want string
	}{
		{facts.Codename, "cubs"},
		{facts.BuildFingerprint, "google/cubs/cubs:17/CD1A.260618.001.A7/15768489:user/release-keys"},
		{facts.SecurityPatch, "2026-06-05"},
	} {
		got, ok := facts.Get(b, tc.fact)
		if !ok || got != tc.want {
			t.Errorf("%s = %q (ok=%v), want %q", tc.fact.Name(), got, ok, tc.want)
		}
	}
}

func TestOTAMetadataRejectsNonOTA(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte("just some text without the markers"),
		append([]byte("post-build=x\x00binary"), 0),    // has a NUL
		[]byte("post-security-patch-level=2026-06-05"), // no post-build
	} {
		if isOTAMetadata(data) {
			t.Errorf("isOTAMetadata(%q) = true, want false", data)
		}
	}
}
