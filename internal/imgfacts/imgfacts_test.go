package imgfacts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-unbrick/internal/facts"
	"go-unbrick/internal/rsakey"
)

// signedBlob is a stand-in for a signed boot image: arbitrary bytes with a cert
// embedded in them, which is how the real ones carry their chain.
func signedBlob(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 0, len(der)+512)
	blob = append(blob, []byte("\x7fELF padding before the chain")...)
	blob = append(blob, der...)
	return append(blob, make([]byte, 64)...)
}

func TestBootCertChainFromImage(t *testing.T) {
	b := facts.NewBag()
	facts.Set(b, SourceImage, signedBlob(t, "Test Attestation CA"),
		facts.Provenance{Source: "abl.elf", Authority: facts.Attested})
	facts.New(FactProviders(), nil).ResolveAll(b, facts.Options{})

	ids, ok := facts.Get(b, BootCertChain)
	if !ok || len(ids) == 0 {
		t.Fatalf("boot_cert_chain = %v %v", ids, ok)
	}
	v, _ := b.Best(BootCertChain.Name())
	// The rendering names the CN, not the whole DN: a boot cert's subject carries
	// the entire secboot identity in its OUs and would swamp the line.
	if got := b.Show(BootCertChain.Name(), v.Data); !strings.Contains(got, "Test Attestation CA") || strings.Contains(got, "O=Test") {
		t.Errorf("show = %q", got)
	}
}

// The same chain found again is the same fact, whatever order it comes back in.
func TestCertChainEqualityIsByFingerprint(t *testing.T) {
	blob := signedBlob(t, "Same Key")
	b := facts.NewBag()
	facts.Set(b, SourceImage, blob, facts.Provenance{Source: "one", Authority: facts.Attested})
	g := facts.New(FactProviders(), nil)
	g.ResolveAll(b, facts.Options{})
	ids, _ := facts.Get(b, BootCertChain)

	rev := make([]rsakey.Identity, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		rev = append(rev, ids[i])
	}
	facts.Set(b, BootCertChain, rev, facts.Provenance{Source: "two", Authority: facts.Attested})
	if res := g.ResolveAll(b, facts.Options{}); len(res.Findings) != 0 {
		t.Fatalf("a reordered identical chain is not a disagreement: %+v", res.Findings)
	}
}

func TestRecognizesVBMetaAndTopLevelImageOnly(t *testing.T) {
	dir := t.TempDir()
	vb := filepath.Join(dir, "anything.bin")
	if err := os.WriteFile(vb, []byte("AVB0\x00HAB_META\x00fogona_50\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := facts.NewBag()
	if err := Ingest(b, Recognizers(), vb, nil); err != nil {
		t.Fatal(err)
	}
	if !b.Has(facts.SourceVBMeta.Name()) {
		t.Error("a vbmeta is recognized by its magic, whatever it is called")
	}
	if b.Has(SourceImage.Name()) {
		t.Error("a vbmeta is not source:image")
	}
}
