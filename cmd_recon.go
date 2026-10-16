package main

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/adb"
	"github.com/W-Floyd/go-unbrick/internal/avb"
	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/bootelf"
	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/devcfg"
	"github.com/W-Floyd/go-unbrick/internal/dtbo"
	"github.com/W-Floyd/go-unbrick/internal/edl"
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/fastboot"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/lenovo"
	"github.com/W-Floyd/go-unbrick/internal/linuxdev"
	"github.com/W-Floyd/go-unbrick/internal/lp"
	"github.com/W-Floyd/go-unbrick/internal/mcfg"
	"github.com/W-Floyd/go-unbrick/internal/modem"
	"github.com/W-Floyd/go-unbrick/internal/otameta"
	"github.com/W-Floyd/go-unbrick/internal/payload"
	"github.com/W-Floyd/go-unbrick/internal/qfil"
	"github.com/W-Floyd/go-unbrick/internal/rsakey"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
	"github.com/W-Floyd/go-unbrick/internal/sparse"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// newReconCmd is the file counterpart to `fastboot recon`: hand it any file and
// it identifies the format and surfaces what it can. Neutral format detection is
// generic (internal/filetype); vendor meaning (which OEM, CID, subsidy) is
// resolved through the vendor seam and vendor parsers.
func newReconCmd() *cobra.Command {
	var depth int
	var carve, why, with, secrets string
	var verify, learn bool
	c := &cobra.Command{
		Use:   "recon <file | http(s) url>",
		Short: "identify any file (stock zip, image, container, config) and report what it is",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reconDepth = depth
			reconCarveDir = carve
			reconWhy = why
			reconVerify = verify
			reconLearn = learn
			reconWith = with
			if secrets != "" {
				if err := loadSecrets(secrets); err != nil {
					return fmt.Errorf("--secrets: %w", err)
				}
				fmt.Fprintf(os.Stderr, "note: %d key/IV pair(s) from %s\n", len(reconSecrets), secrets)
			}
			return runFileRecon(args[0])
		},
	}
	c.Flags().StringVar(&secrets, "secrets", "", "directory of hex key (*key*) and IV (*iv*) files tried on encrypted members")
	c.Flags().IntVar(&depth, "depth", 4, "how many container levels to cascade into (zip → radio → NON-HLOS → ext4)")
	c.Flags().StringVar(&carve, "carve", "", "write every unique embedded cert (PEM+DER) and key (PEM) to this directory")
	c.Flags().StringVar(&why, "why", "", "explain how one fact was derived (e.g. --why cid), with every corroborating source")
	c.Flags().BoolVar(&verify, "verify", false, "run redundant derivations for their cross-check value, even the expensive ones")
	c.Flags().BoolVar(&learn, "learn", false, "contribute this image's raw, non-identifying facts to the library knowledge store")
	c.Flags().StringVar(&with, "with", "", "another package of the same release (file or URL), read for what this one cannot reach; found automatically when a vendor can name it, \"none\" to skip")
	return addFullDownload(c)
}

// reconDepth bounds how deep the cascade recurses into nested containers.
var reconDepth = 4

// reconCarveDir, when set, is where extracted certs/keys are written (--carve).
var reconCarveDir string

// reconWhy names the fact whose derivation to explain (--why); reconVerify opts
// into running redundant derivations for cross-checking (--verify).
var (
	reconWhy    string
	reconVerify bool
	// reconLearn opts a file recon into contributing its raw facts to the
	// knowledge store — off by default, since an image's facts describe the
	// artifact, not a unit in hand; on, they corroborate what devices report.
	reconLearn bool
	// reconWith is a companion package of the same release (--with).
	reconWith string
)

// reconGraph is every derivation available to a recon: the neutral device and
// image providers, the booted-Linux ones, plus whatever the registered vendors
// contribute. Every recon builds it, which is what lets a fact from a package, a
// fact from the bootloader and a fact from a running install meet in one Bag.
func reconGraph() *facts.Graph {
	ps := append(fastboot.FactProviders(), imgfacts.FactProviders()...)
	ps = append(ps, linuxdev.FactProviders()...)
	ps = append(ps, adb.FactProviders()...)
	ps = append(ps, edl.FactProviders()...)
	return facts.New(append(ps, vendor.Providers()...), append(imgfacts.Checks(), vendor.Checks()...))
}

// reconRecognizers is what any recon hands its bytes to: the neutral formats
// plus each vendor's own. Shared so a partition read off a live device is
// recognized by the very rules a packaged image is.
func reconRecognizers() []facts.Recognizer {
	return append(imgfacts.Recognizers(), vendor.Recognizers()...)
}

// reconIngest resolves everything a file can say about itself. What it contains
// is discovered, not assumed: every member is offered to the recognizers, which
// decide what each one is from its content, and only then does the planner run.
//
// A companion (--with) is another package of the same release, read for what
// the first cannot reach. Its members join the same Bag only once both
// packages, resolved on their own, name the same device and build. One the
// user did not name (optional) that fails this is left out with a note
// instead of failing the recon; used is the companion read, if any.
func reconIngest(path, with string, optional bool) (bag *facts.Bag, findings []facts.Finding, used string, err error) {
	bag, findings, err = ingestWith(path, with)
	if err == nil {
		return bag, findings, with, nil
	}
	if !optional || with == "" {
		return nil, nil, "", err
	}
	skipped := err
	bag, findings, err = ingestWith(path, "")
	findings = append(findings, facts.Finding{Severity: facts.Info, Message: fmt.Sprintf("not reading %s: %v", infile.Base(with), skipped)})
	return bag, findings, "", err
}

// autoCompanion picks a companion the user did not name: one a vendor can
// name whole, from the package's own name or among the locations known here
// (the HTTP cache; for a local package, the files beside it).
func autoCompanion(path string) (with, how string) {
	known := infile.Known()
	if !infile.IsRemote(path) {
		dir := filepath.Dir(path)
		if es, err := os.ReadDir(dir); err == nil {
			for _, e := range es {
				known = append(known, filepath.Join(dir, e.Name()))
			}
		}
	}
	for _, c := range vendor.Companions(path, known) {
		switch {
		case c.URL == "" || c.URL == path:
		case !c.Found:
			return c.URL, "derived from its name"
		case infile.IsRemote(c.URL):
			return c.URL, "seen in the HTTP cache"
		default:
			return c.URL, "found beside it"
		}
	}
	return "", ""
}

func ingestWith(path, with string) (*facts.Bag, []facts.Finding, error) {
	bag := facts.NewBag()
	if cat := activeCatalog(); cat != nil {
		facts.Set(bag, facts.SourceCatalog, cat,
			facts.Provenance{Source: "catalog", Authority: facts.Reference})
	}
	bar := newBar()
	defer bar.Clear()
	raw := facts.NewBag()
	if err := imgfacts.Ingest(raw, reconRecognizers(), path, bar); err != nil {
		return bag, []facts.Finding{{Severity: facts.Warn, Message: "reading " + infile.Base(path) + ": " + err.Error()}}, nil
	}
	bag.Merge(raw)
	if with != "" {
		comp := facts.NewBag()
		if err := imgfacts.Ingest(comp, reconRecognizers(), with, bar); err != nil {
			return nil, nil, fmt.Errorf("reading %s: %w", infile.Base(with), err)
		}
		if err := sameRelease(path, raw, with, comp); err != nil {
			return nil, nil, err
		}
		bag.Merge(comp)
	}
	res := reconGraph().ResolveAll(bag, facts.Options{Verify: reconVerify})
	return bag, res.Findings, nil
}

// sameRelease resolves two packages apart and requires that they name the
// same device and the same build: a codename alone is shared by every release
// of a device.
func sameRelease(pa string, a *facts.Bag, pb string, b *facts.Bag) error {
	resolved := func(raw *facts.Bag) *facts.Bag {
		r := facts.NewBag()
		r.Merge(raw)
		reconGraph().ResolveAll(r, facts.Options{})
		return r
	}
	ra, rb := resolved(a), resolved(b)
	na, nb := infile.Base(pa), infile.Base(pb)
	build := false
	for _, k := range []string{facts.Codename.Name(), facts.SoftwareVersion.Name(), facts.BuildFingerprint.Name()} {
		va, okA := ra.Best(k)
		vb, okB := rb.Best(k)
		if !okA || !okB {
			continue
		}
		if !ra.Equal(k, va.Data, vb.Data) {
			return fmt.Errorf("%s is not the same release as %s: %s %s vs %s", nb, na, k, ra.Show(k, va.Data), rb.Show(k, vb.Data))
		}
		build = build || k != facts.Codename.Name()
	}
	if !build {
		return fmt.Errorf("nothing shows %s is the same release as %s: they share no build number or fingerprint", nb, na)
	}
	return nil
}

// printWhy prints the derivation trace --why asked for.
func printWhy(b *facts.Bag) {
	if reconWhy == "" {
		return
	}
	for _, line := range facts.Explain(b, reconWhy) {
		fmt.Println("  " + line)
	}
}

// printIdentityFacts renders what the planner resolved about a device or the
// firmware for one, each line under the caller's indent.
//
// Order and wording are the report's, not the graph's: the bag is keyed by fact,
// the reader wants identity, then build, then what is locked down. It does not
// care where the bytes came from, so a stock package and a set of partitions
// read off a live device print the same way.
func printIdentityFacts(b *facts.Bag, indent string) {
	for _, line := range append(identityFactLines(b), loaderLines(b)...) {
		fmt.Println(indent + line)
	}
}

func identityFactLines(b *facts.Bag) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	if cid, ok := facts.Get(b, facts.CID); ok {
		line := fmt.Sprintf("Target: CID 0x%04X", cid)
		if name, ok := facts.Get(b, facts.Codename); ok {
			line = fmt.Sprintf("Target: codename %s, CID 0x%04X", name, cid)
		}
		if mk, ok := facts.Get(b, vendor.MarketingName); ok {
			line += fmt.Sprintf(" (%s)", mk)
		}
		if carrier, ok := facts.Get(b, facts.Carrier); ok {
			line += " — " + carrier
		}
		out = append(out, line)
	} else if name, ok := facts.Get(b, facts.Codename); ok {
		line := "Device: " + name
		if sku, ok := facts.Get(b, facts.SKU); ok {
			line += " (" + sku + ")"
		}
		out = append(out, line)
	}
	if v, ok := facts.Get(b, facts.SoftwareVersion); ok {
		add("Build:  %s", v)
	}
	if v, ok := facts.Get(b, facts.BuildFingerprint); ok {
		add("Fingerprint: %s", v)
	}
	if v, ok := facts.Get(b, facts.SystemFingerprint); ok {
		add("System fp:   %s", v)
	}
	model, hasModel := facts.Get(b, facts.Model)
	if skus, ok := facts.Get(b, facts.SKUModels); ok {
		line := "Model: " + b.Show(facts.SKUModels.Name(), skus)
		if hasModel {
			line = "Model: " + model + " — " + b.Show(facts.SKUModels.Name(), skus)
		}
		out = append(out, line)
	} else if hasModel {
		add("Model: %s", model)
	}
	var plat []string
	soc, hasSoC := facts.Get(b, facts.SoC)
	if hasSoC {
		plat = append(plat, soc)
	}
	if v, ok := facts.Get(b, facts.BoardPlatform); ok {
		if hasSoC {
			plat[0] += " (" + v + ")"
		} else {
			plat = append(plat, v)
		}
	}
	if v, ok := facts.Get(b, facts.FirstAPILevel); ok {
		plat = append(plat, fmt.Sprintf("launched on API %d", v))
	}
	if len(plat) > 0 {
		add("Platform: %s", strings.Join(plat, ", "))
	}
	if v, ok := facts.Get(b, facts.BluetoothFirmware); ok {
		add("Bluetooth firmware: %s", v)
	}
	if v, ok := facts.Get(b, facts.SecurityPatch); ok {
		line := "Patch level: " + v
		if vp, ok := facts.Get(b, facts.VendorSecurityPatch); ok && vp != v {
			line += ", vendor " + vp
			if vr, ok := facts.Get(b, facts.VendorRelease); ok {
				line += " (Android " + vr + ")"
			}
		}
		out = append(out, line)
	}
	if v, ok := facts.Get(b, facts.AVBKey); ok {
		line := "AVB key: sha256 " + short(v)
		if rb, ok := facts.Get(b, facts.AVBRollbackIndex); ok {
			line += fmt.Sprintf(", rollback %d", rb)
		}
		out = append(out, line)
	}
	var comp []string
	if v, ok := facts.Get(b, vendor.MBMVersion); ok {
		comp = append(comp, "MBM "+v)
	}
	if v, ok := facts.Get(b, vendor.ModemVersion); ok {
		comp = append(comp, "modem "+v)
	}
	if len(comp) > 0 {
		add("Components: %s", strings.Join(comp, ", "))
	}
	if lock, ok := facts.Get(b, vendor.SubsidyLock); ok {
		add("Subsidy: %s", b.Show(vendor.SubsidyLock.Name(), lock))
	}
	var signing []string
	if v, ok := facts.Get(b, facts.SigningCID); ok {
		signing = append(signing, fmt.Sprintf("HAB CID %d", v))
	}
	if v, ok := facts.Get(b, facts.SecurityVersion); ok {
		signing = append(signing, fmt.Sprintf("security-version %d", v))
	}
	if v, ok := facts.Get(b, facts.Region); ok {
		signing = append(signing, "region "+v)
	}
	if v, _ := facts.Get(b, facts.CustomerSigned); v {
		signing = append(signing, "customer-signed")
	}
	if len(signing) > 0 {
		add("Signing: %s", strings.Join(signing, ", "))
	}
	var sb []string
	if v, ok := facts.Get(b, facts.JTAGID); ok {
		sb = append(sb, "JTAG "+v)
	}
	if v, ok := facts.Get(b, facts.OEMID); ok {
		sb = append(sb, "OEM_ID "+v)
	}
	if v, ok := facts.Get(b, facts.RootKeyHash); ok {
		sb = append(sb, "root "+short(v))
	}
	if len(sb) > 0 {
		add("Secure boot: %s", strings.Join(sb, ", "))
	}
	if table, ok := facts.Get(b, facts.AntiRollbackTable); ok {
		// Enforcement is known only where a package's own manifest states it; a
		// table read off the images themselves is silent on it.
		enf := ""
		if v, ok := facts.Get(b, facts.EnforceAntiRollback); ok {
			enf = "not enforced, "
			if v {
				enf = "enforced, "
			}
		}
		if bumped := facts.Bumped(table); len(bumped) == 0 {
			add("Anti-rollback: %sall %d images at 0x00 (baseline)", enf, len(table))
		} else {
			add("Anti-rollback: %sbumped: %s", enf, strings.Join(bumped, ", "))
		}
	}
	if ids, ok := facts.Get(b, imgfacts.OTACerts); ok {
		add("OTA key: %s", b.Show(imgfacts.OTACerts.Name(), ids))
	}
	if v, ok := facts.Get(b, facts.PlatformCert); ok {
		who, _ := facts.Get(b, facts.PlatformSigner)
		add("Platform key: %s sha256 %s", orUnknown(who), short(v))
	}
	if v, ok := facts.Get(b, facts.DataEncryption); ok {
		line := "Encryption: "
		switch v {
		case "none", "full-disk":
			line += v
		default:
			line += "file-based " + v
		}
		if m, _ := facts.Get(b, facts.MetadataEncryption); m {
			line += ", metadata encrypted"
		}
		out = append(out, line)
	}
	if v, ok := facts.Get(b, facts.GSIKeys); ok {
		add("GSI: system also verifies %s", strings.Join(v, ", "))
	}
	var props []string
	if v, ok := facts.Get(b, facts.BuildDate); ok {
		props = append(props, "built "+v)
	}
	if v, ok := facts.Get(b, facts.ABEnabled); ok {
		if v {
			props = append(props, "A/B seamless")
		} else {
			props = append(props, "non-A/B")
		}
	}
	if len(props) > 0 {
		add("Properties: %s", strings.Join(props, ", "))
	}
	return out
}

// printFindings renders the planner's judgments after the values, the way the
// rest of recon warns: a same-fact disagreement, or a broken cross-fact invariant.
func printFindings(fs []facts.Finding) {
	for _, f := range fs {
		switch f.Severity {
		case facts.Error:
			fmt.Println(cBad("  [!] " + f.Message))
		case facts.Info:
			fmt.Println(cGood("  [✓] " + f.Message))
		default:
			fmt.Println(cWarn("  [!] " + f.Message))
		}
	}
}

// certRec is one unique embedded key/cert, deduped across the whole recon so the
// shared attestation chain (Root CA 724, Motorola CA, …) prints once, not per image.
type certRec struct {
	label, issuer string
	bits          int
	kind          string         // "cert" or "key"
	count         int            // how many images embed it
	der           []byte         // cert DER (kind=="cert")
	pub           *rsa.PublicKey // key (kind=="key")
}

var certAccum struct {
	order []string
	recs  map[string]*certRec
}

func resetCerts() { certAccum.order = nil; certAccum.recs = map[string]*certRec{} }

// collectKeys folds a signed image's embedded keys/certs into the shared set.
func collectKeys(data []byte) {
	add := func(rec *certRec, fp string) {
		if fp == "" {
			return
		}
		if ex := certAccum.recs[fp]; ex != nil {
			ex.count++
			return
		}
		rec.count = 1
		certAccum.recs[fp] = rec
		certAccum.order = append(certAccum.order, fp)
	}
	r := rsakey.Scan(data)
	for _, c := range r.Certs {
		cn := c.Subject
		issuer := ""
		var der []byte
		if c.Certificate != nil {
			if c.Certificate.Subject.CommonName != "" {
				cn = c.Certificate.Subject.CommonName
			}
			issuer = c.Certificate.Issuer.CommonName
			der = c.Certificate.Raw
		}
		bits := 0
		if c.Public != nil {
			bits = c.Public.N.BitLen()
		}
		add(&certRec{label: cn, issuer: issuer, bits: bits, kind: "cert", der: der}, c.Fingerprint)
	}
	for _, k := range r.Keys {
		add(&certRec{label: "raw RSA key", bits: k.Bits(), kind: "key", pub: k.Public}, k.Fingerprint)
	}
}

// addCert folds a parsed X.509 cert (e.g. from recovery's otacerts.zip) into the
// same deduped set as collectKeys, using the SPKI-SHA256 fingerprint so it matches
// certs found in signed images.
func addCert(c *x509.Certificate) {
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return
	}
	fp := fmt.Sprintf("%x", sha256.Sum256(der))
	if ex := certAccum.recs[fp]; ex != nil {
		ex.count++
		return
	}
	label := c.Subject.CommonName
	if label == "" {
		label = c.Subject.String()
	}
	certAccum.recs[fp] = &certRec{label: label, issuer: c.Issuer.CommonName, bits: pub.N.BitLen(), kind: "cert", count: 1, der: c.Raw}
	certAccum.order = append(certAccum.order, fp)
}

// descendBootRamdisk lists the notable files in a boot image's ramdisk (fstab,
// OTA certs, props, sepolicy) and folds otacerts.zip certs into the cert set.
func descendBootRamdisk(data []byte, indent string) {
	img, err := bootimg.Parse(data)
	if err != nil {
		return
	}
	for _, s := range img.Sections {
		if !strings.Contains(s.Name, "ramdisk") {
			continue
		}
		rd, _, err := bootimg.DecompressRamdisk(s.Data)
		if err != nil {
			continue
		}
		entries, err := bootimg.ParseCpioConcat(rd)
		if err != nil {
			continue
		}
		for _, e := range entries {
			base := strings.ToLower(filepath.Base(e.Name))
			switch {
			case strings.Contains(base, "fstab"),
				base == "prop.default", base == "default.prop", base == "build.prop",
				base == "sepolicy":
				fmt.Printf("%s%-24s %s\n", indent, e.Name, humanBytes(int64(len(e.Data))))
			case base == "otacerts.zip":
				fmt.Printf("%s%-24s %s (OTA signing)\n", indent, e.Name, humanBytes(int64(len(e.Data))))
				collectOTACerts(e.Data)
			}
		}
	}
}

// collectOTACerts pulls the X.509 certs out of an otacerts.zip and folds them in.
func collectOTACerts(zipData []byte) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if blk, _ := pem.Decode(b); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				addCert(c)
			}
		}
	}
}

// carveKeys writes each unique cert (PEM + DER) and key (PEM) to dir, named by a
// sanitized subject and the fingerprint prefix so filenames are stable and unique.
func carveKeys(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	n := 0
	for _, fp := range certAccum.order {
		r := certAccum.recs[fp]
		base := filepath.Join(dir, sanitize(r.label)+"-"+fp[:min(12, len(fp))])
		switch r.kind {
		case "cert":
			if r.der == nil {
				continue
			}
			if err := os.WriteFile(base+".der", r.der, 0o644); err != nil {
				return err
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.der})
			if err := os.WriteFile(base+".pem", pemBytes, 0o644); err != nil {
				return err
			}
			n++
		case "key":
			if r.pub == nil {
				continue
			}
			der, err := x509.MarshalPKIXPublicKey(r.pub)
			if err != nil {
				continue
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			if err := os.WriteFile(base+".pem", pemBytes, 0o644); err != nil {
				return err
			}
			n++
		}
	}
	fmt.Printf("  Carved %d cert/key file(s) to %s\n", n, dir)
	return nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		out = "key"
	}
	return out
}

// printCollectedKeys prints the deduped key/cert set gathered during the recon.
func printCollectedKeys() {
	if len(certAccum.order) == 0 {
		return
	}
	fmt.Printf("\n  Signing keys & certs (%d unique):\n", len(certAccum.order))
	labelW := 0
	for _, fp := range certAccum.order {
		if n := len(certAccum.recs[fp].label); n > labelW {
			labelW = n
		}
	}
	for _, fp := range certAccum.order {
		r := certAccum.recs[fp]
		note := ""
		switch {
		case r.kind == "cert" && r.issuer == r.label:
			note = "[self-signed root]"
		case r.issuer != "":
			note = "issuer=" + r.issuer
		}
		fpHex := fp
		if len(fpHex) > 16 {
			fpHex = fpHex[:16]
		}
		fmt.Printf("    %-*s  RSA-%-4d  ×%-3d  fp=%-16s  %s\n", labelW, r.label, r.bits, r.count, fpHex, note)
	}
}

func short(hexstr string) string {
	if len(hexstr) > 16 {
		return hexstr[:16] + "…"
	}
	return hexstr
}

// maxCascadeRead caps how large a member/record we fully read to recurse into;
// beyond it we print the type but do not expand (keeps a multi-GB super out).
const maxCascadeRead = 200 << 20

func runFileRecon(path string) error {
	f, err := infile.Open(path)
	if err != nil {
		return err
	}
	head := make([]byte, 8192) // enough for a 4K-sector GPT header at offset 4096
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	size := f.Size()
	f.Close()

	kind := filetype.Detect(head)
	archive := (kind == filetype.Zip || kind == filetype.Tar || kind == filetype.Gzip) && srcfile.IsArchive(path)
	// Every non-archive branch reads the input whole; over HTTP that is the
	// full download this route exists to avoid, so only a modest file is
	// accepted.
	if infile.IsRemote(path) && !archive && size > maxCascadeRead {
		return fmt.Errorf("%s is %s and cannot be read by range; download it to recon it", infile.Base(path), humanBytes(size))
	}
	fmt.Printf("%s\n", infile.Base(path))
	fmt.Printf("  Size:  %s\n", humanBytes(size))
	fmt.Printf("  Type:  %s\n", kind)

	resetCerts() // keys/certs are gathered during the walk, printed deduped after
	// Resolve before rendering: the identity lines a package prints are the
	// planner's answers, and the judgments about them print after everything else.
	with, how := reconWith, ""
	switch with {
	case "none":
		with = ""
	case "":
		with, how = autoCompanion(path)
	}
	bag, findings, used, err := reconIngest(path, with, how != "")
	if err != nil {
		return err
	}
	reconWith = used
	switch {
	case used != "" && how != "":
		fmt.Printf("  With:  %s (%s; --with none to skip)\n", infile.Base(used), how)
	case used != "":
		fmt.Printf("  With:  %s\n", infile.Base(used))
	}
	var rerr error
	switch {
	case archive:
		rerr = reconArchive(path, bag)
	case kind == filetype.VBMeta:
		rerr = reconVBMeta(path)
	case kind == filetype.SingleNLonely:
		rerr = reconContainer(path)
	case kind == filetype.AndroidBoot, kind == filetype.AndroidVendorBoot:
		rerr = reconBootImage(path)
	case kind == filetype.ELF:
		rerr = reconELF(path)
	case kind == filetype.GPT:
		rerr = reconGPT(path)
	case kind == filetype.DTBOTable, kind == filetype.DeviceTree:
		rerr = reconDTBO(path)
	case kind == filetype.SparseImage:
		rerr = reconSparse(path)
	case kind == filetype.Ext4, kind == filetype.FAT:
		rerr = reconExt4(path)
	default:
		// Vendor-specific content with no neutral magic: Motorola CID image or SLCF.
		rerr = reconContentFallback(path, head, bag)
	}
	printCollectedKeys()
	if reconCarveDir != "" && len(certAccum.order) > 0 {
		if err := carveKeys(reconCarveDir); err != nil {
			return err
		}
	}
	printWhy(bag)
	if reconLearn {
		// Only a codename-scoped artifact (a stock package, a device image) is
		// device knowledge. A lone component — one MBN, one loader — has only a
		// JTAG, and JTAG names the silicon, not the unit: the same part ships in
		// every device sharing that die, so learning it keyed by JTAG would pool
		// unrelated phones. JTAG-fallback keying is for a *live* device (still one
		// unit), never a file.
		if _, ok := facts.Get(bag, facts.Codename); ok {
			detected := ""
			if drv, ok := vendor.Detect(path); ok {
				detected = drv.ID()
			}
			learnFromRecon(bag, "", nil, detected) // no unit in hand, so no serial to stitch by
		} else {
			fmt.Printf("\n  %s no codename in this artifact — a lone component is not device knowledge; not learned\n", cWarn("[i]"))
		}
	}
	printFindings(findings)
	return rerr
}

func reconBootImage(path string) error {
	data, err := infile.ReadFile(path)
	if err != nil {
		return err
	}
	img, err := bootimg.Parse(data)
	if err != nil {
		return err
	}
	fmt.Printf("  Header:  v%d", img.HeaderVersion)
	if img.OSVersion != "" {
		fmt.Printf(", OS %s", img.OSVersion)
	}
	fmt.Println()
	if img.Cmdline != "" {
		fmt.Printf("  Cmdline: %s\n", img.Cmdline)
	}
	for _, s := range img.Sections {
		extra := ""
		if s.Name == "ramdisk" || s.Name == "vendor_ramdisk" {
			if _, codec, err := bootimg.DecompressRamdisk(s.Data); err == nil {
				extra = " (" + string(codec) + ")"
			}
		}
		fmt.Printf("    %-16s %s%s\n", s.Name, humanBytes(int64(len(s.Data))), extra)
	}
	descendBootRamdisk(data, "    ")
	return nil
}

func reconELF(path string) error {
	data, missing, err := readImage(path)
	if err != nil {
		return err
	}
	info, err := bootelf.Analyze(data)
	if err != nil {
		return err
	}
	fmt.Printf("  ELF:     %d-bit %s %s, %d segments\n", info.Class, info.Endian, info.Arch, len(info.Segments))
	if n := splitNote(missing); n != "" {
		fmt.Printf("  Split:   %s\n", n)
	}
	if info.QCVersion != "" {
		fmt.Printf("  Build:   %s", info.QCVersion)
		if info.TargetSoC != "" {
			fmt.Printf("  (%s)", info.TargetSoC)
		}
		fmt.Println()
	}
	var built []string
	if info.QCBuildTime != "" {
		built = append(built, "Qualcomm "+info.QCBuildTime)
	}
	if d := info.Provenance.BuildDate; d != "" {
		built = append(built, "OEM "+d)
	}
	if len(built) > 0 {
		fmt.Printf("  Built:   %s\n", strings.Join(built, ", "))
	}
	if id := info.Identity; id != nil {
		fmt.Printf("  Secboot: %s HW_ID=%s key=RSA-%d\n", secbootAnnotate(id), id.HWID, id.KeyBits)
	}
	collectKeys(data)
	printDevcfgPolicy(data)
	return nil
}

// printDevcfgPolicy surfaces the OEM secure-boot posture when the ELF is a
// devcfg.mbn — the /tz/oem TrustZone policy node. It is the one place the device
// declares its ROT-transfer, RPMB-keystore, anti-rollback (MRC) and image-
// encryption stance, none of which is visible from the signature chain.
func printDevcfgPolicy(data []byte) {
	for _, c := range devcfg.FromELF(data) {
		p := c.OEM()
		if !p.Found {
			continue
		}
		fmt.Println("  OEM secure-boot policy (/tz/oem):")
		yn := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		fmt.Printf("    ROT transfer (SendROT):  APPS %s, MODEM %s\n", yn(p.ROTTransferAPPS), yn(p.ROTTransferMODEM))
		fmt.Printf("    RPMB keystore/counter:   keystore %s, counter %s, key-provision %s, autoprov %s\n",
			yn(p.RPMBKeystore), yn(p.RPMBCounter), yn(p.AllowRPMBKeyProvision), yn(!p.DisableRPMBAutoprov))
		fmt.Printf("    Anti-rollback (MRC):     activation-list %d, revocation-list %d\n", p.MRCActivation, p.MRCRevocation)
		extras := []string{"counter-measures " + yn(p.CounterMeasure), "image-encryption " + yn(p.ImageEncryption)}
		if p.HasPubKey {
			extras = append(extras, "OEM RSA pubkey embedded")
		}
		if p.HasPKHashFuse {
			extras = append(extras, "ROT PK-hash field present")
		}
		fmt.Printf("    %s\n", strings.Join(extras, ", "))
		return
	}
}

func reconGPT(path string) error {
	data, err := infile.ReadFile(path)
	if err != nil {
		return err
	}
	t, err := qfil.ParseGPT(data)
	if err != nil {
		return err
	}
	fmt.Printf("  GPT:     %d partitions, %d-byte sectors\n", len(t.Partitions), t.SectorSize)
	for i, p := range t.Partitions {
		if i >= 6 {
			fmt.Printf("    … (+%d more)\n", len(t.Partitions)-6)
			break
		}
		fmt.Printf("    %-20s %s\n", p.Name, humanBytes(int64(p.NumSectors*uint64(t.SectorSize))))
	}
	return nil
}

func reconDTBO(path string) error {
	data, err := infile.ReadFile(path)
	if err != nil {
		return err
	}
	t, err := dtbo.Parse(data)
	if err != nil {
		return err
	}
	fmt.Printf("  DT table: v%d, %d device tree(s)\n", t.Version, len(t.Entries))
	for i, e := range t.Entries {
		if i >= 8 {
			fmt.Printf("    … (+%d more)\n", len(t.Entries)-8)
			break
		}
		fmt.Printf("    id=0x%08x rev=0x%08x  %s\n", e.ID, e.Rev, humanBytes(int64(e.Size)))
	}
	return nil
}

func reconSparse(path string) error {
	data, err := infile.ReadFile(path)
	if err != nil {
		return err
	}
	size, err := sparse.OutputSize(data)
	if err != nil {
		return err
	}
	inner := filetype.Unknown
	if pre, err := sparse.Prefix(data, 64<<10); err == nil {
		inner = filetype.Detect(pre)
	}
	fmt.Printf("  Sparse:  expands to %s; inner: %s\n", humanBytes(size), inner)
	return nil
}

func reconExt4(path string) error {
	data, err := infile.ReadFile(path)
	if err != nil {
		return err
	}
	entries, err := modem.List(data)
	if err != nil {
		return err
	}
	fmt.Printf("  %-8s %d files\n", typeLabel(path, data)+":", len(entries))
	for i, e := range entries {
		if i >= 6 {
			fmt.Printf("    … (+%d more; see `unbrick ls`)\n", len(entries)-6)
			break
		}
		fmt.Printf("    %-28s %s\n", e.Path, humanBytes(int64(e.Size)))
	}
	printModemCarrier(data, "  ")
	return nil
}

// printModemCarrier prints the carrier/variant each mcfg config in a modem
// filesystem is built for — the identity that ties this modem image to a carrier.
func printModemCarrier(ext4 []byte, indent string) {
	if bb := modem.Baseband(ext4); bb != "" {
		fmt.Printf("%sModem baseband: %s\n", indent, bb)
	}
	entries, err := modem.List(ext4)
	if err != nil {
		return
	}
	for _, e := range entries {
		if note := mcfgNote(ext4, e.Path); note != "" {
			fmt.Printf("%sModem %s\n", indent, note)
		}
	}
}

func reconArchive(path string, bag *facts.Bag) error {
	// Whose build is this, and whose package format? The brand names the
	// vendor; the format driver can differ (a Lenovo build in a MediaTek
	// SP Flash Tool package).
	vendorID := brandVendor(bag)
	drvID := ""
	if drv, ok := vendor.Detect(path); ok {
		drvID = drv.ID()
	}
	switch {
	case vendorID != "" && drvID != "" && drvID != vendorID:
		fmt.Printf("  Vendor: %s (%s package)\n", vendorID, drvID)
	case vendorID != "":
		fmt.Printf("  Vendor: %s\n", vendorID)
	case drvID != "":
		vendorID = drvID
		fmt.Printf("  Vendor: %s\n", vendorID)
	}
	if _, pkg, ok := vendor.DetectStock(path); ok && pkg != nil {
		fmt.Printf("  Kind:   stock firmware package\n")
	}
	// The system partition's own build.prop, read from super, is the authoritative
	// source of ro.system.build.fingerprint (the ramdisk's copy is stale) and it
	// corroborates the patch/date. Read it before rendering so it shows and so a
	// subsequent --learn contributes the true system identity.
	learnSystemProps(path, bag)
	if reconWith != "" {
		learnSystemProps(reconWith, bag)
	}
	// What the package says about itself was resolved before this ran: the
	// recognizers decided what each member is, the vendor's rules turned those
	// into facts, and the planner cross-checked the ones two members both
	// produce. Recon only renders. In particular the carrier CID (flashfile
	// cid_value) and the HAB signing CID (vbmeta HAB_META) are different facts,
	// which is why their legitimate difference is not a disagreement.
	printIdentityFacts(bag, "  ")
	// Cascade through the members, descending into nested containers.
	members, err := srcfile.Members(path, 8192)
	if err != nil || len(members) == 0 {
		return err
	}
	// By the base name each line shows, the path breaking ties.
	sort.Slice(members, func(i, j int) bool {
		bi, bj := filepath.Base(members[i].Name), filepath.Base(members[j].Name)
		if bi != bj {
			return bi < bj
		}
		return members[i].Name < members[j].Name
	})
	fmt.Printf("  Contents (%d members):\n", len(members))
	if why := srcfile.Incomplete(path); why != "" {
		fmt.Printf("    %s listing is partial: %s\n", cWarn("[!]"), why)
		if reconWith == "" {
			for _, c := range vendor.Companions(path, infile.Known()) {
				where := c.URL
				if where == "" {
					where = c.Hint
				}
				fmt.Printf("    %s the release's %s may hold the rest: --with %s\n", cWarn("[i]"), c.What, where)
			}
		}
	}
	var chunkCount int
	var chunkBytes int64
	var expand []srcfile.Member
	for _, m := range members {
		// Collapse the super sparsechunk fragments into one aggregate line.
		if strings.Contains(filepath.Base(m.Name), "sparsechunk") {
			chunkCount++
			chunkBytes += int64(m.Size)
			continue
		}
		expand = append(expand, m)
	}
	// The bar shows only while a member is being read; it is cleared before
	// anything prints, and the next member's Describe redraws it below.
	bar := newBar()
	bar.Begin(len(expand))
	for _, m := range expand {
		base := filepath.Base(m.Name)
		kind := filetype.Detect(m.Head)
		bar.Describe("reading " + base)
		if label, detail, ok := describeOTAMember(path, base, m); ok {
			bar.Clear()
			fmt.Printf("    %-26s [%s] — %s\n", base, label, detail)
			bar.Advance()
			continue
		}
		whole := ""
		if kind == filetype.Unknown {
			whole = wholeLabel(path, base, m)
			if whole == "" && typeLabel(base, m.Head) == "unknown" {
				whole = pieceLabel(base, members)
			}
		}
		switch {
		case whole != "":
			bar.Clear()
			fmt.Printf("    %-26s %s\n", base, whole)
		case kind == filetype.OTAPayload:
			bar.Clear()
			printPayload(path, base, int64(m.Size), "    ")
		case kind == filetype.Tar:
			printNestedTar(path, m.Name, "    ", bar)
		case strings.HasPrefix(typeLabel(base, m.Head), "encrypted ") && printEncryptedFS(path, m, "    ", bar.Clear):
		case int64(m.Size) > maxCascadeRead:
			// Too big to buffer, but a filesystem carve can walk by range (ext4,
			// erofs — read via ReaderAt, metadata only) is listed rather than
			// skipped. Otherwise label it, with the build its own build.prop
			// states when it can be read in place.
			bar.Clear()
			if isRangeWalkable(kind) && printLargeFS(path, base, m, "    ") {
				break
			}
			fp := ""
			if n, err := carvePath(path, m.Name); err == nil && n.RandomAccess() {
				if ra, err := n.ReaderAt(); err == nil {
					fp = partitionFingerprint(ra, n.Size, m.Head)
				}
			}
			if fp != "" {
				fmt.Printf("    %-26s [%s]  %s — %s\n", base, typeLabel(base, m.Head), humanBytes(int64(m.Size)), fp)
			} else {
				fmt.Printf("    %-26s [%s]  %s (not expanded)\n", base, typeLabel(base, m.Head), humanBytes(int64(m.Size)))
			}
		case !isContainer(kind) && !lenovo.IsROM(base, m.Head):
			bar.Clear()
			fmt.Printf("    %-26s [%s]%s\n", base, typeLabel(base, m.Head), summarize(m.Head, nil))
		default:
			// An LMSA ROM (.t/.x) is not a neutral container but cascade
			// decrypts and descends into it, so read it whole like one.
			_, data, err := srcfile.Open(path, base)
			bar.Clear()
			if err != nil {
				fmt.Printf("    %-26s [%s]  (unreadable)\n", base, typeLabel(base, m.Head))
			} else {
				cascade(base, data, "    ", reconDepth)
			}
		}
		bar.Advance()
	}
	if chunkCount > 0 {
		fmt.Printf("    %-26s [android-sparse]  %d fragments, %s (super: dynamic partitions)\n",
			"super.img_sparsechunk.*", chunkCount, humanBytes(chunkBytes))
		printSuperMap(path, "      ")
	}
	return nil
}

// isRangeWalkable reports whether carve can list a filesystem of this kind from
// a ReaderAt without buffering it whole (ext4, erofs). f2fs has no reader, and
// FAT's lister is byte-based, so they are excluded.
func isRangeWalkable(k filetype.Kind) bool {
	return k == filetype.Ext4 || k == filetype.EROFS
}

// printLargeFS lists a filesystem member too big to buffer by walking it through
// carve (ext4fs/erofs over a ReaderAt, reading directory metadata only, not file
// contents). It prints the file count and the top-level directory counts, the
// same shape as the in-memory path. Returns false if the member did not expand
// to any files, so the caller can fall back to a plain label.
func printLargeFS(path, base string, m srcfile.Member, indent string) bool {
	n, err := carvePath(path, m.Name)
	if err != nil {
		return false
	}
	// Only a seekable member can be read by range. A deflated zip entry is
	// stream-only, so walking it would decompress the whole multi-GiB image
	// (and overrun MaxBuffer) — not a range read at all, so leave it labelled.
	if !n.RandomAccess() {
		return false
	}
	_, kids, err := n.Children()
	if err != nil || len(kids) == 0 {
		return false
	}
	fmt.Printf("%s%-26s [%s]  %s — %d files\n", indent, base, typeLabel(base, m.Head), humanBytes(int64(m.Size)), len(kids))
	count := map[string]int{}
	var dirs []string
	for _, k := range kids {
		d, _, ok := strings.Cut(strings.TrimPrefix(k.Name, "/"), "/")
		if !ok {
			d = "."
		}
		if count[d] == 0 {
			dirs = append(dirs, d)
		}
		count[d]++
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		fmt.Printf("%s  %-24s %d files\n", indent, d+"/", count[d])
	}
	return true
}

// partitionFingerprint is the build fingerprint a partition image's own
// build.prop states, read in place, or "".
func partitionFingerprint(ra io.ReaderAt, size int64, head []byte) string {
	switch filetype.Detect(head) {
	case filetype.Ext4, filetype.EROFS:
	default:
		return ""
	}
	fsys, err := carve.FromReaderAt("", ra, size).FS()
	if err != nil {
		return ""
	}
	for _, p := range []string{"build.prop", "etc/build.prop", "system/build.prop"} {
		data, err := fs.ReadFile(fsys, p)
		if err != nil || len(data) > 1<<20 {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && strings.HasPrefix(k, "ro.") && strings.HasSuffix(k, "build.fingerprint") && v != "" {
				return v
			}
		}
	}
	return ""
}

// printNestedTar lists a tar member's own members (an Odin .tar.md5),
// cascading into each small enough to read; an lz4 one is read through its
// decompression.
func printNestedTar(path, name, indent string, bar *barSink) {
	base := filepath.Base(name)
	n, err := carvePath(path, name)
	var kids []*carve.Node
	if err == nil {
		_, kids, err = n.Children()
	}
	bar.Clear()
	if err != nil {
		fmt.Printf("%s%-26s [tar]  (%v)\n", indent, base, err)
		return
	}
	fmt.Printf("%s%-26s [tar]  %s, %d members\n", indent, base, humanBytes(n.Size), len(kids))
	if why := n.Partial(); why != "" {
		fmt.Printf("%s  %s listing is partial: %s\n", indent, cWarn("[!]"), why)
	}
	for _, k := range kids {
		bar.Describe("reading " + k.Name)
		line, data := nestedMember(k)
		bar.Clear()
		if data != nil {
			cascade(k.Name, data, indent+"  ", reconDepth-1)
		} else {
			fmt.Printf("%s  %s\n", indent, line)
		}
	}
}

// nestedMember reads k whole when it is small enough to cascade into, else
// describes it from its head.
func nestedMember(k *carve.Node) (line string, data []byte) {
	inner := k
	if filetype.Detect(k.Head()) == filetype.LZ4 {
		if _, c, err := k.Children(); err == nil && len(c) == 1 {
			inner = c[0]
		}
	}
	if k.Size <= maxCascadeRead {
		if b, err := inner.Bytes(); err == nil {
			return "", b
		}
	}
	size := humanBytes(k.Size)
	if inner != k {
		size += " lz4"
		if inner.Size >= 0 {
			size += ", " + humanBytes(inner.Size) + " raw"
		}
	}
	return fmt.Sprintf("%-24s [%s]  %s (not expanded)", k.Name, typeLabel(inner.Name, inner.Head()), size), nil
}

// maxWholeRead caps the member read whole to label what its head cannot
// show: a zero head proves nothing about the rest, and a backup GPT's header
// is its last sector.
const maxWholeRead = 1 << 20

// wholeLabel labels a small member of no recognizable head from all of its
// bytes, or returns "": one that is zeros throughout, as packages ship to wipe
// a partition (Xiaomi's multi_image.mbn for multiimgoem), or a backup GPT.
func wholeLabel(path, base string, m srcfile.Member) string {
	// A wipe image is read further: only zeros are, and its head says so.
	limit := uint64(maxWholeRead)
	if bytes.Count(m.Head, []byte{0}) == len(m.Head) {
		limit = maxBlankRead
	}
	if m.Size == 0 || m.Size > limit {
		return ""
	}
	data := m.Head
	if uint64(len(data)) < m.Size {
		var err error
		if _, data, err = srcfile.Open(path, base); err != nil || uint64(len(data)) != m.Size {
			return ""
		}
	}
	switch {
	case bytes.Count(data, []byte{0}) == len(data):
		return fmt.Sprintf("[blank]  %s of zeros", humanBytes(int64(m.Size)))
	case filetype.BackupGPT(data):
		if t, err := qfil.ParseGPT(data); err == nil {
			return fmt.Sprintf("[gpt backup]  %d partitions", len(t.Partitions))
		}
		return "[gpt backup]"
	case lp.IsSuper(data):
		if md, err := lp.Parse(data); err == nil {
			var names []string
			for _, p := range md.Partitions {
				names = append(names, p.Name)
			}
			return fmt.Sprintf("[super metadata]  %d partitions: %s", len(names), strings.Join(names, ", "))
		}
		return "[super metadata]"
	}
	return ""
}

// pieceRe is how a sparse image split for QFIL names its pieces: name_N.img,
// each written at the offset the rawprogram XML gives.
var pieceRe = regexp.MustCompile(`^(.+)_(\d+)\.img$`)

// pieceLabel labels a piece of a split partition image, which carries no
// format of its own past the first, or "": the member must be one of a
// name_N.img series that has a first piece.
func pieceLabel(base string, members []srcfile.Member) string {
	m := pieceRe.FindStringSubmatch(base)
	if m == nil {
		return ""
	}
	for _, o := range members {
		if filepath.Base(o.Name) == m[1]+"_1.img" {
			return fmt.Sprintf("[%s, piece %s]", m[1], m[2])
		}
	}
	return ""
}

// maxBlankRead caps the member read whole to prove it is zeros throughout.
const maxBlankRead = 64 << 20

// describeOTAMember labels an OTA package's descriptive members (metadata,
// otacert, the protobufs), which carry no magic for typeLabel to go on.
func describeOTAMember(path, base string, m srcfile.Member) (label, detail string, ok bool) {
	if m.Size > 1<<16 {
		return "", "", false
	}
	data := m.Head
	if uint64(len(data)) < m.Size {
		var err error
		if _, data, err = srcfile.Open(path, base); err != nil {
			return "", "", false
		}
	}
	return otameta.Describe(base, data)
}

// printPayload lists an OTA payload's partitions, cascading into each one small
// enough to materialize. Reads are lazy per operation, so the multi-GB dynamic
// partitions cost only their first block (for the type label).
func printPayload(zipPath, name string, size int64, indent string) {
	p, closer, err := payload.OpenZip(zipPath)
	if err != nil {
		fmt.Printf("%s%-26s [OTA payload]  %s (unreadable: %v)\n", indent, name, humanBytes(size), err)
		return
	}
	defer closer.Close()
	kind := "full"
	if p.IsDelta() {
		kind = "delta"
	}
	parts := p.Partitions()
	fmt.Printf("%s%-26s [OTA payload]  %s, %s, %d partition(s)\n", indent, name, humanBytes(size), kind, len(parts))
	bar := newBar()
	bar.Begin(len(parts))
	for _, pn := range parts {
		bar.Describe("reading " + pn)
		ra, psize, err := p.PartitionReaderAt(pn)
		if err != nil {
			bar.Clear()
			fmt.Printf("%s  %-24s (not readable: %v)\n", indent, pn, err)
			bar.Advance()
			continue
		}
		if psize > maxCascadeRead {
			head := make([]byte, 8192)
			ra.ReadAt(head, 0)
			fp := partitionFingerprint(ra, psize, head)
			bar.Clear()
			if fp != "" {
				fmt.Printf("%s  %-24s [%s]  %s — %s\n", indent, pn, typeLabel(pn, head), humanBytes(psize), fp)
			} else {
				fmt.Printf("%s  %-24s [%s]  %s (not expanded)\n", indent, pn, typeLabel(pn, head), humanBytes(psize))
			}
			bar.Advance()
			continue
		}
		data := make([]byte, psize)
		_, err = ra.ReadAt(data, 0)
		bar.Clear()
		if err != nil {
			fmt.Printf("%s  %-24s (unreadable: %v)\n", indent, pn, err)
		} else {
			cascade(pn, data, indent+"  ", reconDepth-1)
		}
		bar.Advance()
	}
}

// printSuperMap reads super's logical-partition map from just the first chunk
// (the liblp metadata lives at the front), so it never expands the whole image.
func printSuperMap(path, indent string) {
	stop := spin("reading super metadata…")
	_, chunk0, err := srcfile.Open(path, "super.img_sparsechunk.0")
	stop()
	if err != nil {
		return
	}
	raw, err := sparse.Decode(chunk0)
	if err != nil {
		return
	}
	md, err := lp.Parse(raw)
	if err != nil {
		return
	}
	for _, p := range md.Partitions {
		grp := ""
		if p.Group != "" && p.Group != "default" {
			grp = "  (" + p.Group + ")"
		}
		fmt.Printf("%s%-22s %s%s\n", indent, p.Name, humanBytes(int64(p.SizeBytes)), grp)
	}
}

// secbootAnnotate renders a signed image's identity with what the catalog knows:
// OEM_ID → vendor, JTAG_ID → device/SoC, SW_ID → boot-chain stage.
func secbootAnnotate(id *secboot.Identity) string {
	oem := "OEM_ID=" + id.OEMID
	if drv, ok := vendor.ForOEMID(id.OEMID); ok {
		oem += " (" + drv.ID() + ")"
	}
	jtag := "JTAG=" + id.JTAGID
	if soc, ok := activeCatalog().SoCByJTAG(id.JTAGID); ok && soc != "" {
		jtag += " (" + soc + ")"
	}
	sw := fmt.Sprintf("SW_ID=%d", id.SWType())
	if n := activeCatalog().SWIDName(id.SWID); n != "" {
		sw += " (" + n + ")"
	}
	if m := id.Meta; m != nil {
		sw += fmt.Sprintf(" ARB=%d", m.AntiRollback)
		if len(id.Signers) > 1 {
			sw += " QTI+OEM-signed"
		}
		if len(m.Serials) > 0 {
			sw += fmt.Sprintf(" serial-bound(%d)", len(m.Serials))
		}
	}
	return oem + " " + jtag + " " + sw
}

// isContainer reports whether a kind holds nested artifacts worth recursing into.
func isContainer(k filetype.Kind) bool {
	switch k {
	case filetype.SingleNLonely, filetype.SparseImage, filetype.Ext4, filetype.FAT,
		filetype.AndroidBoot, filetype.AndroidVendorBoot:
		return true
	}
	return false
}

// cascade prints one node and recurses into its children up to depth levels.
// lmsaWordlistEnv names a file of newline-separated passwords to try, beyond the
// recovered default and lenovo.Candidates, when decrypting an LMSA ROM.
const lmsaWordlistEnv = "LMSA_ROM_WORDLIST"

// lmsaExtraPasswords gathers caller-supplied LMSA passwords: a single one from
// the override env, then every line of a wordlist file if one is named. Both are
// tried before the built-in candidates.
func lmsaExtraPasswords() []string {
	var extra []string
	if p := os.Getenv(vendor.LMSAPasswordEnv); p != "" {
		extra = append(extra, p)
	}
	if wl := os.Getenv(lmsaWordlistEnv); wl != "" {
		if b, err := os.ReadFile(wl); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if s := strings.TrimRight(line, "\r"); s != "" {
					extra = append(extra, s)
				}
			}
		}
	}
	return extra
}

func cascade(name string, data []byte, indent string, depth int) {
	// Detect on the full in-memory record: some magics (a 4K-sector GPT header)
	// sit past the first 4 KiB. filetype only indexes what it needs, so this is cheap.
	kind := filetype.Detect(data)
	fmt.Printf("%s%-26s [%s]%s\n", indent, name, typeLabel(name, data), summarize(data, data))
	if kind == filetype.ELF {
		collectKeys(data)
	}
	if depth <= 0 {
		return
	}
	if lenovo.IsROM(name, data) {
		if out, pw, err := lenovo.Recover(data, lmsaExtraPasswords()...); err == nil {
			fmt.Printf("%s  decrypted with password %q\n", indent, pw)
			cascade(lenovo.OutName(filepath.Base(name)), out, indent+"  ", depth-1)
		} else {
			fmt.Printf("%s  %s LMSA ROM: no known password (try %s or %s)\n",
				indent, cWarn("[!]"), vendor.LMSAPasswordEnv, lmsaWordlistEnv)
		}
		return
	}
	switch kind {
	case filetype.SingleNLonely:
		recs, err := blankflash.Parse(data)
		if err != nil {
			return
		}
		for _, r := range recs {
			if r.Name == blankflash.Trailer || r.Name == "" || strings.HasSuffix(r.Name, ".xml") {
				continue
			}
			cascade(r.Name, r.Data, indent+"  ", depth-1)
		}
	case filetype.GPT:
		if t, err := qfil.ParseGPT(data); err == nil {
			cat := activeCatalog()
			others := 0
			for _, p := range t.Partitions {
				sz := int64(p.NumSectors * uint64(t.SectorSize))
				base := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(p.Name, "_a"), "_b"))
				r, ok := cat.PartitionRule(p.Name)
				// Interesting = per-device data you must preserve, plus the big dynamic
				// containers; the replaceable boot chain (from the package) is collapsed.
				if !(cat.IsProtected(p.Name) || base == "super" || base == "userdata") {
					others++
					continue
				}
				tag := ""
				if ok && r.Category != "" {
					tag = "  (" + r.Category
					if r.Criticality != "" {
						tag += "/" + r.Criticality
					}
					tag += ")"
				}
				fmt.Printf("%s  %-20s %s%s\n", indent, p.Name, humanBytes(sz), tag)
			}
			if others > 0 {
				fmt.Printf("%s  (+%d replaceable boot/other partitions)\n", indent, others)
			}
		}
	case filetype.AndroidBoot, filetype.AndroidVendorBoot:
		descendBootRamdisk(data, indent+"  ")
	case filetype.SparseImage:
		// summarize already named the expanded size and inner FS from the header.
		// Only expand the whole image when it is small enough to descend into; a
		// 45 GiB userdata is left at that one line rather than materialized.
		if size, err := sparse.OutputSize(data); err != nil || size > maxCascadeRead {
			return
		}
		if raw, err := sparse.Decode(data); err == nil {
			cascade("(unsparsed)", raw, indent+"  ", depth-1)
		}
	case filetype.Ext4, filetype.FAT:
		if entries, err := modem.List(data); err == nil {
			// Subsystem firmware (adsp, cdsp, modem, …) ships as PIL splits; each
			// is shown joined, so its build and secboot identity read through.
			shown := 0
			for _, e := range entries {
				if !strings.EqualFold(filepath.Ext(e.Path), ".mdt") {
					continue
				}
				img, missing, err := modem.JoinSplit(data, e.Path)
				if err != nil {
					continue
				}
				collectKeys(img)
				line := fmt.Sprintf("%s  %-24s %s%s", indent, filepath.Base(e.Path), humanBytes(int64(len(img))), summarize(img, img))
				if n := splitNote(missing); n != "" {
					line += " (" + n + ")"
				}
				fmt.Println(line)
				shown++
			}
			leaves := 0
			for _, e := range entries {
				// Only surface the interesting leaves (signed images, PD maps, configs).
				if !ext4Notable(e.Path) || strings.EqualFold(filepath.Ext(e.Path), ".mdt") {
					continue
				}
				if leaves >= 8 {
					fmt.Printf("%s  … (+more; see `unbrick ls`)\n", indent)
					break
				}
				line := fmt.Sprintf("%s  %-24s %s", indent, filepath.Base(e.Path), humanBytes(int64(e.Size)))
				if note := leafNote(data, e.Path); note != "" {
					line += " — " + note
				}
				fmt.Println(line)
				leaves++
			}
			if shown+leaves == 0 {
				printDirCounts(entries, indent+"  ")
			}
		}
	}
}

// mcfgNote returns a one-line carrier/variant summary for an mcfg_*.mbn leaf, or
// "" if the file is not an mcfg. It reads the member from the modem image and
// parses the MCFG identity (the carrier this modem config is built for).
func mcfgNote(ext4 []byte, path string) string {
	b := strings.ToLower(filepath.Base(path))
	if !strings.HasPrefix(b, "mcfg") || !strings.HasSuffix(b, ".mbn") {
		return ""
	}
	data, err := modem.Extract(ext4, path)
	if err != nil {
		return ""
	}
	c, ok := mcfg.Parse(data)
	if !ok || c.Profile == "" {
		return ""
	}
	kind := "HW variant"
	if c.SW {
		kind = "carrier"
	}
	note := fmt.Sprintf("%s %q", kind, c.Profile)
	if len(c.APNs) > 0 {
		note += " (APNs: " + strings.Join(c.APNs, ", ") + ")"
	}
	return note
}

func ext4Notable(p string) bool {
	b := strings.ToLower(filepath.Base(p))
	return strings.HasSuffix(b, ".jsn") || strings.HasSuffix(b, ".mbn") || strings.HasSuffix(b, ".ver") ||
		b == "modem.mdt" || strings.HasPrefix(b, "mcfg") || strings.HasSuffix(b, ".qdb")
}

// leafNote is the one-line summary of a notable firmware-filesystem leaf, or "".
func leafNote(img []byte, path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsn":
		data, err := modem.Extract(img, path)
		if err != nil {
			return ""
		}
		return servregNote(data)
	case ".ver":
		// A build stamp (Qualcomm's BTFM firmware ships one beside each patch).
		data, err := modem.Extract(img, path)
		if ok, _ := filetype.Text(data); err != nil || !ok || len(data) > 256 {
			return ""
		}
		line, _, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
		return strings.TrimSpace(line)
	}
	if strings.EqualFold(filepath.Ext(path), ".qdb") {
		if data, err := modem.Extract(img, path); err == nil {
			return qdbNote(data)
		}
		return ""
	}
	if note := mcfgNote(img, path); note != "" {
		return note
	}
	// A whole signed image (venus.mbn, widevine.mbn), not split like an .mdt.
	if data, err := modem.Extract(img, path); err == nil && filetype.Detect(data) == filetype.ELF {
		collectKeys(data)
		return strings.TrimPrefix(summarize(data, data), " — ")
	}
	return ""
}

// servregNote summarizes a Qualcomm service-registry map (.jsn): the
// protection domain it describes and the services that domain provides, which
// is what the PD-restart machinery looks up.
func servregNote(data []byte) string {
	var m struct {
		Domain struct {
			Domain    string `json:"domain"`
			Subdomain string `json:"subdomain"`
		} `json:"sr_domain"`
		Services []struct {
			Provider string `json:"provider"`
			Service  string `json:"service"`
		} `json:"sr_service"`
	}
	if json.Unmarshal(data, &m) != nil || m.Domain.Domain == "" {
		return ""
	}
	var svcs []string
	for _, s := range m.Services {
		svcs = append(svcs, s.Provider+"/"+s.Service)
	}
	return fmt.Sprintf("service registry: %s/%s provides %s", m.Domain.Domain, m.Domain.Subdomain, strings.Join(svcs, ", "))
}

// printDirCounts lists how a filesystem's files fall by top directory, for an
// image none of whose files is singled out (DSP libraries, BT firmware).
func printDirCounts(entries []modem.Entry, indent string) {
	count := map[string]int{}
	var dirs []string
	for _, e := range entries {
		d, _, ok := strings.Cut(strings.TrimPrefix(e.Path, "/"), "/")
		if !ok {
			d = "."
		}
		if count[d] == 0 {
			dirs = append(dirs, d)
		}
		count[d]++
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		fmt.Printf("%s%-24s %d files\n", indent, d+"/", count[d])
	}
}

// typeLabel gives a short human label for a detected kind (with Moto/ext hints).
func typeLabel(name string, head []byte) string {
	switch filetype.Detect(head) {
	case filetype.AndroidBoot:
		return "Android boot"
	case filetype.AndroidVendorBoot:
		return "Android vendor_boot"
	case filetype.VBMeta:
		return "AVB vbmeta"
	case filetype.DTBOTable, filetype.DeviceTree:
		return "device tree"
	case filetype.SparseImage:
		return "android-sparse"
	case filetype.Ext4:
		return "ext4"
	case filetype.FAT:
		return "FAT"
	case filetype.EROFS:
		return "erofs"
	case filetype.GPT:
		return "gpt"
	case filetype.SingleNLonely:
		return "SINGLE_N_LONELY"
	case filetype.QDB:
		return "Qualcomm Q6 db"
	case filetype.ELF:
		return "ELF"
	case filetype.OTAPayload:
		return "OTA payload"
	case filetype.Tar:
		return "tar"
	case filetype.LZ4:
		return "lz4"
	case filetype.PE:
		return "PE executable"
	case filetype.F2FS:
		return "f2fs"
	case filetype.JPEG:
		return "JPEG"
	case filetype.PNG:
		return "PNG"
	case filetype.WinHelp:
		return "WinHelp"
	case filetype.TypeLib:
		return "COM type library"
	case filetype.SQLite:
		return "SQLite"
	case filetype.Gzip:
		return "gzip"
	case filetype.Zip:
		return "zip"
	}
	if lp.IsSuper(head) {
		return "super metadata"
	}
	if info, ok := vendor.RecognizeArtifact(activeCatalog(), name, head); ok {
		return info.Label
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".nvm":
		return "SLCF subsidy"
	case ".xml":
		return "XML manifest"
	case ".txt":
		return "text"
	case ".png":
		return "PNG"
	case ".dat":
		return "data"
	}
	if ok, script := filetype.Text(head); script {
		return "script"
	} else if ok {
		return "text"
	}
	if highEntropy(head) {
		if l, ok := decryptLabel(head); ok {
			return l
		}
		return "encrypted or compressed"
	}
	return "unknown"
}

// highEntropy reports bytes as close to uniform as ciphertext or compressed
// data, and enough of them to tell: what is left once no format is seen.
func highEntropy(b []byte) bool {
	if len(b) < 1024 {
		return false
	}
	var count [256]int
	for _, c := range b {
		count[c]++
	}
	h := 0.0
	for _, n := range count {
		if n > 0 {
			p := float64(n) / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	// A sample of n bytes from a uniform source falls short of 8 bits by
	// about 255/(2n ln 2); allow a little more.
	return h > 8-255/(float64(len(b))*math.Ln2)-0.05
}

// summarize returns a short " — detail" for a node when full data is available;
// with data==nil (head only) it stays quiet unless the head alone suffices.
func summarize(head, data []byte) string {
	switch filetype.Detect(head) {
	case filetype.ELF:
		if data == nil {
			return ""
		}
		if info, err := bootelf.Analyze(data); err == nil {
			s := " — " + info.Arch
			if info.QCVersion != "" {
				s += ", " + info.QCVersion // e.g. TZ.XF.5.1.6-…, XBL.…, ABL.…
			}
			if id := info.Identity; id != nil {
				s += ", " + secbootAnnotate(id)
			}
			return s
		}
	case filetype.VBMeta:
		if h, err := avb.Parse(head); err == nil {
			s := fmt.Sprintf(" — libavb %d.%d, %s", h.VersionMajor, h.VersionMinor, h.Algorithm)
			if data != nil {
				if m, ok := vendor.ParseHABMeta(data); ok {
					s += fmt.Sprintf(", HAB %s/%s", m.Codename, m.CIDHex())
				}
			}
			return s
		}
	case filetype.AndroidBoot, filetype.AndroidVendorBoot:
		if data == nil {
			return ""
		}
		if img, err := bootimg.Parse(data); err == nil {
			return fmt.Sprintf(" — v%d, %d section(s)", img.HeaderVersion, len(img.Sections))
		}
	case filetype.DTBOTable, filetype.DeviceTree:
		if data == nil {
			return ""
		}
		if t, err := dtbo.Parse(data); err == nil {
			return fmt.Sprintf(" — %d device tree(s)", len(t.Entries))
		}
	case filetype.SparseImage:
		if data == nil {
			return ""
		}
		// Read the expanded size from the header and detect the inner FS from a
		// small prefix — never expand the whole image (a 45 GiB userdata hangs).
		if size, err := sparse.OutputSize(data); err == nil {
			inner := filetype.Unknown
			if pre, err := sparse.Prefix(data, 64<<10); err == nil {
				inner = filetype.Detect(pre)
			}
			return fmt.Sprintf(" — expands to %s (%s)", humanBytes(size), inner)
		}
	case filetype.Ext4, filetype.FAT:
		if data == nil {
			return ""
		}
		if entries, err := modem.List(data); err == nil {
			return fmt.Sprintf(" — %d files", len(entries))
		}
	case filetype.EROFS:
		if data == nil {
			return ""
		}
		return erofsSummary(data)
	case filetype.GPT:
		if data == nil {
			return ""
		}
		if t, err := qfil.ParseGPT(data); err == nil {
			return fmt.Sprintf(" — %d partitions", len(t.Partitions))
		}
	case filetype.SingleNLonely:
		if data == nil {
			return ""
		}
		if recs, err := blankflash.Parse(data); err == nil {
			return fmt.Sprintf(" — %d records", len(recs)-1)
		}
	}
	// Vendor-specific formats with no neutral magic (CID, MotoLogo, SLCF).
	if info, ok := vendor.RecognizeArtifact(activeCatalog(), "", head); ok && info.Detail != "" {
		return " — " + info.Detail
	}
	return ""
}

func reconVBMeta(path string) error {
	data, err := infile.ReadFile(path)
	if err != nil {
		return err
	}
	if img, err := avb.ParseImage(data); err == nil {
		h := img.Header
		fmt.Printf("  AVB:     libavb %d.%d, %s, rollback %d (loc %d), flags 0x%x\n",
			h.VersionMajor, h.VersionMinor, h.Algorithm, h.RollbackIndex, img.RollbackIndexLocation, h.Flags)
		if h.Release != "" {
			fmt.Printf("  Signed by: %s\n", h.Release)
		}
		if img.PublicKeySHA256 != "" {
			fmt.Printf("  AVB key:  sha256 %s\n", img.PublicKeySHA256)
		}
		printAVBDescriptors(img)
	}
	if m, ok := vendor.ParseHABMeta(data); ok {
		fmt.Printf("  HAB_META: codename %s, base CID %s (signing value, not carrier CID)\n", m.Codename, m.CIDHex())
	}
	return nil
}

// printAVBDescriptors renders the verified-boot manifest: which partitions AVB
// protects (hash/hashtree), the partitions chained to a separate key, and the
// per-partition os_version / security_patch the vbmeta signs over — the
// authoritative source for the release each partition was built at.
func printAVBDescriptors(img *avb.Image) {
	var protected, chains []string
	osv := map[string]string{}
	patch := map[string]string{}
	for _, d := range img.Descriptors {
		switch d.Kind {
		case "hash":
			protected = append(protected, fmt.Sprintf("%s (%s)", d.Partition, humanBytes(int64(d.ImageSize))))
		case "hashtree":
			protected = append(protected, d.Partition+" (verity)")
		case "chain":
			chains = append(chains, fmt.Sprintf("%s → key sha256 %s (rollback loc %d)", d.Partition, short(d.ChainKeySHA256), d.ChainRollbackLoc))
		case "property":
			if p, ok := strings.CutPrefix(d.Key, "com.android.build."); ok {
				if part, ok := strings.CutSuffix(p, ".os_version"); ok {
					osv[part] = d.Value
				} else if part, ok := strings.CutSuffix(p, ".security_patch"); ok {
					patch[part] = d.Value
				}
			}
		}
	}
	for _, c := range chains {
		fmt.Printf("  AVB chain: %s\n", c)
	}
	if len(protected) > 0 {
		fmt.Printf("  Protects: %s\n", strings.Join(protected, ", "))
	}
	// The os_version per partition is the signed record of the release split.
	if rels := distinctValues(osv); len(rels) > 1 {
		fmt.Printf("  OS version: split — %s\n", partitionsByValue(osv))
	} else if len(rels) == 1 {
		fmt.Printf("  OS version: %s (all partitions)\n", rels[0])
	}
	if p := distinctValues(patch); len(p) >= 1 {
		fmt.Printf("  Patch level: %s\n", strings.Join(p, ", "))
	}
}

// distinctValues returns the sorted unique values of a map.
func distinctValues(m map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range m {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// partitionsByValue groups partition names by their value, e.g.
// "14: product,system · 13: boot,vendor".
func partitionsByValue(m map[string]string) string {
	byVal := map[string][]string{}
	for part, v := range m {
		byVal[v] = append(byVal[v], part)
	}
	vals := distinctValues(m)
	// Show highest (newest) first.
	sort.Sort(sort.Reverse(sort.StringSlice(vals)))
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		ps := byVal[v]
		sort.Strings(ps)
		parts = append(parts, v+": "+strings.Join(ps, ","))
	}
	return strings.Join(parts, " · ")
}

func reconContainer(path string) error {
	data, err := infile.ReadFile(path)
	if err != nil {
		return err
	}
	recs, err := blankflash.Parse(data)
	if err != nil {
		return err
	}
	fmt.Printf("  SINGLE_N_LONELY container, %d record(s):\n", len(recs)-1) // minus trailer
	hasModem := false
	for _, r := range recs {
		if r.Name == blankflash.Trailer || r.Name == "" {
			continue
		}
		fmt.Printf("    %-16s %s\n", r.Name, humanBytes(int64(len(r.Data))))
		if r.Name == "NON-HLOS.bin" || r.Name == "modem" {
			hasModem = true
		}
	}
	if hasModem {
		if entries, err := modem.List(data); err == nil {
			fmt.Printf("  Modem filesystem: %d files (see `unbrick ls`)\n", len(entries))
		}
		printModemCarrier(data, "  ")
	}
	return nil
}

func reconContentFallback(path string, head []byte, bag *facts.Bag) error {
	// Vendor-specific content with no neutral magic (CID image, MotoLogo, SLCF).
	if info, ok := vendor.RecognizeArtifact(activeCatalog(), filepath.Base(path), head); ok {
		line := "  " + info.Label
		if info.Detail != "" {
			line += " — " + info.Detail
		}
		fmt.Println(line)
		return nil
	}
	// An empty subsidy default (.nvm) has no content to recognize.
	if strings.HasSuffix(strings.ToLower(path), ".nvm") {
		fmt.Println("  Motorola SLCF subsidy config: no lock (retail default)")
		return nil
	}
	// No artifact recognizer claimed it, but a fact recognizer may have: say what
	// the file turned out to be rather than that nothing read it.
	if srcs := recognizedSources(bag); len(srcs) > 0 {
		fmt.Printf("  Recognized: %s\n", strings.Join(srcs, ", "))
		return nil
	}
	fmt.Printf("  (no deeper recognizer; try `inspect` for ELF/blankflash detail)\n")
	return nil
}

// recognizedSources names the leaf sources ingestion found in the file itself,
// dropping the two that describe the run rather than the file.
func recognizedSources(bag *facts.Bag) []string {
	var out []string
	for _, n := range bag.Names() {
		if !strings.HasPrefix(n, "source:") ||
			n == facts.SourceCatalog.Name() || n == facts.SourceStockZip.Name() {
			continue
		}
		out = append(out, strings.TrimPrefix(n, "source:"))
	}
	return out
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// erofsSummary is the file count and the build fingerprint of an erofs image
// held in memory, as the large-image path gives for one read by range.
func erofsSummary(data []byte) string {
	ra := bytes.NewReader(data)
	n := carve.FromReaderAt("", ra, int64(len(data)))
	_, kids, err := n.Children()
	if err != nil || len(kids) == 0 {
		return ""
	}
	s := fmt.Sprintf(" — %d files", len(kids))
	if fp := partitionFingerprint(ra, int64(len(data)), data); fp != "" {
		s += ", " + fp
	}
	return s
}
