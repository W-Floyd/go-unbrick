package main

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/W-Floyd/go-unbrick/internal/adb"
	"github.com/W-Floyd/go-unbrick/internal/avb"
	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/bootelf"
	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/devcfg"
	"github.com/W-Floyd/go-unbrick/internal/dtbo"
	"github.com/W-Floyd/go-unbrick/internal/edl"
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/fastboot"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
	"github.com/W-Floyd/go-unbrick/internal/linuxdev"
	"github.com/W-Floyd/go-unbrick/internal/lp"
	"github.com/W-Floyd/go-unbrick/internal/mcfg"
	"github.com/W-Floyd/go-unbrick/internal/modem"
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
	var carve, why string
	var verify, learn bool
	c := &cobra.Command{
		Use:   "recon <file>",
		Short: "identify any file (stock zip, image, container, config) and report what it is",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reconDepth = depth
			reconCarveDir = carve
			reconWhy = why
			reconVerify = verify
			reconLearn = learn
			return runFileRecon(args[0])
		},
	}
	c.Flags().IntVar(&depth, "depth", 4, "how many container levels to cascade into (zip → radio → NON-HLOS → ext4)")
	c.Flags().StringVar(&carve, "carve", "", "write every unique embedded cert (PEM+DER) and key (PEM) to this directory")
	c.Flags().StringVar(&why, "why", "", "explain how one fact was derived (e.g. --why cid), with every corroborating source")
	c.Flags().BoolVar(&verify, "verify", false, "run redundant derivations for their cross-check value, even the expensive ones")
	c.Flags().BoolVar(&learn, "learn", false, "contribute this image's raw, non-identifying facts to the library knowledge store")
	return c
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
	return facts.New(append(ps, vendor.Providers()...), vendor.Checks())
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
func reconIngest(path string) (*facts.Bag, []facts.Finding) {
	bag := facts.NewBag()
	if cat := activeCatalog(); cat != nil {
		facts.Set(bag, facts.SourceCatalog, cat,
			facts.Provenance{Source: "catalog", Authority: facts.Reference})
	}
	bar := newBar()
	defer bar.Clear()
	if err := imgfacts.Ingest(bag, reconRecognizers(), path, bar); err != nil {
		return bag, []facts.Finding{{Severity: facts.Warn, Message: "reading " + filepath.Base(path) + ": " + err.Error()}}
	}
	res := reconGraph().ResolveAll(bag, facts.Options{Verify: reconVerify})
	return bag, res.Findings
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
	for _, line := range identityFactLines(b) {
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
	if v, ok := facts.Get(b, facts.SecurityPatch); ok {
		add("Patch level: %s", v)
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
		enf := "not enforced"
		if v, _ := facts.Get(b, facts.EnforceAntiRollback); v {
			enf = "enforced"
		}
		if bumped := facts.Bumped(table); len(bumped) == 0 {
			add("Anti-rollback: %s, all %d images at 0x00 (baseline)", enf, len(table))
		} else {
			add("Anti-rollback: %s, bumped: %s", enf, strings.Join(bumped, ", "))
		}
	}
	if ids, ok := facts.Get(b, imgfacts.OTACerts); ok {
		add("OTA key: %s", b.Show(imgfacts.OTACerts.Name(), ids))
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
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	head := make([]byte, 8192) // enough for a 4K-sector GPT header at offset 4096
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	fi, _ := f.Stat()
	f.Close()

	kind := filetype.Detect(head)
	fmt.Printf("%s\n", filepath.Base(path))
	if fi != nil {
		fmt.Printf("  Size:  %s\n", humanBytes(fi.Size()))
	}
	fmt.Printf("  Type:  %s\n", kind)

	resetCerts() // keys/certs are gathered during the walk, printed deduped after
	// Resolve before rendering: the identity lines a package prints are the
	// planner's answers, and the judgments about them print after everything else.
	bag, findings := reconIngest(path)
	var rerr error
	switch kind {
	case filetype.Zip:
		rerr = reconZip(path, bag)
	case filetype.VBMeta:
		rerr = reconVBMeta(path)
	case filetype.SingleNLonely:
		rerr = reconContainer(path)
	case filetype.AndroidBoot, filetype.AndroidVendorBoot:
		rerr = reconBootImage(path)
	case filetype.ELF:
		rerr = reconELF(path)
	case filetype.GPT:
		rerr = reconGPT(path)
	case filetype.DTBOTable, filetype.DeviceTree:
		rerr = reconDTBO(path)
	case filetype.SparseImage:
		rerr = reconSparse(path)
	case filetype.Ext4, filetype.FAT:
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
			learnFromRecon(bag, "", nil) // no unit in hand, so no serial to stitch by
		} else {
			fmt.Printf("\n  %s no codename in this artifact — a lone component is not device knowledge; not learned\n", cWarn("[i]"))
		}
	}
	printFindings(findings)
	return rerr
}

func reconBootImage(path string) error {
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	raw, err := sparse.Decode(data)
	if err != nil {
		return err
	}
	fmt.Printf("  Sparse:  expands to %s; inner: %s\n", humanBytes(int64(len(raw))), filetype.Detect(raw))
	return nil
}

func reconExt4(path string) error {
	data, err := os.ReadFile(path)
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
			fmt.Printf("    … (+%d more; try `modem ls`)\n", len(entries)-6)
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

func reconZip(path string, bag *facts.Bag) error {
	// Which vendor's package is this?
	vendorID := ""
	if drv, ok := vendor.Detect(path); ok {
		vendorID = drv.ID()
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
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	fmt.Printf("  Contents (%d members):\n", len(members))
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
		switch {
		case kind == filetype.OTAPayload:
			bar.Clear()
			printPayload(path, base, int64(m.Size), "    ")
		case int64(m.Size) > maxCascadeRead:
			// Don't expand anything too big; label it and move on.
			bar.Clear()
			fmt.Printf("    %-26s [%s]  %s (not expanded)\n", base, typeLabel(base, m.Head), humanBytes(int64(m.Size)))
		case !isContainer(kind):
			bar.Clear()
			fmt.Printf("    %-26s [%s]%s\n", base, typeLabel(base, m.Head), summarize(m.Head, nil))
		default:
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
			bar.Clear()
			fmt.Printf("%s  %-24s [%s]  %s (not expanded)\n", indent, pn, typeLabel(pn, head), humanBytes(psize))
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
		if raw, err := sparse.Decode(data); err == nil {
			cascade("(unsparsed)", raw, indent+"  ", depth-1)
		}
	case filetype.Ext4, filetype.FAT:
		if entries, err := modem.List(data); err == nil {
			// Subsystem firmware (adsp, cdsp, modem, …) ships as PIL splits; each
			// is shown joined, so its build and secboot identity read through.
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
			}
			shown := 0
			for _, e := range entries {
				// Only surface the interesting leaves (signed images, PD maps, configs).
				if !ext4Notable(e.Path) || strings.EqualFold(filepath.Ext(e.Path), ".mdt") {
					continue
				}
				if shown >= 8 {
					fmt.Printf("%s  … (+more; `modem ls`)\n", indent)
					break
				}
				line := fmt.Sprintf("%s  %-24s %s", indent, filepath.Base(e.Path), humanBytes(int64(e.Size)))
				if note := mcfgNote(data, e.Path); note != "" {
					line += " — " + note
				}
				fmt.Println(line)
				shown++
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
	return strings.HasSuffix(b, ".jsn") || strings.HasSuffix(b, ".mbn") ||
		b == "modem.mdt" || strings.HasPrefix(b, "mcfg") || strings.HasSuffix(b, ".qdb")
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
	}
	if info, ok := vendor.RecognizeArtifact(activeCatalog(), head); ok {
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
	return "unknown"
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
		if raw, err := sparse.Decode(data); err == nil {
			return fmt.Sprintf(" — expands to %s (%s)", humanBytes(int64(len(raw))), filetype.Detect(raw))
		}
	case filetype.Ext4, filetype.FAT:
		if data == nil {
			return ""
		}
		if entries, err := modem.List(data); err == nil {
			return fmt.Sprintf(" — %d files", len(entries))
		}
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
	if info, ok := vendor.RecognizeArtifact(activeCatalog(), head); ok && info.Detail != "" {
		return " — " + info.Detail
	}
	return ""
}

func reconVBMeta(path string) error {
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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
			fmt.Printf("  Modem filesystem: %d files (try `modem ls`)\n", len(entries))
		}
		printModemCarrier(data, "  ")
	}
	return nil
}

func reconContentFallback(path string, head []byte, bag *facts.Bag) error {
	// Vendor-specific content with no neutral magic (CID image, MotoLogo, SLCF).
	if info, ok := vendor.RecognizeArtifact(activeCatalog(), head); ok {
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
