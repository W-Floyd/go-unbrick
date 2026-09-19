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

	"go-unbrick/internal/avb"
	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/bootelf"
	"go-unbrick/internal/bootimg"
	"go-unbrick/internal/cid"
	"go-unbrick/internal/dtbo"
	"go-unbrick/internal/filetype"
	"go-unbrick/internal/lp"
	"go-unbrick/internal/modem"
	"go-unbrick/internal/qfil"
	"go-unbrick/internal/rsakey"
	"go-unbrick/internal/secboot"
	"go-unbrick/internal/sparse"
	"go-unbrick/internal/srcfile"
	"go-unbrick/internal/vendor"
)

// newReconCmd is the file counterpart to `fastboot recon`: hand it any file and
// it identifies the format and surfaces what it can. Neutral format detection is
// generic (internal/filetype); vendor meaning (which OEM, CID, subsidy) is
// resolved through the vendor seam and vendor parsers.
func newReconCmd() *cobra.Command {
	var depth int
	var carve string
	c := &cobra.Command{
		Use:   "recon <file>",
		Short: "identify any file (stock zip, image, container, config) and report what it is",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reconDepth = depth
			reconCarveDir = carve
			return runFileRecon(args[0])
		},
	}
	c.Flags().IntVar(&depth, "depth", 4, "how many container levels to cascade into (zip → radio → NON-HLOS → ext4)")
	c.Flags().StringVar(&carve, "carve", "", "write every unique embedded cert (PEM+DER) and key (PEM) to this directory")
	return c
}

// reconDepth bounds how deep the cascade recurses into nested containers.
var reconDepth = 4

// reconCarveDir, when set, is where extracted certs/keys are written (--carve).
var reconCarveDir string

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
	var rerr error
	switch kind {
	case filetype.Zip:
		rerr = reconZip(path)
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
	case filetype.Ext4:
		rerr = reconExt4(path)
	default:
		// Vendor-specific content with no neutral magic: Motorola CID image or SLCF.
		rerr = reconContentFallback(path, head)
	}
	printCollectedKeys()
	if reconCarveDir != "" && len(certAccum.order) > 0 {
		if err := carveKeys(reconCarveDir); err != nil {
			return err
		}
	}
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
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := bootelf.Analyze(data)
	if err != nil {
		return err
	}
	fmt.Printf("  ELF:     %d-bit %s %s, %d segments\n", info.Class, info.Endian, info.Arch, len(info.Segments))
	if info.QCVersion != "" {
		fmt.Printf("  Build:   %s", info.QCVersion)
		if info.TargetSoC != "" {
			fmt.Printf("  (%s)", info.TargetSoC)
		}
		fmt.Println()
	}
	if id := info.Identity; id != nil {
		fmt.Printf("  Secboot: %s HW_ID=%s key=RSA-%d\n", secbootAnnotate(id), id.HWID, id.KeyBits)
	}
	collectKeys(data)
	return nil
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
	fmt.Printf("  ext4:    %d files\n", len(entries))
	for i, e := range entries {
		if i >= 6 {
			fmt.Printf("    … (+%d more; try `modem ls`)\n", len(entries)-6)
			break
		}
		fmt.Printf("    %-28s %s\n", e.Path, humanBytes(int64(e.Size)))
	}
	return nil
}

func reconZip(path string) error {
	// Which vendor's package is this?
	vendorID := ""
	if drv, ok := vendor.Detect(path); ok {
		vendorID = drv.ID()
		fmt.Printf("  Vendor: %s\n", vendorID)
	}
	if _, pkg, ok := vendor.DetectStock(path); ok && pkg != nil {
		fmt.Printf("  Kind:   stock firmware package\n")
	}
	// Authoritative target CID comes from flashfile.xml (cid_value), not the vbmeta
	// HAB_META CID — that one is a signing/base value, constant across a device's
	// carrier variants (e.g. HAB_META says 0x0032 even in a 0x0033 package).
	codename := ""
	if _, data, err := srcfile.Open(path, "vbmeta.img"); err == nil {
		if m, ok := cid.ParseHABMeta(data); ok {
			codename = m.Codename
		}
	}
	if _, data, err := srcfile.Open(path, "flashfile.xml"); err == nil {
		ff := vendor.ParseFlashfile(data)
		if ff.CIDValue != "" {
			line := "  Target: CID " + ff.CIDValue
			if codename != "" {
				line = fmt.Sprintf("  Target: codename %s, CID %s", codename, ff.CIDValue)
			}
			if name := activeCatalog().CarrierIDName(vendorID, ff.CIDValue); name != "" {
				line += " — " + name
			} else if ref := activeCatalog().CarrierIDReference(vendorID, ff.CIDValue); ref != "" {
				line += " — " + ref
			}
			fmt.Println(line)
		}
		if ff.SoftwareVersion != "" {
			fmt.Printf("  Build:  %s\n", ff.SoftwareVersion)
		}
	}
	// Subsidy lock from the slcf member.
	if names, _ := srcfile.Glob(path, "slcf_*.nvm"); len(names) > 0 {
		if _, data, err := srcfile.Open(path, names...); err == nil {
			if cfg, err := vendor.ParseSLCF(data); err == nil {
				if cfg.Locked {
					nets := make([]string, 0, len(cfg.PLMNs))
					for _, p := range cfg.PLMNs {
						nets = append(nets, p.String())
					}
					fmt.Printf("  Subsidy: LOCKED, %d-digit key, networks: %s\n", cfg.ControlKeyDigits, strings.Join(nets, ", "))
				} else {
					fmt.Printf("  Subsidy: none (retail)\n")
				}
			}
		}
	}
	// Cascade through the members, descending into nested containers.
	members, err := srcfile.Members(path, 8192)
	if err != nil || len(members) == 0 {
		return err
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	fmt.Printf("  Contents (%d members):\n", len(members))
	var chunkCount int
	var chunkBytes int64
	for _, m := range members {
		base := filepath.Base(m.Name)
		kind := filetype.Detect(m.Head)
		// Collapse the super sparsechunk fragments into one aggregate line.
		if strings.Contains(base, "sparsechunk") {
			chunkCount++
			chunkBytes += int64(m.Size)
			continue
		}
		// Don't expand anything too big; label it and move on.
		if int64(m.Size) > maxCascadeRead {
			fmt.Printf("    %-26s [%s]  %s (not expanded)\n", base, typeLabel(base, m.Head), humanBytes(int64(m.Size)))
			continue
		}
		if !isContainer(kind) {
			fmt.Printf("    %-26s [%s]%s\n", base, typeLabel(base, m.Head), summarize(m.Head, nil))
			continue
		}
		_, data, err := srcfile.Open(path, base)
		if err != nil {
			fmt.Printf("    %-26s [%s]  (unreadable)\n", base, typeLabel(base, m.Head))
			continue
		}
		cascade(base, data, "    ", reconDepth)
	}
	if chunkCount > 0 {
		fmt.Printf("    %-26s [android-sparse]  %d fragments, %s (super: dynamic partitions)\n",
			"super.img_sparsechunk.*", chunkCount, humanBytes(chunkBytes))
		printSuperMap(path, "      ")
	}
	return nil
}

// printSuperMap reads super's logical-partition map from just the first chunk
// (the liblp metadata lives at the front), so it never expands the whole image.
func printSuperMap(path, indent string) {
	_, chunk0, err := srcfile.Open(path, "super.img_sparsechunk.0")
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
	sw := fmt.Sprintf("SW_ID=%d", id.SWID)
	if n := activeCatalog().SWIDName(id.SWID); n != "" {
		sw += " (" + n + ")"
	}
	return oem + " " + jtag + " " + sw
}

// isContainer reports whether a kind holds nested artifacts worth recursing into.
func isContainer(k filetype.Kind) bool {
	switch k {
	case filetype.SingleNLonely, filetype.SparseImage, filetype.Ext4,
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
			for _, p := range t.Partitions {
				fmt.Printf("%s  %-22s %s\n", indent, p.Name, humanBytes(int64(p.NumSectors*uint64(t.SectorSize))))
			}
		}
	case filetype.AndroidBoot, filetype.AndroidVendorBoot:
		descendBootRamdisk(data, indent+"  ")
	case filetype.SparseImage:
		if raw, err := sparse.Decode(data); err == nil {
			cascade("(unsparsed)", raw, indent+"  ", depth-1)
		}
	case filetype.Ext4:
		if entries, err := modem.List(data); err == nil {
			shown := 0
			for _, e := range entries {
				// Only surface the interesting leaves (signed images, PD maps, configs).
				if !ext4Notable(e.Path) {
					continue
				}
				if shown >= 8 {
					fmt.Printf("%s  … (+more; `modem ls`)\n", indent)
					break
				}
				fmt.Printf("%s  %-24s %s\n", indent, filepath.Base(e.Path), humanBytes(int64(e.Size)))
				shown++
			}
		}
	}
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
	}
	if len(head) >= 8 && string(head[:8]) == "MotoLogo" {
		return "MotoLogo"
	}
	if _, ok := cid.Version(head); ok {
		return "Motorola CID"
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
			if id := info.Identity; id != nil {
				s += ", " + secbootAnnotate(id)
			}
			return s
		}
	case filetype.VBMeta:
		if h, err := avb.Parse(head); err == nil {
			s := fmt.Sprintf(" — libavb %d.%d, %s", h.VersionMajor, h.VersionMinor, h.Algorithm)
			if data != nil {
				if m, ok := cid.ParseHABMeta(data); ok {
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
	case filetype.Ext4:
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
	return ""
}

func reconVBMeta(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if h, err := avb.Parse(data); err == nil {
		fmt.Printf("  AVB:     libavb %d.%d, %s, rollback %d, flags 0x%x\n",
			h.VersionMajor, h.VersionMinor, h.Algorithm, h.RollbackIndex, h.Flags)
		if h.Release != "" {
			fmt.Printf("  Signed by: %s\n", h.Release)
		}
	}
	if m, ok := cid.ParseHABMeta(data); ok {
		fmt.Printf("  HAB_META: codename %s, base CID %s (signing value, not carrier CID)\n", m.Codename, m.CIDHex())
	}
	return nil
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
	}
	return nil
}

func reconContentFallback(path string, head []byte) error {
	// Motorola CID partition image (magic 0x00F0).
	if v, ok := cid.Version(head); ok {
		fmt.Printf("  Motorola CID image, version %d", v)
		if cid.IsSigned(head) {
			fmt.Printf(" (signed, secure-production)")
		}
		fmt.Println()
		return nil
	}
	// SLCF subsidy config (.nvm): ASCII hex NV records.
	if strings.HasSuffix(strings.ToLower(path), ".nvm") || hasSLCFPrefix(head) {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cfg, err := vendor.ParseSLCF(data)
		if err == nil {
			if !cfg.Locked {
				fmt.Printf("  Motorola SLCF subsidy config: no lock (retail default)\n")
			} else {
				fmt.Printf("  Motorola SLCF subsidy config: LOCKED, %d-digit key, %d network(s)\n", cfg.ControlKeyDigits, len(cfg.PLMNs))
			}
			return nil
		}
	}
	fmt.Printf("  (no deeper recognizer; try `inspect` for ELF/blankflash detail)\n")
	return nil
}

func hasSLCFPrefix(head []byte) bool {
	return len(head) >= 4 && string(head[:4]) == "8021"
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
