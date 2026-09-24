// Package imgfacts holds the cross-vendor derivations over an image's bytes:
// what any signed ELF, any Android boot image or any vbmeta says about itself,
// whoever built it. Vendor-specific readings of the same bytes stay behind the
// vendor seam; what is here would be true of another OEM's image too.
package imgfacts

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"os"

	"go-unbrick/internal/avb"
	"go-unbrick/internal/bootelf"
	"go-unbrick/internal/bootimg"
	"go-unbrick/internal/facts"
	"go-unbrick/internal/filetype"
	"go-unbrick/internal/rsakey"
	"go-unbrick/internal/secboot"
	"go-unbrick/internal/srcfile"
)

// SourceBootImage is any Android boot/recovery/vendor_boot image — the form
// that may carry an otacerts.zip in its ramdisk. Unlike SourceImage it is set
// for members too, since a package's recovery.img is exactly where the OTA key
// lives; the providers that read it decline on the boot images that carry none.
var SourceBootImage = facts.Key[[]byte]("source:boot_image", facts.Fmt(facts.ByteLen))

// Recognizers returns the vendor-neutral recognizers: the formats any OEM's
// package may contain, identified by their magic rather than their name.
func Recognizers() []facts.Recognizer {
	return []facts.Recognizer{func(b *facts.Bag, f facts.File) []string {
		switch filetype.Detect(f.Data) {
		case filetype.VBMeta:
			facts.Set(b, facts.SourceVBMeta, f.Data,
				facts.Provenance{Source: f.From, Authority: facts.Attested})
			return []string{facts.SourceVBMeta.Name()}
		case filetype.AndroidBoot, filetype.AndroidVendorBoot:
			facts.Set(b, SourceBootImage, f.Data,
				facts.Provenance{Source: f.From, Authority: facts.Attested})
			return []string{SourceBootImage.Name()}
		case filetype.ELF:
			// A signed image is a fact about itself; a package full of them is not
			// one image, so inside a container this is left to the recon walk.
			if !f.Top {
				return nil
			}
			facts.Set(b, SourceImage, f.Data,
				facts.Provenance{Source: f.From, Authority: facts.Attested})
			return []string{SourceImage.Name()}
		}
		return nil
	}, recognizeGPT, recognizeOTAMetadata}
}

// SourceImage is one image's bytes: an ELF, a .mbn, an Android boot image.
// Whole-file, because every reading of it (the signature chain, the ramdisk,
// the build string) needs a different part.
var SourceImage = facts.Key[[]byte]("source:image", facts.Fmt(facts.ByteLen))

// Keys whose values are cert identities. Two facts, not one: the chain a signed
// image carries is the boot-time trust, the certs in recovery's otacerts.zip are
// what may sign an update. They differ by design, so they are separate facts.
var (
	BootCertChain = facts.Key[[]rsakey.Identity]("boot_cert_chain",
		facts.Eq(sameIdentities), facts.Fmt(showIdentities))
	OTACerts = facts.Key[[]rsakey.Identity]("ota_certs",
		facts.Eq(sameIdentities), facts.Fmt(showIdentities))
)

// Ingest offers a file, and everything inside it, to the recognizers: what a
// package yields is decided by looking at what it actually carries, not by
// asking it for member names we happen to know. Members too large to hold are
// skipped — nothing that names a device fits in a few kilobytes anyway.
// p, if non-nil, is stepped once per member read.
func Ingest(b *facts.Bag, rs []facts.Recognizer, path string, p Progress) error {
	base := filepath.Base(path)
	if fi, err := os.Stat(path); err == nil && fi.Size() <= maxTopRead && !fi.IsDir() {
		if data, err := os.ReadFile(path); err == nil {
			facts.Recognize(b, rs, facts.File{Name: base, Data: data, From: base, Top: true})
		}
	}
	if !srcfile.IsZip(path) {
		return nil
	}
	facts.Set(b, facts.SourceStockZip, path, facts.Provenance{Source: base, Authority: facts.Attested})
	// Read a head first, decide the budget from what the member is: a boot image
	// is the one large member worth reading in full, because the OTA key lives in
	// recovery's ramdisk and nothing smaller carries it. The bulk images (super,
	// the sparse chunks) stay past the cap — a manifest states their facts more
	// cheaply.
	members, err := srcfile.Members(path, 8192)
	if err != nil {
		return err
	}
	var read []srcfile.Member
	for _, m := range members {
		budget := int64(maxMemberRead)
		if isBootKind(m.Head) {
			budget = maxBootRead
		}
		if int64(m.Size) <= budget {
			read = append(read, m)
		}
	}
	if p != nil {
		p.Begin(len(read))
	}
	for _, m := range read {
		name := filepath.Base(m.Name)
		if p != nil {
			p.Describe("reading " + name)
		}
		if _, data, err := srcfile.Open(path, name); err == nil {
			facts.Recognize(b, rs, facts.File{Name: name, Data: data, From: base + " " + name})
		}
		if p != nil {
			p.Advance()
		}
	}
	return nil
}

// Progress is stepped as ingestion reads members: Begin with the count, then
// Describe and Advance per member.
type Progress interface {
	Begin(total int)
	Describe(label string)
	Advance()
}

func isBootKind(head []byte) bool {
	switch filetype.Detect(head) {
	case filetype.AndroidBoot, filetype.AndroidVendorBoot:
		return true
	}
	return false
}

// What ingestion will hold in memory: the whole of the file under examination,
// any member small enough that reading it costs nothing, and — a step up — a
// boot image, whose ramdisk is where the OTA key hides. The bulk images (super,
// the sparse chunks) are past all three, and carry no fact a manifest does not
// state more cheaply.
const (
	maxTopRead          = 256 << 20
	maxMemberRead       = 8 << 20
	maxBootRead   int64 = 128 << 20
)

// FactProviders returns the vendor-neutral image derivations.
func FactProviders() []facts.Provider {
	return append(otaProviders(), []facts.Provider{
		abFromGPT,
		// Reading a whole image costs more than picking a field out of one already
		// parsed, which is what keeps a chain that starts from a package member
		// cheaper than one that starts from an image.
		facts.Rule{
			Out: BootCertChain.Name(), In: []string{SourceImage.Name()}, Price: 5, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				data, ok := facts.Get(b, SourceImage)
				if !ok {
					return false, nil
				}
				ids := rsakey.Scan(data).Identities()
				if len(ids) == 0 {
					return false, nil
				}
				facts.Set(b, BootCertChain, ids, facts.Provenance{
					Source: "embedded signing chain (rsakey scan)", Authority: facts.Attested})
				return true, nil
			},
		},
		// The secure-boot identity a signed image is bound to. On a device read
		// over EDL this meets the fused values Sahara reported, and a mismatch is
		// an image the PBL will refuse.
		secbootRule(facts.JTAGID, "cert HW_ID", func(id *secboot.Identity) string {
			if id.JTAGID == "00000000" {
				return "" // not bound to a part
			}
			return strings.ToUpper(id.JTAGID)
		}),
		secbootRule(facts.OEMID, "cert OEM_ID", func(id *secboot.Identity) string { return strings.ToUpper(id.OEMID) }),
		// Both digests, since which one a chip fuses is unknown here; RootKeyHash
		// compares only same-length values, so the pair never conflicts itself.
		secbootRule(facts.RootKeyHash, "root cert SHA-256", func(id *secboot.Identity) string { return id.RootSHA256 }),
		secbootRule(facts.RootKeyHash, "root cert SHA-384", func(id *secboot.Identity) string { return id.RootSHA384 }),
		facts.Rule{
			Out: OTACerts.Name(), In: []string{SourceBootImage.Name()}, Price: 5, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				// Try every boot image; only the one carrying otacerts (recovery)
				// yields, the rest decline. Merge across any that do.
				var all []rsakey.Identity
				for _, data := range facts.GetAll(b, SourceBootImage) {
					all = append(all, otaCerts(data)...)
				}
				if len(all) == 0 {
					return false, nil
				}
				facts.Set(b, OTACerts, all, facts.Provenance{
					Source: "recovery otacerts.zip", Authority: facts.Attested})
				return true, nil
			},
		},
		// A boot/recovery image's ramdisk carries prop.default, which states the
		// security-patch level. It also carries a ro.system.build.fingerprint, but
		// that is the ramdisk's snapshot of it, which for Motorola is stale (a
		// placeholder release, e.g. fogona:13) — the true system fingerprint is the
		// Motorola System Image identity (device=msi) in the system partition's own
		// build.prop, read from super separately. So only the patch is taken here.
		facts.Rule{
			Out: facts.SecurityPatch.Name(), In: []string{SourceBootImage.Name()}, Price: 5, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				for _, data := range facts.GetAll(b, SourceBootImage) {
					p := buildProps(data)
					if v := p["ro.build.version.security_patch"]; v != "" {
						facts.Set(b, facts.SecurityPatch, v, facts.Provenance{Source: "prop.default", Authority: facts.Attested})
						return true, nil
					}
				}
				return false, nil
			},
		},

		// The vbmeta signing key and rollback index — the verified-boot root and
		// anti-rollback floor. Both vbmeta partitions carry the same top key, so
		// two members corroborate rather than conflict.
		facts.Rule{
			Out: facts.AVBKey.Name(), In: []string{facts.SourceVBMeta.Name()}, Price: 1, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				set := false
				for _, data := range facts.GetAll(b, facts.SourceVBMeta) {
					img, err := avb.ParseImage(data)
					if err != nil || img.PublicKeySHA256 == "" {
						continue
					}
					facts.Set(b, facts.AVBKey, img.PublicKeySHA256, facts.Provenance{Source: "vbmeta AVB pubkey", Authority: facts.Attested})
					facts.Set(b, facts.AVBRollbackIndex, int(img.RollbackIndex), facts.Provenance{Source: "vbmeta rollback_index", Authority: facts.Attested})
					set = true
				}
				return set, nil
			},
		},

		// A Qualcomm boot image names the SoC it was built for, either in its
		// QC_IMAGE_VERSION_STRING or through the JTAG id in its signature. The
		// value is the catalog's marketing spelling of that silicon (bootelf
		// resolves it), so SourceCatalog is a declared input — which also marks
		// the fact as our interpretation, not a raw read, for learning.
		facts.Rule{
			Out: facts.SoC.Name(), In: []string{SourceImage.Name(), facts.SourceCatalog.Name()}, Price: 5, Level: facts.Derived,
			Fn: func(b *facts.Bag) (bool, error) {
				data, ok := facts.Get(b, SourceImage)
				if !ok {
					return false, nil
				}
				info, err := bootelf.Analyze(data)
				if err != nil || info.TargetSoC == "" {
					return false, nil
				}
				facts.Set(b, facts.SoC, info.TargetSoC, facts.Provenance{
					Source: "ELF " + strings.TrimSpace(info.QCVersion), Authority: facts.Derived})
				return true, nil
			},
		},
	}...)
}

// secbootRule reads one field of the secure-boot identity of every signed image
// in the Bag. Images signed for one device agree; one that does not is exactly
// what the cross-check is for.
func secbootRule(out facts.Fact[string], source string, pick func(*secboot.Identity) string) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{SourceImage.Name()}, Price: 5, Level: facts.Attested,
		Fn: func(b *facts.Bag) (bool, error) {
			set := false
			for _, data := range facts.GetAll(b, SourceImage) {
				id, err := secboot.FromELF(data)
				if err != nil {
					continue
				}
				if v := pick(id); v != "" {
					facts.Set(b, out, v, facts.Provenance{Source: "signed image " + source, Authority: facts.Attested})
					set = true
				}
			}
			return set, nil
		},
	}
}

// buildProps parses the key=value build properties out of a boot image's
// ramdisk (prop.default / *.prop). Comment and blank lines are skipped. Returns
// nil if the image has no such file.
func buildProps(data []byte) map[string]string {
	img, err := bootimg.Parse(data)
	if err != nil {
		return nil
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
			if base != "prop.default" && base != "build.prop" && base != "default.prop" {
				continue
			}
			props := map[string]string{}
			for _, line := range strings.Split(string(e.Data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				k, v, ok := strings.Cut(line, "=")
				if ok && props[k] == "" {
					props[k] = v
				}
			}
			if len(props) > 0 {
				return props
			}
		}
	}
	return nil
}

// otaCerts pulls the update-signing certs out of a boot image's ramdisk.
func otaCerts(data []byte) []rsakey.Identity {
	img, err := bootimg.Parse(data)
	if err != nil {
		return nil
	}
	var out []rsakey.Identity
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
			if strings.ToLower(filepath.Base(e.Name)) != "otacerts.zip" {
				continue
			}
			out = append(out, certsFromZip(e.Data)...)
		}
	}
	return out
}

func certsFromZip(data []byte) []rsakey.Identity {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var out []rsakey.Identity
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(rc)
		rc.Close()
		blk, _ := pem.Decode(raw)
		if blk == nil {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		pub, ok := c.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			continue
		}
		label := c.Subject.CommonName
		if label == "" {
			label = c.Subject.String()
		}
		out = append(out, rsakey.Identity{
			Fingerprint: fmt.Sprintf("%x", sha256.Sum256(der)),
			Bits:        pub.N.BitLen(),
			Kind:        "cert",
			Label:       label,
			Public:      pub,
		})
	}
	return out
}

// sameIdentities compares two cert sets by SPKI fingerprint, so the same trust
// found at different offsets, or in a different order, is the same fact.
func sameIdentities(a, b []rsakey.Identity) bool {
	if len(a) != len(b) {
		return false
	}
	return strings.Join(fingerprints(a), ",") == strings.Join(fingerprints(b), ",")
}

func fingerprints(ids []rsakey.Identity) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.Fingerprint)
	}
	sort.Strings(out)
	return out
}

func showIdentities(ids []rsakey.Identity) string {
	labels := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		l := commonName(id.Label)
		if seen[l] {
			continue
		}
		seen[l] = true
		labels = append(labels, l)
	}
	return fmt.Sprintf("%d key(s): %s", len(ids), strings.Join(labels, ", "))
}

// commonName pulls the CN out of a cert's subject. A boot cert's DN carries the
// whole secboot identity in its OUs, which is a fact of its own and not what a
// one-line rendering of the chain is for.
func commonName(subject string) string {
	i := strings.Index(subject, "CN=")
	if i < 0 {
		return subject
	}
	rest := subject[i+3:]
	if j := strings.Index(rest, ",OU="); j >= 0 {
		return rest[:j]
	}
	if j := strings.Index(rest, ","); j >= 0 {
		return rest[:j]
	}
	return rest
}
