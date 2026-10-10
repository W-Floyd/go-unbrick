package imgfacts

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// PartProps is one build-prop file read out of a partition image.
type PartProps struct {
	Partition string // "vendor", "odm"
	File      string // its path in the partition
	// SKU is the hardware SKU a per-SKU prop file is for. AOSP names those
	// build_<sku>.prop; an OEM's own naming is recognized by its driver.
	SKU   string
	Props map[string]string
}

var (
	SourcePartProps = facts.Key[PartProps]("source:partition.prop",
		facts.Fmt(func(p PartProps) string { return p.Partition + "/" + p.File }))
	SourceFstab          = facts.Key[[]byte]("source:fstab", facts.Fmt(facts.ByteLen))
	SourceMacPermissions = facts.Key[[]byte]("source:mac_permissions", facts.Fmt(facts.ByteLen))
)

// partitionFiles are what is read out of each partition image a package
// carries: the files that say what the device is and how it is secured.
var partitionFiles = map[string][]string{
	"vendor": {"build.prop", "etc/fstab.*"},
	"odm":    {"etc/build.prop", "etc/*build*.prop"},
	"system": {"system/etc/selinux/plat_mac_permissions.xml", "etc/selinux/plat_mac_permissions.xml"},
}

// ReadPartitionFiles adds files (fs.Glob patterns) to what is read out of a
// partition image, for an OEM's own partitions. Call it from init.
func ReadPartitionFiles(part string, patterns ...string) {
	partitionFiles[part] = append(partitionFiles[part], patterns...)
}

// maxPartitionFile caps one such file; they are a few KiB.
const maxPartitionFile = 4 << 20

// Containers worth descending through to reach partition images. Not a
// sparse image: unsparsing a whole super to read a prop file is the cost
// this route avoids.
var partitionHolders = map[string]bool{"archive": true, "zip": true, "payload": true, "super": true}

// ingestPartitionFiles offers the recognizers the partitionFiles of every
// partition image in the package (an OTA payload's partitions, super's
// logical ones), each named "<partition>/<path>".
func ingestPartitionFiles(b *facts.Bag, rs []facts.Recognizer, p, base string) {
	root, err := carve.Open(p)
	if err != nil {
		return
	}
	var visit func(n *carve.Node, depth int)
	visit = func(n *carve.Node, depth int) {
		_, kids, err := n.Children()
		if err != nil {
			return
		}
		for _, k := range kids {
			if want, ok := partitionFiles[partitionName(k.Name)]; ok {
				if fsys, err := k.FS(); err == nil {
					readPartitionFiles(b, rs, fsys, partitionName(k.Name), want, base)
				}
				continue
			}
			if e, ok := carve.Format(k); ok && depth > 0 && partitionHolders[e.Kind] {
				visit(k, depth-1)
			}
		}
	}
	visit(root, 2)
}

// partitionName is the partition a node holds: "vendor" for vendor,
// vendor_a or vendor.img.
func partitionName(name string) string {
	n := strings.TrimSuffix(path.Base(name), ".img")
	return strings.TrimSuffix(strings.TrimSuffix(n, "_a"), "_b")
}

func readPartitionFiles(b *facts.Bag, rs []facts.Recognizer, fsys fs.FS, part string, want []string, base string) {
	seen := map[string]bool{}
	for _, pat := range want {
		matches, _ := fs.Glob(fsys, pat)
		for _, m := range matches {
			if seen[m] {
				continue
			}
			seen[m] = true
			if info, err := fs.Stat(fsys, m); err != nil || info.IsDir() || info.Size() > maxPartitionFile {
				continue
			}
			data, err := fs.ReadFile(fsys, m)
			if err != nil {
				continue
			}
			name := part + "/" + m
			facts.Recognize(b, rs, facts.File{Name: name, Data: data, From: base + " " + name})
		}
	}
}

// recognizePartitionFile claims the partition files by where they were read
// from: their content is plain text or XML that many things share.
func recognizePartitionFile(b *facts.Bag, f facts.File) []string {
	part, file, ok := strings.Cut(f.Name, "/")
	if !ok || partitionFiles[part] == nil {
		return nil
	}
	prov := facts.Provenance{Source: f.From, Authority: facts.Attested}
	switch base := path.Base(file); {
	case strings.HasSuffix(base, ".prop"):
		props := ParseProps(f.Data)
		if len(props) == 0 {
			return nil
		}
		pp := PartProps{Partition: part, File: file, Props: props}
		if m := aospSKUProp.FindStringSubmatch(base); m != nil {
			pp.SKU = m[1]
		}
		facts.Set(b, SourcePartProps, pp, prov)
		return []string{SourcePartProps.Name()}
	case strings.HasPrefix(base, "fstab."):
		facts.Set(b, SourceFstab, f.Data, prov)
		return []string{SourceFstab.Name()}
	case strings.HasSuffix(base, "mac_permissions.xml"):
		facts.Set(b, SourceMacPermissions, f.Data, prov)
		return []string{SourceMacPermissions.Name()}
	}
	return nil
}

var aospSKUProp = regexp.MustCompile(`^build_(.+)\.prop$`)

// ParseProps parses key=value build properties, skipping comments.
func ParseProps(data []byte) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && props[k] == "" {
			props[k] = v
		}
	}
	return props
}

// partProps returns the prop files of one partition, the non-SKU ones first.
func partProps(b *facts.Bag, part string) []PartProps {
	var out []PartProps
	for _, p := range facts.GetAll(b, SourcePartProps) {
		if p.Partition == part {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].SKU == "" && out[j].SKU != "" })
	return out
}

// vendorProp is a rule reading one property of the vendor image's own
// build.prop (not a per-SKU one).
func vendorProp[T any](out facts.Fact[T], key string, conv func(string) (T, bool)) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{SourcePartProps.Name()}, Price: 1, Level: facts.Attested,
		Fn: func(b *facts.Bag) (bool, error) {
			for _, p := range partProps(b, "vendor") {
				if v, ok := p.Props[key]; ok && p.SKU == "" {
					if t, ok := conv(v); ok {
						facts.Set(b, out, t, facts.Provenance{Source: "vendor/" + p.File + " " + key, Authority: facts.Attested})
						return true, nil
					}
				}
			}
			return false, nil
		},
	}
}

func str(v string) (string, bool) { return v, v != "" }

func partitionProviders() []facts.Provider {
	return []facts.Provider{
		vendorProp(facts.BoardPlatform, "ro.board.platform", str),
		vendorProp(facts.FirstAPILevel, "ro.product.first_api_level", func(v string) (int, bool) {
			n, err := strconv.Atoi(v)
			return n, err == nil
		}),
		vendorProp(facts.VendorRelease, "ro.vendor.build.version.release", str),
		vendorProp(facts.VendorSecurityPatch, "ro.vendor.build.security_patch", str),

		// Per-SKU odm props: each SKU's model number, and the market name when
		// every SKU agrees on one.
		facts.Rule{
			Out: facts.SKUModels.Name(), In: []string{SourcePartProps.Name()}, Price: 1, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				models := map[string]string{}
				names := map[string]bool{}
				for _, p := range partProps(b, "odm") {
					if p.SKU == "" {
						continue
					}
					if m := firstProp(p.Props, "ro.product.odm.model", "ro.product.model"); m != "" {
						models[p.SKU] = m
					}
					if n := firstProp(p.Props, "ro.product.odm.marketname", "ro.product.marketname"); n != "" {
						names[n] = true
					}
				}
				if len(models) == 0 {
					return false, nil
				}
				facts.Set(b, facts.SKUModels, models, facts.Provenance{Source: "odm per-SKU build props", Authority: facts.Attested})
				if len(names) == 1 {
					for n := range names {
						facts.Set(b, facts.Model, n, facts.Provenance{Source: "odm per-SKU marketname", Authority: facts.Attested})
					}
				}
				return true, nil
			},
		},

		facts.Rule{
			Out: facts.DataEncryption.Name(), In: []string{SourceFstab.Name()}, Price: 1, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				for _, data := range facts.GetAll(b, SourceFstab) {
					enc, meta, ok := fstabEncryption(data)
					if !ok {
						continue
					}
					prov := facts.Provenance{Source: "vendor fstab userdata", Authority: facts.Attested}
					facts.Set(b, facts.DataEncryption, enc, prov)
					facts.Set(b, facts.MetadataEncryption, meta, prov)
					return true, nil
				}
				return false, nil
			},
		},
		facts.Rule{
			Out: facts.GSIKeys.Name(), In: []string{SourceFstab.Name()}, Price: 1, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				for _, data := range facts.GetAll(b, SourceFstab) {
					if keys := fstabGSIKeys(data); len(keys) > 0 {
						facts.Set(b, facts.GSIKeys, keys, facts.Provenance{Source: "vendor fstab system avb_keys", Authority: facts.Attested})
						return true, nil
					}
				}
				return false, nil
			},
		},

		facts.Rule{
			Out: facts.PlatformCert.Name(), In: []string{SourceMacPermissions.Name()}, Price: 1, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				set := false
				for _, data := range facts.GetAll(b, SourceMacPermissions) {
					signers, err := macSigners(data)
					if err != nil {
						continue
					}
					prov := facts.Provenance{Source: "plat_mac_permissions.xml", Authority: facts.Attested}
					var test []string
					for _, s := range signers {
						if aospTestKeys[s.sha256] {
							test = append(test, s.seinfo)
						}
						if s.seinfo == "platform" {
							facts.Set(b, facts.PlatformCert, s.sha256, prov)
							if s.cn != "" {
								facts.Set(b, facts.PlatformSigner, s.cn, prov)
							}
							set = true
						}
					}
					sort.Strings(test)
					facts.Set(b, facts.AOSPTestKeys, slices.Compact(test), prov)
				}
				return set, nil
			},
		},
	}
}

func firstProp(props map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := props[k]; v != "" {
			return v
		}
	}
	return ""
}

// fstabMount returns the fs_mgr flags of the fstab entry mounted at mount.
func fstabMount(data []byte, mount string) (flags []string, ok bool) {
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && !strings.HasPrefix(f[0], "#") && f[1] == mount {
			return strings.Split(f[4], ","), true
		}
	}
	return nil, false
}

// fstabEncryption reads userdata's encryption: file-based (fileencryption=,
// and whether metadata is encrypted too), or full-disk.
func fstabEncryption(data []byte) (enc string, metadata, ok bool) {
	flags, ok := fstabMount(data, "/data")
	if !ok {
		return "", false, false
	}
	for _, fl := range flags {
		k, v, _ := strings.Cut(fl, "=")
		switch k {
		case "fileencryption":
			enc = v
		case "forceencrypt", "encryptable", "forcefdeorfbe":
			if enc == "" {
				enc = "full-disk"
			}
		case "keydirectory", "metadata_encryption":
			metadata = true
		}
	}
	if enc == "" {
		enc = "none"
	}
	return enc, metadata, true
}

// fstabGSIKeys names the GSI keys (q-gsi, …) system's avb_keys lists.
func fstabGSIKeys(data []byte) []string {
	flags, ok := fstabMount(data, "/system")
	if !ok {
		return nil
	}
	var out []string
	for _, fl := range flags {
		v, ok := strings.CutPrefix(fl, "avb_keys=")
		if !ok {
			continue
		}
		for _, k := range strings.Split(v, ":") {
			if b := strings.TrimSuffix(path.Base(k), ".avbpubkey"); strings.Contains(b, "gsi") {
				out = append(out, b)
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

type macSigner struct{ seinfo, sha256, cn string }

// macSigners reads the signer → seinfo map of a mac_permissions.xml.
func macSigners(data []byte) ([]macSigner, error) {
	var doc struct {
		Signers []struct {
			Signature string `xml:"signature,attr"`
			Seinfo    []struct {
				Value string `xml:"value,attr"`
			} `xml:"seinfo"`
		} `xml:"signer"`
	}
	// The build declares it iso-8859-1, which encoding/xml will not read
	// unaided; the content (hex and role names) is ASCII either way.
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := d.Decode(&doc); err != nil {
		return nil, err
	}
	var out []macSigner
	for _, s := range doc.Signers {
		der, err := hex.DecodeString(s.Signature)
		if err != nil || len(s.Seinfo) == 0 {
			continue
		}
		sum := sha256.Sum256(der)
		m := macSigner{seinfo: s.Seinfo[0].Value, sha256: hex.EncodeToString(sum[:])}
		if c, err := x509.ParseCertificate(der); err == nil {
			m.cn = c.Subject.CommonName
		}
		out = append(out, m)
	}
	return out, nil
}

// aospTestKeys are the SHA-256s of AOSP's public test certs
// (build/make/target/product/security/*.x509.pem): platform, shared, media,
// networkstack, sdk_sandbox, bluetooth.
var aospTestKeys = map[string]bool{
	"c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8": true,
	"28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd": true,
	"465983f7791f2abeb43ea2cbdc7f21a8260b72bc08a55c839fc1a43bc741a81e": true,
	"e1dbadce60dc080d15b58a014b0dcf9400e24de23fa00b287a5a982bfebda2ee": true,
	"abf21f9e2af1d881cc673fddcefa6ed9c269a437bd64b279cf45844cfd589126": true,
	"a6ccc500ff0e7421200eb66a7fe174ef1b00e52ca91727070cbedf061ff76c35": true,
}

// Checks are the neutral cross-fact judgments.
func Checks() []facts.Check {
	return []facts.Check{
		facts.CheckFunc{
			On: []string{facts.SecurityPatch.Name(), facts.VendorSecurityPatch.Name()},
			Fn: func(b *facts.Bag) []facts.Finding {
				sys, _ := facts.Get(b, facts.SecurityPatch)
				ven, _ := facts.Get(b, facts.VendorSecurityPatch)
				st, err1 := time.Parse("2006-01-02", sys)
				vt, err2 := time.Parse("2006-01-02", ven)
				if err1 != nil || err2 != nil || !vt.Before(st.AddDate(0, -1, 0)) {
					return nil
				}
				months := (st.Year()-vt.Year())*12 + int(st.Month()-vt.Month())
				return []facts.Finding{{Severity: facts.Warn,
					Facts:   []string{facts.SecurityPatch.Name(), facts.VendorSecurityPatch.Name()},
					Message: fmt.Sprintf("the vendor image's security patch (%s) is %d months behind system's (%s): vendor-side fixes since are missing", ven, months, sys)}}
			},
		},
		facts.CheckFunc{
			On: []string{facts.AOSPTestKeys.Name()},
			Fn: func(b *facts.Bag) []facts.Finding {
				roles, _ := facts.Get(b, facts.AOSPTestKeys)
				if len(roles) == 0 {
					return nil
				}
				return []facts.Finding{{Severity: facts.Error, Facts: []string{facts.AOSPTestKeys.Name()},
					Message: fmt.Sprintf("signed with AOSP's public test keys for %s: anyone can sign apps with those privileges", strings.Join(roles, ", "))}}
			},
		},
	}
}
