package vendor

import (
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
)

// FactProviders implements FactDeriver. A Samsung boot image's ramdisk names
// the device and build (system/etc/ramdisk/build.prop in boot, prop.default
// in recovery); only a samsung-branded one is read, as another OEM's ramdisk
// copy can be a stale placeholder.
func (samsung) FactProviders() []facts.Provider {
	prop := func(out facts.Fact[string], keys ...string) facts.Rule {
		return facts.Rule{
			Out: out.Name(), In: []string{imgfacts.SourceBootImage.Name()}, Price: 5, Level: facts.Attested,
			Fn: func(b *facts.Bag) (bool, error) {
				for _, data := range facts.GetAll(b, imgfacts.SourceBootImage) {
					p := imgfacts.BuildProps(data)
					if firstProp(p, "ro.product.bootimage.brand", "ro.product.vendor.brand", "ro.product.brand") != "samsung" {
						continue
					}
					for _, k := range keys {
						if v := p[k]; v != "" {
							facts.Set(b, out, v, facts.Provenance{Source: "boot ramdisk " + k, Authority: facts.Attested})
							return true, nil
						}
					}
				}
				return false, nil
			},
		}
	}
	return []facts.Provider{
		prop(facts.Codename, "ro.product.bootimage.device", "ro.product.vendor.device", "ro.product.device"),
		prop(facts.SKU, "ro.product.bootimage.model", "ro.product.vendor.model", "ro.product.model"),
		prop(facts.BuildFingerprint, "ro.bootimage.build.fingerprint", "ro.vendor.build.fingerprint"),
		prop(facts.SoftwareVersion, "ro.build.PDA", "ro.bootimage.build.version.incremental"),
		prop(facts.BoardPlatform, "ro.board.platform", "ro.product.board"),
	}
}

func firstProp(p map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := p[k]; v != "" {
			return v
		}
	}
	return ""
}
