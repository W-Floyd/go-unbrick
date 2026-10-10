package vendor

import (
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/imgfacts"
)

// FactProviders implements FactDeriver: what a Samsung boot image's ramdisk
// says beyond the codename and fingerprint any vendor's does — the model
// number, the PDA build, the board.
func (samsung) FactProviders() []facts.Provider {
	isSamsung := func(brand string) bool { return brand == "samsung" }
	return []facts.Provider{
		imgfacts.RamdiskProp(facts.SKU, isSamsung, "ro.product.bootimage.model", "ro.product.vendor.model", "ro.product.model"),
		imgfacts.RamdiskProp(facts.SoftwareVersion, isSamsung, "ro.build.PDA", "ro.bootimage.build.version.incremental"),
		imgfacts.RamdiskProp(facts.BoardPlatform, isSamsung, "ro.board.platform", "ro.product.board"),
	}
}
