package main

import (
	"github.com/W-Floyd/go-unbrick/internal/androidkeys"
	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/bootelf"
	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/dtbo"
	"github.com/W-Floyd/go-unbrick/internal/fdt"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/npkg"
	"github.com/W-Floyd/go-unbrick/internal/pemfile"
	"github.com/W-Floyd/go-unbrick/internal/qcdt"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
	"github.com/W-Floyd/go-unbrick/internal/telechips"
	"github.com/W-Floyd/go-unbrick/internal/ubi"
	"github.com/W-Floyd/go-unbrick/internal/ubifs"
	"github.com/W-Floyd/go-unbrick/internal/unixauth"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/cache"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/recognize"
)

// init registers every content recognizer into recognize.Default, in the
// order typeLabel's old hand-copied chain tried them (the most complete of
// the three copies that used to exist). First Claims wins, so order matters:
// npkg is registered before HKMCRecognizer because hkmcArtifact also has its
// own internal npkg.Is case — without this ordering that case would make the
// dedicated npkg.Recognizer unreachable dead code. This file is the only
// place that order is written down now.
func init() {
	vendor.ActiveCatalog = activeCatalog

	// Plain parsers with no Claims/Label/Report of their own (not
	// recognize.Recognizer): their cache version still lives as a const next
	// to their own code, wired in here instead of a hand-maintained number in
	// cache.go.
	cache.VersionFuncs["filetype"] = func() int { return filetype.Version }
	cache.VersionFuncs["dtbo"] = func() int { return dtbo.Version }
	cache.VersionFuncs["fdt"] = func() int { return fdt.Version }
	cache.VersionFuncs["ubi"] = func() int { return ubi.Version }
	cache.VersionFuncs["ubifs"] = func() int { return ubifs.Version }
	cache.VersionFuncs["qcdt"] = func() int { return qcdt.Version }
	cache.VersionFuncs["bootimg"] = func() int { return bootimg.Version }
	cache.VersionFuncs["blankflash"] = func() int { return blankflash.SingleImageVersion }
	cache.VersionFuncs["bootelf"] = func() int { return bootelf.Version }
	cache.VersionFuncs["secboot"] = func() int { return secboot.Version }
	cache.VersionFuncs["lkrom"] = func() int { return telechips.LKROMVersion }
	cache.VersionFuncs["carve-containers"] = func() int { return carve.FormatsVersion }
	// facts: reconGraph() is the exact provider/check assembly recon's Bag
	// construction uses (cmd_recon.go), so this can't drift from what's
	// actually run the way a hand-maintained number could.
	cache.VersionFuncs["facts"] = func() int { return reconGraph().Version() }

	for _, r := range []recognize.Recognizer{
		kernelLabelRecognizer{},
		superMetadataRecognizer{},
		androidkeys.Recognizer{},
		unixauth.Recognizer{},
		pemfile.Recognizer{},
		hexValueRecognizer{},
		vendor.MotorolaRecognizer{},
		npkg.Recognizer{}, // claims .npkg bytes before HKMCRecognizer's own bundled npkg.Is check gets the chance to
		vendor.HKMCRecognizer{},
		vendor.TelechipsArtifactRecognizer{},
		vendor.FSGRecognizer{},
		vendor.QcomRecognizer{},
		vendor.MediatekRecognizer{},
		vendor.SamsungPITRecognizer{},
	} {
		recognize.Default.Register(r)
	}
}
