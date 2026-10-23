package main

import (
	"github.com/W-Floyd/go-unbrick/internal/androidkeys"
	"github.com/W-Floyd/go-unbrick/internal/npkg"
	"github.com/W-Floyd/go-unbrick/internal/pemfile"
	"github.com/W-Floyd/go-unbrick/internal/unixauth"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
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
