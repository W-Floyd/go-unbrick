package vendor

// Adapters onto pkg/analysis/recognize.Recognizer for the dispatch chain
// RecognizeArtifact/ArtifactReport used to hardcode: one Recognizer per
// branch, in the same order, so a registry can try them individually instead
// of through that chain. The chain itself (RecognizeArtifact, ArtifactReport,
// every xxxArtifact function) is untouched -- this file only wraps it.

import (
	"fmt"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/recognize"
)

// ActiveCatalog, if set, is the device catalog to consult for recognition
// that benefits from one (currently: Motorola CID carrier-name lookups).
// The host sets this once at startup; nil is fine (those lookups are
// already nil-safe).
var ActiveCatalog func() *catalog.Catalog

func activeCatalog() *catalog.Catalog {
	if ActiveCatalog != nil {
		return ActiveCatalog()
	}
	return nil
}

func summaryOf(detail string) string {
	if detail == "" {
		return ""
	}
	return " — " + detail
}

// MotorolaRecognizer wraps motorolaArtifact: LMSA ROM, CID image, MotoLogo
// container, subsidy-lock SLCF.
type MotorolaRecognizer struct{}

var _ recognize.Recognizer = MotorolaRecognizer{}

func (MotorolaRecognizer) Name() string { return "motorola-artifact" }

func (MotorolaRecognizer) Version() int { return 1 }

func (MotorolaRecognizer) Claims(name string, head []byte) bool {
	_, ok := motorolaArtifact(activeCatalog(), name, head)
	return ok
}

func (MotorolaRecognizer) Label(name string, head []byte) string {
	info, _ := motorolaArtifact(activeCatalog(), name, head)
	return info.Label
}

func (MotorolaRecognizer) Summary(name string, head, data []byte) string {
	info, _ := motorolaArtifact(activeCatalog(), name, head)
	return summaryOf(info.Detail)
}

func (MotorolaRecognizer) Report(path, name string, head, data []byte) []string { return nil }

// HKMCRecognizer wraps hkmcArtifact (navi/head-unit formats) plus hkmc's
// ArtifactReport (the PRNM/.npkg section table).
type HKMCRecognizer struct{}

var _ recognize.Recognizer = HKMCRecognizer{}

func (HKMCRecognizer) Name() string { return "hkmc-artifact" }

func (HKMCRecognizer) Version() int { return 1 }

func (HKMCRecognizer) Claims(name string, head []byte) bool {
	_, ok := hkmcArtifact(name, head)
	return ok
}

func (HKMCRecognizer) Label(name string, head []byte) string {
	info, _ := hkmcArtifact(name, head)
	return info.Label
}

func (HKMCRecognizer) Summary(name string, head, data []byte) string {
	info, _ := hkmcArtifact(name, head)
	return summaryOf(info.Detail)
}

func (HKMCRecognizer) Report(path, name string, head, data []byte) []string {
	return hkmc{}.ArtifactReport(path, head)
}

// TelechipsArtifactRecognizer wraps tccArtifact (boot-stage wrapper and LK
// ROM) plus tcc's ArtifactReport. Distinct from "lkrom" in cache.Versions,
// which covers internal/telechips's LKROM parsing itself, not this
// recognition/report layer.
type TelechipsArtifactRecognizer struct{}

var _ recognize.Recognizer = TelechipsArtifactRecognizer{}

func (TelechipsArtifactRecognizer) Name() string { return "telechips-artifact" }

func (TelechipsArtifactRecognizer) Version() int { return 1 }

func (TelechipsArtifactRecognizer) Claims(name string, head []byte) bool {
	_, ok := tccArtifact(head)
	return ok
}

func (TelechipsArtifactRecognizer) Label(name string, head []byte) string {
	info, _ := tccArtifact(head)
	return info.Label
}

func (TelechipsArtifactRecognizer) Summary(name string, head, data []byte) string {
	info, _ := tccArtifact(head)
	return summaryOf(info.Detail)
}

func (TelechipsArtifactRecognizer) Report(path, name string, head, data []byte) []string {
	return tcc{}.ArtifactReport(path, head)
}

// FSGRecognizer wraps fsgArtifact (modem EFS golden-copy table).
type FSGRecognizer struct{}

var _ recognize.Recognizer = FSGRecognizer{}

func (FSGRecognizer) Name() string { return "fsg-artifact" }

func (FSGRecognizer) Version() int { return 1 }

func (FSGRecognizer) Claims(name string, head []byte) bool {
	_, ok := fsgArtifact(head)
	return ok
}

func (FSGRecognizer) Label(name string, head []byte) string {
	info, _ := fsgArtifact(head)
	return info.Label
}

func (FSGRecognizer) Summary(name string, head, data []byte) string {
	info, _ := fsgArtifact(head)
	return summaryOf(info.Detail)
}

func (FSGRecognizer) Report(path, name string, head, data []byte) []string { return nil }

// QcomRecognizer wraps qcomArtifact (Qualcomm MBN / partition table magics).
type QcomRecognizer struct{}

var _ recognize.Recognizer = QcomRecognizer{}

func (QcomRecognizer) Name() string { return "qcom-artifact" }

func (QcomRecognizer) Version() int { return 1 }

func (QcomRecognizer) Claims(name string, head []byte) bool {
	_, ok := qcomArtifact(head)
	return ok
}

func (QcomRecognizer) Label(name string, head []byte) string {
	info, _ := qcomArtifact(head)
	return info.Label
}

func (QcomRecognizer) Summary(name string, head, data []byte) string {
	info, _ := qcomArtifact(head)
	return summaryOf(info.Detail)
}

func (QcomRecognizer) Report(path, name string, head, data []byte) []string { return nil }

// MediatekRecognizer wraps mediatekArtifact (image/Download Agent/GFH/modem
// debug database magics).
type MediatekRecognizer struct{}

var _ recognize.Recognizer = MediatekRecognizer{}

func (MediatekRecognizer) Name() string { return "mediatek-artifact" }

func (MediatekRecognizer) Version() int { return 1 }

func (MediatekRecognizer) Claims(name string, head []byte) bool {
	_, ok := mediatekArtifact(head)
	return ok
}

func (MediatekRecognizer) Label(name string, head []byte) string {
	info, _ := mediatekArtifact(head)
	return info.Label
}

func (MediatekRecognizer) Summary(name string, head, data []byte) string {
	info, _ := mediatekArtifact(head)
	return summaryOf(info.Detail)
}

func (MediatekRecognizer) Report(path, name string, head, data []byte) []string { return nil }

// SamsungPITRecognizer wraps ParsePIT (Odin's partition table).
type SamsungPITRecognizer struct{}

var _ recognize.Recognizer = SamsungPITRecognizer{}

func (SamsungPITRecognizer) Name() string { return "samsung-pit" }

func (SamsungPITRecognizer) Version() int { return 1 }

func (SamsungPITRecognizer) Claims(name string, head []byte) bool {
	_, err := ParsePIT(head)
	return err == nil
}

func (SamsungPITRecognizer) Label(name string, head []byte) string { return "Samsung PIT" }

func (SamsungPITRecognizer) Summary(name string, head, data []byte) string {
	p, err := ParsePIT(head)
	if err != nil {
		return ""
	}
	return summaryOf(fmt.Sprintf("%d partitions", len(p.Entries)))
}

func (SamsungPITRecognizer) Report(path, name string, head, data []byte) []string { return nil }
