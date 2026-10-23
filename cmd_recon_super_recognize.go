package main

import "github.com/W-Floyd/go-unbrick/internal/lp"

// superMetadataRecognizer adapts lp.IsSuper to pkg/analysis/recognize.Recognizer.
// Report is nil: there is no fuller report for this fallback chain to produce.
// super's own partition map (printSuperMap) is a separate dispatch path, run
// only when a package's super arrives as a super.img_sparsechunk.* series
// (cmd_recon.go, around printSuperMap's call site), not keyed off typeLabel's
// lp.IsSuper(head) check -- see this migration's final report for what was
// checked.
type superMetadataRecognizer struct{}

func (superMetadataRecognizer) Name() string { return "lp-super" }

func (superMetadataRecognizer) Version() int { return 1 }

func (superMetadataRecognizer) Claims(name string, head []byte) bool { return lp.IsSuper(head) }

func (superMetadataRecognizer) Label(name string, head []byte) string { return "super metadata" }

// Summary is "": typeLabel's fallback chain has no summarize case for super
// metadata beyond the Label above.
func (superMetadataRecognizer) Summary(name string, head, data []byte) string { return "" }

func (superMetadataRecognizer) Report(path, name string, head, data []byte) []string { return nil }
